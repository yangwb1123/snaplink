package compliance_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"

	_ "modernc.org/sqlite"
)

// The pure-Go SQLite stores (no CGO) are real, production implementations of
// the same SPIs the memory stores satisfy — NOT mocks. Closing the backing
// *sql.DB after seeding makes every subsequent query return a genuine driver
// error, which is the no-mock way to drive the Eraser/Exporter best-effort
// partial-failure branches (a store outage mid-erasure) that the happy-path
// memory tests never reach.

// openTempDB opens a real temp-file SQLite DB and registers cleanup. Callers
// close it early to simulate a store outage.
func openTempDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "compliance.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// indexOnlyRefresh adapts the real MemoryRefreshTokenStore to the bare
// RefreshTokenSubjectIndex SPI WITHOUT the optional RefreshTokenSubjectCounter,
// modelling a backend that can bulk-delete but offers no non-destructive
// count. The one method delegates to the real store — no fabricated behaviour.
type indexOnlyRefresh struct {
	inner *defaultimpl.MemoryRefreshTokenStore
}

func (i indexOnlyRefresh) DeleteAllForSubject(ctx context.Context, userID, clientID string) (int, error) {
	return i.inner.DeleteAllForSubject(ctx, userID, clientID)
}

var _ oauth.RefreshTokenSubjectIndex = indexOnlyRefresh{}

// TestEraseSubject_DryRunNoCounterIsSkipped covers the dry-run branch where
// the wired index can't preview a count: the step is recorded in Skipped and
// nothing is deleted.
func TestEraseSubject_DryRunNoCounterIsSkipped(t *testing.T) {
	ctx := context.Background()
	mem := defaultimpl.NewMemoryRefreshTokenStore()
	clients := defaultimpl.NewMemoryClientStore()
	if err := clients.Add(ctx, &core.Client{ID: "c1"}); err != nil {
		t.Fatalf("add client: %v", err)
	}
	if err := mem.Issue(ctx, "u1-c1-rt", &oauth.RefreshToken{
		UserID: "u1", ClientID: "c1", ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	e := &compliance.Eraser{Refresh: indexOnlyRefresh{inner: mem}, Clients: clients}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if rep.RefreshTokensDeleted != 0 {
		t.Errorf("RefreshTokensDeleted = %d, want 0 (no counter to preview)", rep.RefreshTokensDeleted)
	}
	if !hasSkipPrefix(rep.Skipped, "refresh_tokens(dry-run") {
		t.Errorf("Skipped = %v, want a refresh_tokens dry-run note", rep.Skipped)
	}
	// Token still present — dry-run mutated nothing.
	if n, _ := mem.DeleteAllForSubject(ctx, "u1", "c1"); n != 1 {
		t.Errorf("dry-run deleted tokens: real delete found %d, want 1", n)
	}
}

// TestEraseSubject_ClientListErrorLive covers the live (non-dry-run) branch
// where enumerating clients for refresh revocation fails: the failure lands
// in Errors and the run continues to sessions + user.
func TestEraseSubject_ClientListErrorLive(t *testing.T) {
	ctx := context.Background()
	refresh := sqlite.NewRefreshTokenStoreWithDB(openTempDB(t)) // wired, never reached past List
	clientsDB := openTempDB(t)
	clients := sqlite.NewClientStoreWithDB(clientsDB)
	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &core.User{ID: "u1"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	_ = clientsDB.Close() // List now errors

	e := &compliance.Eraser{Refresh: refresh, Clients: clients, Users: users}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err == nil {
		t.Fatal("expected aggregated error from client list failure")
	}
	if !containsErr(rep.Errors, "list clients") {
		t.Errorf("Errors = %v, want a 'list clients' failure", rep.Errors)
	}
	// Best-effort: the user step still ran despite the refresh-step failure.
	if !rep.UserDeleted {
		t.Error("UserDeleted = false; user step should still run after refresh failure")
	}
}

// TestEraseSubject_ClientListErrorDryRun covers the same failure under
// DryRun, where the counter type-assertion succeeds (sqlite implements it)
// but the subsequent List errors.
func TestEraseSubject_ClientListErrorDryRun(t *testing.T) {
	ctx := context.Background()
	refresh := sqlite.NewRefreshTokenStoreWithDB(openTempDB(t)) // implements RefreshTokenSubjectCounter
	clientsDB := openTempDB(t)
	clients := sqlite.NewClientStoreWithDB(clientsDB)
	_ = clientsDB.Close()

	e := &compliance.Eraser{Refresh: refresh, Clients: clients}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{DryRun: true})
	if err == nil {
		t.Fatal("expected error from client list failure under dry-run")
	}
	if !containsErr(rep.Errors, "list clients") {
		t.Errorf("Errors = %v, want a 'list clients' failure", rep.Errors)
	}
}

// TestEraseSubject_RefreshDeleteErrorLive covers the per-client revocation
// failure path: clients enumerate fine (memory) but the refresh store is a
// closed sqlite handle, so DeleteAllForSubject errors for each client.
func TestEraseSubject_RefreshDeleteErrorLive(t *testing.T) {
	ctx := context.Background()
	clients := defaultimpl.NewMemoryClientStore()
	for _, id := range []string{"c1", "c2"} {
		if err := clients.Add(ctx, &core.Client{ID: id}); err != nil {
			t.Fatalf("add client %s: %v", id, err)
		}
	}
	refreshDB := openTempDB(t)
	refresh := sqlite.NewRefreshTokenStoreWithDB(refreshDB)
	_ = refreshDB.Close() // DeleteAllForSubject now errors

	e := &compliance.Eraser{Refresh: refresh, Clients: clients}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err == nil {
		t.Fatal("expected aggregated error from refresh delete failures")
	}
	// One failure per client, none counted as deleted.
	if len(rep.Errors) != 2 {
		t.Errorf("Errors len = %d, want 2 (one per client)", len(rep.Errors))
	}
	if rep.RefreshTokensDeleted != 0 {
		t.Errorf("RefreshTokensDeleted = %d, want 0", rep.RefreshTokensDeleted)
	}
	if !containsErr(rep.Errors, "revoke refresh tokens") {
		t.Errorf("Errors = %v, want 'revoke refresh tokens' failures", rep.Errors)
	}
}

// TestEraseSubject_RefreshCountErrorDryRun covers the dry-run per-client
// count failure path.
func TestEraseSubject_RefreshCountErrorDryRun(t *testing.T) {
	ctx := context.Background()
	clients := defaultimpl.NewMemoryClientStore()
	if err := clients.Add(ctx, &core.Client{ID: "c1"}); err != nil {
		t.Fatalf("add client: %v", err)
	}
	refreshDB := openTempDB(t)
	refresh := sqlite.NewRefreshTokenStoreWithDB(refreshDB)
	_ = refreshDB.Close() // CountForSubject now errors

	e := &compliance.Eraser{Refresh: refresh, Clients: clients}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{DryRun: true})
	if err == nil {
		t.Fatal("expected error from count failure under dry-run")
	}
	if !containsErr(rep.Errors, "count refresh tokens") {
		t.Errorf("Errors = %v, want a 'count refresh tokens' failure", rep.Errors)
	}
}

// TestEraseSubject_SessionListError covers the sessions-step failure where
// listing the subject's sessions errors.
func TestEraseSubject_SessionListError(t *testing.T) {
	ctx := context.Background()
	sessDB := openTempDB(t)
	sessions, err := sqlite.NewSessionManagerWithDB(sessDB, time.Hour)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	_ = sessDB.Close() // ListByUser now errors

	e := &compliance.Eraser{Sessions: sessions}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err == nil {
		t.Fatal("expected aggregated error from session list failure")
	}
	if !containsErr(rep.Errors, "list sessions") {
		t.Errorf("Errors = %v, want a 'list sessions' failure", rep.Errors)
	}
	if rep.SessionsDestroyed != 0 {
		t.Errorf("SessionsDestroyed = %d, want 0", rep.SessionsDestroyed)
	}
}

// TestEraseSubject_SessionDestroyError covers the per-session destroy
// failure: ListByUser returns real seeded sessions (from a live memory
// manager) while Destroy returns a real error sourced from a closed sqlite
// manager. destroyFailingSessions delegates both methods to real stores —
// it fabricates no behaviour of its own.
func TestEraseSubject_SessionDestroyError(t *testing.T) {
	ctx := context.Background()
	live := defaultimpl.NewMemorySessionManager()
	if _, err := live.Create(ctx, "u1"); err != nil {
		t.Fatalf("create session: %v", err)
	}
	sessDB := openTempDB(t)
	dead, err := sqlite.NewSessionManagerWithDB(sessDB, time.Hour)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	_ = sessDB.Close() // dead.Destroy now errors

	e := &compliance.Eraser{Sessions: destroyFailingSessions{list: live, destroy: dead}}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err == nil {
		t.Fatal("expected aggregated error from session destroy failure")
	}
	if !containsErr(rep.Errors, "destroy session") {
		t.Errorf("Errors = %v, want a 'destroy session' failure", rep.Errors)
	}
	if rep.SessionsDestroyed != 0 {
		t.Errorf("SessionsDestroyed = %d, want 0 (destroy failed)", rep.SessionsDestroyed)
	}
}

// TestEraseSubject_UserDeleteError covers the user-delete failure path.
func TestEraseSubject_UserDeleteError(t *testing.T) {
	ctx := context.Background()
	usersDB := openTempDB(t)
	users := sqlite.NewUserProviderWithDB(usersDB)
	_ = usersDB.Close() // Delete now errors

	e := &compliance.Eraser{Users: users}
	rep, err := e.EraseSubject(ctx, "u1", compliance.EraseOptions{})
	if err == nil {
		t.Fatal("expected aggregated error from user delete failure")
	}
	if !containsErr(rep.Errors, "delete user") {
		t.Errorf("Errors = %v, want a 'delete user' failure", rep.Errors)
	}
	if rep.UserDeleted {
		t.Error("UserDeleted = true despite delete failure")
	}
}

// TestExportSubject_UserAndSessionReadErrors covers the export read-side
// failure branches: both built-in reads error, the errors aggregate, and a
// non-nil (empty) bundle is still returned.
func TestExportSubject_UserAndSessionReadErrors(t *testing.T) {
	ctx := context.Background()
	usersDB := openTempDB(t)
	users := sqlite.NewUserProviderWithDB(usersDB)
	sessDB := openTempDB(t)
	sessions, err := sqlite.NewSessionManagerWithDB(sessDB, time.Hour)
	if err != nil {
		t.Fatalf("session manager: %v", err)
	}
	_ = usersDB.Close()
	_ = sessDB.Close()

	exp := &compliance.Exporter{Users: users, Sessions: sessions}
	bundle, err := exp.ExportSubject(ctx, "u1")
	if err == nil {
		t.Fatal("expected aggregated error from user + session read failures")
	}
	msg := err.Error()
	if !strings.Contains(msg, "user:") || !strings.Contains(msg, "sessions:") {
		t.Errorf("error = %q, want both user and sessions failures", msg)
	}
	if bundle == nil {
		t.Fatal("bundle is nil; ExportSubject must always return a non-nil bundle")
	}
	if _, ok := bundle.Data["user"]; ok {
		t.Error("failed user read should not appear in bundle data")
	}
}

// destroyFailingSessions composes two real SessionManagers: ListByUser comes
// from a live store (returns seeded sessions) and Destroy comes from a closed
// one (returns a real driver error). Every other SessionManager method is
// served by the live store so the type fully satisfies core.SessionManager.
type destroyFailingSessions struct {
	list    *defaultimpl.MemorySessionManager
	destroy *sqlite.SessionManager
}

func (d destroyFailingSessions) Create(ctx context.Context, userID string) (*core.Session, error) {
	return d.list.Create(ctx, userID)
}

func (d destroyFailingSessions) Get(ctx context.Context, sessionID string) (*core.Session, error) {
	return d.list.Get(ctx, sessionID)
}

func (d destroyFailingSessions) Refresh(ctx context.Context, sessionID string) (*core.Session, error) {
	return d.list.Refresh(ctx, sessionID)
}

func (d destroyFailingSessions) Destroy(ctx context.Context, sessionID string) error {
	return d.destroy.Destroy(ctx, sessionID)
}

func (d destroyFailingSessions) ListByUser(ctx context.Context, userID string) ([]*core.Session, error) {
	return d.list.ListByUser(ctx, userID)
}

func (d destroyFailingSessions) ListAll(ctx context.Context) ([]*core.Session, error) {
	return d.list.ListAll(ctx)
}

var _ core.SessionManager = destroyFailingSessions{}

func hasSkipPrefix(skipped []string, prefix string) bool {
	for _, s := range skipped {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

func containsErr(errs []error, sub string) bool {
	for _, e := range errs {
		if e != nil && strings.Contains(e.Error(), sub) {
			return true
		}
	}
	return false
}
