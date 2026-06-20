package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/migrate"
)

func newSessionManagerForTest(t *testing.T) *SessionManager {
	t.Helper()
	return newSessionManagerForTestWithTTL(t, time.Hour)
}

func newSessionManagerForTestWithTTL(t *testing.T, ttl time.Duration) *SessionManager {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "sessions.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	mgr, err := NewSessionManager(dsn, ttl)
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	return mgr
}

// markSessionRevoked flips revoked=1 directly via SQL — bypasses
// SessionManager which doesn't expose a revoke method (admin RPCs
// use a separate path). Used by the Refresh-refuses-revoked test
// to set up state without going through the destroy-and-recreate
// dance.
func markSessionRevoked(t *testing.T, mgr *SessionManager, sessionID string) error {
	t.Helper()
	_, err := mgr.db.ExecContext(context.Background(), `UPDATE sessions SET revoked = 1 WHERE id = ?`, sessionID)
	return err
}

func TestSessionManager_CreateAndGet(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	created, err := mgr.Create(ctx, "alice")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == "" || created.UserID != "alice" {
		t.Fatalf("bad created session: %#v", created)
	}
	if created.CreatedAt.IsZero() || created.ExpiresAt.IsZero() {
		t.Fatal("timestamps not populated on create")
	}
	if !created.ExpiresAt.After(created.CreatedAt) {
		t.Fatalf("ExpiresAt %v must be after CreatedAt %v", created.ExpiresAt, created.CreatedAt)
	}

	got, err := mgr.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != created.ID || got.UserID != created.UserID {
		t.Fatalf("get mismatch: got %#v want %#v", got, created)
	}
	if got.CreatedAt.UnixNano() != created.CreatedAt.UnixNano() {
		t.Fatalf("CreatedAt: got %v want %v", got.CreatedAt, created.CreatedAt)
	}
	if got.ExpiresAt.UnixNano() != created.ExpiresAt.UnixNano() {
		t.Fatalf("ExpiresAt: got %v want %v", got.ExpiresAt, created.ExpiresAt)
	}
	if got.Revoked {
		t.Fatal("Revoked should default to false")
	}
}

func TestSessionManager_GetUnknownReturnsNotFound(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	_, err := mgr.Get(context.Background(), "nonexistent-id")
	if !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("got %v, want ErrSessionNotFound", err)
	}
}

func TestSessionManager_DestroyRemoves(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	created, _ := mgr.Create(ctx, "alice")
	if err := mgr.Destroy(ctx, created.ID); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	_, err := mgr.Get(ctx, created.ID)
	if !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("post-Destroy Get: got %v, want ErrSessionNotFound", err)
	}
	// Destroy is idempotent — second call should not error.
	if err := mgr.Destroy(ctx, created.ID); err != nil {
		t.Fatalf("idempotent Destroy: %v", err)
	}
}

func TestSessionManager_RefreshExtendsExpiresAt(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	created, _ := mgr.Create(ctx, "alice")
	// Sleep so the new ExpiresAt is measurably different.
	time.Sleep(2 * time.Millisecond)

	refreshed, err := mgr.Refresh(ctx, created.ID)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if !refreshed.ExpiresAt.After(created.ExpiresAt) {
		t.Fatalf("Refresh did not extend ExpiresAt: created=%v refreshed=%v",
			created.ExpiresAt, refreshed.ExpiresAt)
	}
	if refreshed.UserID != "alice" {
		t.Fatalf("UserID lost on refresh: %q", refreshed.UserID)
	}
}

func TestSessionManager_RefreshUnknownReturnsNotFound(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	_, err := mgr.Refresh(context.Background(), "nonexistent")
	if !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("got %v, want ErrSessionNotFound", err)
	}
}

// TestSessionManager_RefreshRefusesExpired pins the security
// invariant — a captured session id past its expiry MUST NOT be
// resurrectable. The SQL UPDATE's WHERE filter (expires_at > now)
// is what enforces it; RowsAffected = 0 surfaces as ErrNoRows →
// ErrSessionNotFound. Without the WHERE clause, an attacker who
// captured an old session id and could trigger Refresh (via admin
// RPC, internal handler, etc) could extend it forever.
func TestSessionManager_RefreshRefusesExpired(t *testing.T) {
	mgr := newSessionManagerForTestWithTTL(t, 10*time.Millisecond)
	s, _ := mgr.Create(context.Background(), "alice")
	time.Sleep(20 * time.Millisecond)
	if _, err := mgr.Refresh(context.Background(), s.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("expired Refresh: got %v, want ErrSessionNotFound", err)
	}
}

// TestSessionManager_RefreshRefusesRevoked covers the admin-
// revocation case — operator marks the session revoked, attacker
// captures the id, calls Refresh. MUST fail (the same WHERE
// filter also checks revoked = 0).
func TestSessionManager_RefreshRefusesRevoked(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	s, _ := mgr.Create(context.Background(), "alice")
	// Mark revoked directly via DB so we exercise the Refresh
	// WHERE filter, not Destroy (which removes the row entirely).
	if err := markSessionRevoked(t, mgr, s.ID); err != nil {
		t.Fatalf("markSessionRevoked: %v", err)
	}
	if _, err := mgr.Refresh(context.Background(), s.ID); !errors.Is(err, sso.ErrSessionNotFound) {
		t.Fatalf("revoked Refresh: got %v, want ErrSessionNotFound", err)
	}
}

func TestSessionManager_ListByUserFiltersByOwner(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	a1, _ := mgr.Create(ctx, "alice")
	a2, _ := mgr.Create(ctx, "alice")
	_, _ = mgr.Create(ctx, "bob")

	aliceSessions, err := mgr.ListByUser(ctx, "alice")
	if err != nil {
		t.Fatalf("ListByUser alice: %v", err)
	}
	if len(aliceSessions) != 2 {
		t.Fatalf("alice sessions: got %d want 2", len(aliceSessions))
	}
	seen := map[string]bool{a1.ID: false, a2.ID: false}
	for _, s := range aliceSessions {
		if _, ok := seen[s.ID]; ok {
			seen[s.ID] = true
		}
	}
	for id, ok := range seen {
		if !ok {
			t.Fatalf("missing session %q from ListByUser result", id)
		}
	}

	bobSessions, err := mgr.ListByUser(ctx, "bob")
	if err != nil {
		t.Fatalf("ListByUser bob: %v", err)
	}
	if len(bobSessions) != 1 {
		t.Fatalf("bob sessions: got %d want 1", len(bobSessions))
	}

	noOne, err := mgr.ListByUser(ctx, "ghost")
	if err != nil {
		t.Fatalf("ListByUser ghost: %v", err)
	}
	if len(noOne) != 0 {
		t.Fatalf("ghost sessions: got %d want 0", len(noOne))
	}
}

func TestSessionManager_ListAllReturnsEverything(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	_, _ = mgr.Create(ctx, "alice")
	_, _ = mgr.Create(ctx, "bob")
	_, _ = mgr.Create(ctx, "carol")

	all, err := mgr.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListAll: got %d want 3", len(all))
	}
}

func TestSessionManager_DefaultsToConfiguredTTL(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "default-ttl.db")
	mgr, err := NewSessionManager(dsn, 0) // zero = use sso.DefaultSessionDuration
	if err != nil {
		t.Fatalf("NewSessionManager: %v", err)
	}
	defer func() { _ = mgr.Close() }()

	if mgr.ttl != sso.DefaultSessionDuration {
		t.Fatalf("ttl = %v, want sso.DefaultSessionDuration (%v)", mgr.ttl, sso.DefaultSessionDuration)
	}
	session, _ := mgr.Create(context.Background(), "alice")
	dur := session.ExpiresAt.Sub(session.CreatedAt)
	// Allow a few-ms scheduling slack — the two timestamps are
	// captured between two clock samples inside Create.
	if dur < sso.DefaultSessionDuration-time.Second || dur > sso.DefaultSessionDuration+time.Second {
		t.Fatalf("Create duration = %v, want ~%v", dur, sso.DefaultSessionDuration)
	}
}

func TestSessionManager_CrossInstanceSharing(t *testing.T) {
	// The whole point of SQLite-backed sessions is that a session
	// minted on one process is visible to another against the same
	// DB file — the multi-replica use case.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	mgrA, err := NewSessionManager(dsn, time.Hour)
	if err != nil {
		t.Fatalf("instance A: %v", err)
	}
	defer func() { _ = mgrA.Close() }()
	mgrB, err := NewSessionManager(dsn, time.Hour)
	if err != nil {
		t.Fatalf("instance B: %v", err)
	}
	defer func() { _ = mgrB.Close() }()

	created, err := mgrA.Create(context.Background(), "alice")
	if err != nil {
		t.Fatalf("Create on A: %v", err)
	}
	got, err := mgrB.Get(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("Get on B: %v", err)
	}
	if got.UserID != "alice" || got.ID != created.ID {
		t.Fatalf("cross-instance session mismatch: got %#v want %#v", got, created)
	}
}

func TestSessionManager_CreateWithMeta_RoundTrips(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()

	created, err := mgr.CreateWithMeta(ctx, "alice", sso.SessionMeta{IP: "203.0.113.7", UserAgent: "Mozilla/5.0 Chrome/120"})
	if err != nil {
		t.Fatalf("CreateWithMeta: %v", err)
	}
	if created.IP != "203.0.113.7" || created.UserAgent != "Mozilla/5.0 Chrome/120" {
		t.Fatalf("created meta = %q / %q", created.IP, created.UserAgent)
	}
	// Get round-trips the metadata.
	got, err := mgr.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.IP != "203.0.113.7" || got.UserAgent != "Mozilla/5.0 Chrome/120" {
		t.Errorf("Get meta = %q / %q, want 203.0.113.7 / Mozilla...", got.IP, got.UserAgent)
	}
	// ListByUser carries it too; Refresh preserves it.
	list, _ := mgr.ListByUser(ctx, "alice")
	if len(list) != 1 || list[0].IP != "203.0.113.7" {
		t.Errorf("ListByUser meta lost: %+v", list)
	}
	ref, _ := mgr.Refresh(ctx, created.ID)
	if ref == nil || ref.IP != "203.0.113.7" || ref.UserAgent != "Mozilla/5.0 Chrome/120" {
		t.Errorf("Refresh dropped meta: %+v", ref)
	}
	// Plain Create leaves them empty (no request context).
	plain, _ := mgr.Create(ctx, "bob")
	if plain.IP != "" || plain.UserAgent != "" {
		t.Errorf("plain Create should have empty meta, got %q / %q", plain.IP, plain.UserAgent)
	}
}

// TestSessionManager_MigrationFromV1 verifies the v2 ALTER applies cleanly to a
// DB created at v1 (sessions without the device-context columns).
func TestSessionManager_MigrationFromV1(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "v1.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	// Stand up a v1-only sessions DB (baseline schema, no ip/user_agent).
	db, err := openV1Sessions(t, dsn)
	if err != nil {
		t.Fatalf("v1 setup: %v", err)
	}
	_ = db.Close()
	// Reopen through the real constructor → runs v2.
	mgr, err := NewSessionManager(dsn, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionManager (migrate v1->v2): %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if v := SessionsMaxVersion(); v < 2 {
		t.Fatalf("SessionsMaxVersion = %d, want >=2", v)
	}
	// The new columns exist and round-trip.
	s, err := mgr.CreateWithMeta(ctx, "alice", sso.SessionMeta{IP: "198.51.100.9"})
	if err != nil {
		t.Fatalf("CreateWithMeta after migration: %v", err)
	}
	if got, _ := mgr.Get(ctx, s.ID); got.IP != "198.51.100.9" {
		t.Errorf("ip not persisted after migration: %q", got.IP)
	}
}

// TestSessionManager_DeleteByTenant verifies the bulk-revocation seam used on
// tenant suspension: DeleteByTenant removes only the target tenant's sessions
// and leaves other tenants' (and untagged) sessions intact.
func TestSessionManager_DeleteByTenant(t *testing.T) {
	mgr := newSessionManagerForTest(t)
	ctx := context.Background()
	if _, err := mgr.CreateWithMeta(ctx, "alice", sso.SessionMeta{TenantID: "acme"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := mgr.CreateWithMeta(ctx, "bob", sso.SessionMeta{TenantID: "acme"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	keepTenant, err := mgr.CreateWithMeta(ctx, "carol", sso.SessionMeta{TenantID: "globex"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	keepUntagged, err := mgr.Create(ctx, "dave")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	n, err := mgr.DeleteByTenant(ctx, "acme")
	if err != nil {
		t.Fatalf("DeleteByTenant: %v", err)
	}
	if n != 2 {
		t.Fatalf("deleted %d, want 2", n)
	}
	if _, err := mgr.Get(ctx, keepTenant.ID); err != nil {
		t.Errorf("globex session destroyed: %v", err)
	}
	if _, err := mgr.Get(ctx, keepUntagged.ID); err != nil {
		t.Errorf("untagged session destroyed: %v", err)
	}
	all, _ := mgr.ListAll(ctx)
	if len(all) != 2 {
		t.Errorf("remaining sessions = %d, want 2", len(all))
	}
	// The tenant binding round-trips through the column.
	if got, _ := mgr.Get(ctx, keepTenant.ID); got.TenantID != "globex" {
		t.Errorf("tenant_id not persisted: %q", got.TenantID)
	}
	// Idempotent re-run + empty tenant must not wipe the store.
	if n, _ := mgr.DeleteByTenant(ctx, "acme"); n != 0 {
		t.Errorf("re-delete = %d, want 0", n)
	}
	if n, _ := mgr.DeleteByTenant(ctx, ""); n != 0 {
		t.Errorf("empty tenant deleted %d, want 0 (no wildcard)", n)
	}
	all, _ = mgr.ListAll(ctx)
	if len(all) != 2 {
		t.Errorf("empty-tenant delete must not wipe store, remaining = %d", len(all))
	}
}

// TestSessionManager_MigrationFromV2 verifies the v3 tenant_id ALTER applies
// cleanly to a DB created at v2 (sessions without the tenant binding) and that
// the new column round-trips.
func TestSessionManager_MigrationFromV2(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "v2.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	// Apply ONLY v1+v2 so the tenant_id column added by v3 is absent.
	if err := migrate.Run(ctx, db, "sessions", sessionMigrations[:2]); err != nil {
		t.Fatalf("v2 setup: %v", err)
	}
	_ = db.Close()
	// Reopen through the real constructor → runs v3.
	mgr, err := NewSessionManager(dsn, time.Hour)
	if err != nil {
		t.Fatalf("NewSessionManager (migrate v2->v3): %v", err)
	}
	t.Cleanup(func() { _ = mgr.Close() })
	if v := SessionsMaxVersion(); v < 3 {
		t.Fatalf("SessionsMaxVersion = %d, want >=3", v)
	}
	s, err := mgr.CreateWithMeta(ctx, "alice", sso.SessionMeta{TenantID: "acme"})
	if err != nil {
		t.Fatalf("CreateWithMeta after migration: %v", err)
	}
	if got, _ := mgr.Get(ctx, s.ID); got.TenantID != "acme" {
		t.Errorf("tenant_id not persisted after migration: %q", got.TenantID)
	}
	if n, err := mgr.DeleteByTenant(ctx, "acme"); err != nil || n != 1 {
		t.Errorf("DeleteByTenant after migration = (%d, %v), want (1, nil)", n, err)
	}
}

// openV1Sessions creates a sessions DB at schema v1 only (no device-context
// columns), simulating a deployment that predates the v2 migration.
func openV1Sessions(t *testing.T, dsn string) (*sql.DB, error) {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, err
	}
	// Apply ONLY v1 (baseline) so the columns added by v2 are absent.
	if err := migrate.Run(context.Background(), db, "sessions", sessionMigrations[:1]); err != nil {
		_ = db.Close()
		return nil, err
	}
	return db, nil
}
