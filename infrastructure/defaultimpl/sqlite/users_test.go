package sqlite_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/infrastructure/auditoutbox"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newTestProvider builds an in-memory SQLite UserProvider for tests.
// Per-test isolation is automatic — :memory: gives each connection
// its own database. The provider closes when the test cleans up.
func newTestProvider(t *testing.T) *sqlite.UserProvider {
	t.Helper()
	// Use a per-test named in-memory DB so parallel tests don't share state.
	dsn := fmt.Sprintf("file:users_%s?mode=memory&cache=shared&_pragma=busy_timeout(5000)", t.Name())
	p, err := sqlite.NewUserProvider(dsn)
	if err != nil {
		t.Fatalf("NewUserProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestUserProvider_CreateThenGetByID(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()

	in := &sso.User{
		ID:         "alice",
		ExternalID: "github:42",
		Provider:   "github",
		Email:      "alice@example.com",
		Name:       "Alice Example",
		Attributes: map[string]string{"team": "platform", "tier": "gold"},
	}
	if err := p.CreateOrUpdate(ctx, in); err != nil {
		t.Fatalf("CreateOrUpdate: %v", err)
	}
	got, err := p.GetByID(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.ID != in.ID || got.Email != in.Email || got.Name != in.Name {
		t.Errorf("user roundtrip mismatch: got %+v", got)
	}
	if got.Attributes["team"] != "platform" || got.Attributes["tier"] != "gold" {
		t.Errorf("attributes roundtrip mismatch: %v", got.Attributes)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps not stamped: created=%v updated=%v", got.CreatedAt, got.UpdatedAt)
	}
}

func TestUserProvider_SCIMUserNameUniqueCaseInsensitive(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()
	first := &sso.User{ID: "u1", Attributes: map[string]string{"scim:userName": "Alice@example.com"}}
	second := &sso.User{ID: "u2", Attributes: map[string]string{"scim:userName": "alice@example.com"}}
	if err := p.CreateOrUpdate(ctx, first); err != nil {
		t.Fatalf("first CreateOrUpdate: %v", err)
	}
	if err := p.CreateOrUpdate(ctx, second); !errors.Is(err, sso.ErrUserExists) {
		t.Fatalf("duplicate CreateOrUpdate = %v, want ErrUserExists", err)
	}
}

func TestUserProvider_GetByID_MissingReturnsErrNoSuchUser(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	_, err := p.GetByID(context.Background(), "ghost")
	if !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("missing GetByID err = %v, want ErrNoSuchUser", err)
	}
}

func TestUserProvider_GetByExternalID(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()

	_ = p.CreateOrUpdate(ctx, &sso.User{
		ID: "u1", ExternalID: "ext-1", Provider: "github",
	})
	_ = p.CreateOrUpdate(ctx, &sso.User{
		ID: "u2", ExternalID: "ext-2", Provider: "gitlab",
	})

	got, err := p.GetByExternalID(ctx, "github", "ext-1")
	if err != nil {
		t.Fatalf("GetByExternalID: %v", err)
	}
	if got.ID != "u1" {
		t.Errorf("got id %q, want u1", got.ID)
	}
}

func TestUserProvider_GetByExternalID_MissingReturnsErrNoSuchUser(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	_, err := p.GetByExternalID(context.Background(), "github", "nope")
	if !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("got %v, want ErrNoSuchUser", err)
	}
}

func TestUserProvider_CreateOrUpdate_PreservesCreatedAt(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()

	first := &sso.User{ID: "alice", Email: "old@x"}
	if err := p.CreateOrUpdate(ctx, first); err != nil {
		t.Fatalf("first: %v", err)
	}
	createdAt := first.CreatedAt
	if createdAt.IsZero() {
		t.Fatal("CreatedAt not stamped on first insert")
	}

	// Wait a beat so UpdatedAt has a chance to move past CreatedAt
	// at unix-second resolution.
	time.Sleep(1100 * time.Millisecond)

	second := &sso.User{ID: "alice", Email: "new@x"}
	if err := p.CreateOrUpdate(ctx, second); err != nil {
		t.Fatalf("second: %v", err)
	}

	got, err := p.GetByID(ctx, "alice")
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Email != "new@x" {
		t.Errorf("update did not stick: email = %q", got.Email)
	}
	if !got.CreatedAt.Equal(createdAt) {
		t.Errorf("CreatedAt drifted on update: was %v, now %v", createdAt, got.CreatedAt)
	}
	if !got.UpdatedAt.After(createdAt) {
		t.Errorf("UpdatedAt did not advance: created=%v updated=%v", createdAt, got.UpdatedAt)
	}
}

func TestUserProvider_CreateOrUpdate_RejectsEmptyID(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	err := p.CreateOrUpdate(context.Background(), &sso.User{})
	if err == nil {
		t.Error("expected error for empty ID")
	}
}

func TestUserProvider_List_OrderById(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()

	for _, id := range []string{"z", "a", "m"} {
		_ = p.CreateOrUpdate(ctx, &sso.User{ID: id})
	}

	got, err := p.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d users, want 3", len(got))
	}
	want := []string{"a", "m", "z"}
	for i, u := range got {
		if u.ID != want[i] {
			t.Errorf("List[%d].ID = %q, want %q", i, u.ID, want[i])
		}
	}
}

func TestUserProvider_ListPaginated(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()
	for _, id := range []string{"e", "a", "d", "b", "c"} {
		_ = p.CreateOrUpdate(ctx, &sso.User{ID: id})
	}
	page, total, err := p.ListPaginated(ctx, 1, 2)
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	if total != 5 || len(page) != 2 || page[0].ID != "b" || page[1].ID != "c" {
		t.Fatalf("page=%v total=%d, want [b c], 5", page, total)
	}
	empty, total, err := p.ListPaginated(ctx, 99, 10)
	if err != nil || total != 5 || len(empty) != 0 {
		t.Fatalf("past-end page=%v total=%d err=%v", empty, total, err)
	}
}

func TestUserProvider_Delete_RemovesUser(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()

	_ = p.CreateOrUpdate(ctx, &sso.User{ID: "alice"})
	if err := p.Delete(ctx, "alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := p.GetByID(ctx, "alice"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("after delete GetByID err = %v, want ErrNoSuchUser", err)
	}
}

func TestUserProvider_Delete_MissingIDIsIdempotent(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	if err := p.Delete(context.Background(), "ghost"); err != nil {
		t.Errorf("delete of missing id should be nil, got %v", err)
	}
}

func TestUserProvider_NilAttributes_RoundtripsAsNilOrEmpty(t *testing.T) {
	t.Parallel()
	// A User created without Attributes should come back the same way
	// — no surprise allocation of an empty map.
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.CreateOrUpdate(ctx, &sso.User{ID: "u"})
	got, _ := p.GetByID(ctx, "u")
	if len(got.Attributes) != 0 {
		t.Errorf("nil attributes roundtrip = %v, want empty/nil", got.Attributes)
	}
}

// ---- import governance pair-write (R1/R2 of the import spec) ----

// TestUserProvider_CreateOrUpdateTx_ParityAndRollback pins R1: the
// transaction-scoped upsert matches CreateOrUpdate semantics; a rolled-back
// tx leaves no row; a committed tx persists (with CreatedAt preserved on
// the conflict path).
func TestUserProvider_CreateOrUpdateTx_ParityAndRollback(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	ctx := context.Background()

	// Parity: same validation and upsert semantics as CreateOrUpdate.
	tx, err := p.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CreateOrUpdateTx(ctx, tx, &sso.User{ID: "tx:1", Email: "a@x.z"}); err != nil {
		t.Fatalf("CreateOrUpdateTx: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetByID(ctx, "tx:1"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("rolled-back tx left a row: %v", err)
	}

	tx, err = p.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.CreateOrUpdateTx(ctx, tx, &sso.User{ID: "tx:2", Email: "b@x.z"}); err != nil {
		t.Fatalf("CreateOrUpdateTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	got, err := p.GetByID(ctx, "tx:2")
	if err != nil || got.Email != "b@x.z" {
		t.Fatalf("committed tx row missing: %v %+v", err, got)
	}

	// Empty ID rejected inside the tx too.
	tx, err = p.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := p.CreateOrUpdateTx(ctx, tx, &sso.User{}); err == nil {
		t.Error("empty ID must be rejected in tx path")
	}
}

// TestUserProvider_ImportUser_CommitsPairAndRollsBackTogether covers the
// sqlite pair-write (the exact function the import CLI calls): a commit
// persists user + event; an event that fails validation after the user
// upsert rolls BOTH back (no orphan on either side); a same-fact re-import
// is a no-op (deterministic ID).
func TestUserProvider_ImportUser_CommitsPairAndRollsBackTogether(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	if err := auditoutbox.Migrate(context.Background(), p.DB()); err != nil {
		t.Fatalf("migrate audit_outbox: %v", err)
	}
	ctx := context.Background()

	now := time.Now().UTC()
	event := func(tenantID, userID string) *commerce.OutboxEvent {
		key := "import:" + tenantID + ":" + userID
		return &commerce.OutboxEvent{
			ID: key, TenantID: tenantID, Type: "snaplink.audit.user.import",
			AggregateType: "user", AggregateID: userID, AggregateVersion: 1,
			IdempotencyKey: key, OccurredAt: now,
			Payload:       map[string]string{"user_id": userID, "provider": "csv"},
			PayloadDigest: "digest", Status: commerce.OutboxPending, CreatedAt: now,
		}
	}

	// Commit path: both rows land.
	if err := p.ImportUser(ctx, &sso.User{ID: "u1", Email: "a@x.z"}, event("tenant-a", "u1")); err != nil {
		t.Fatalf("ImportUser: %v", err)
	}
	if _, err := p.GetByID(ctx, "u1"); err != nil {
		t.Errorf("user row missing after commit: %v", err)
	}
	var events int
	if err := p.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_outbox WHERE tenant_id='tenant-a'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("event rows = %d, want 1", events)
	}

	// Rollback path: an event failing Validate() after the user upsert
	// undoes the user row too.
	bad := event("tenant-b", "u2")
	bad.TenantID = "" // Validate() requires TenantID
	if err := p.ImportUser(ctx, &sso.User{ID: "u2", Email: "b@x.z"}, bad); err == nil {
		t.Fatal("ImportUser with invalid event must error")
	}
	if _, err := p.GetByID(ctx, "u2"); !errors.Is(err, sso.ErrNoSuchUser) {
		t.Errorf("user row survived the failed pair: %v", err)
	}
	if err := p.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_outbox WHERE tenant_id='tenant-b'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 0 {
		t.Errorf("event rows for rolled-back pair = %d, want 0", events)
	}

	// Idempotent re-import: same deterministic ID → no-op, no error.
	if err := p.ImportUser(ctx, &sso.User{ID: "u1", Email: "a@x.z"}, event("tenant-a", "u1")); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	if err := p.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_outbox WHERE tenant_id='tenant-a'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Errorf("event rows after re-import = %d, want 1 (no duplicate)", events)
	}
}

// TestUserProvider_ImportUser_ChangedFactCollisionKeepsOldRow pins the
// documented sqlite asymmetry: ON CONFLICT(id) DO NOTHING is primary-key
// targeted, so a changed-fact collision (payload spec change across CLI
// versions) silently keeps the OLD row instead of erroring (postgres
// surfaces ErrIdempotencyConflict for the same case).
func TestUserProvider_ImportUser_ChangedFactCollisionKeepsOldRow(t *testing.T) {
	t.Parallel()
	p := newTestProvider(t)
	if err := auditoutbox.Migrate(context.Background(), p.DB()); err != nil {
		t.Fatalf("migrate audit_outbox: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	fact := func(payload map[string]string) *commerce.OutboxEvent {
		return &commerce.OutboxEvent{
			ID: "import:t:u1", TenantID: "t", Type: "snaplink.audit.user.import",
			AggregateType: "user", AggregateID: "u1", AggregateVersion: 1,
			IdempotencyKey: "import:t:u1", OccurredAt: now, Payload: payload,
			PayloadDigest: "d1", Status: commerce.OutboxPending, CreatedAt: now,
		}
	}
	if err := p.ImportUser(ctx, &sso.User{ID: "u1"}, fact(map[string]string{"user_id": "u1", "provider": "csv"})); err != nil {
		t.Fatal(err)
	}
	changed := fact(map[string]string{"user_id": "u1", "provider": "csv", "extra": "spec-v2"})
	if err := p.ImportUser(ctx, &sso.User{ID: "u1"}, changed); err != nil {
		t.Fatalf("sqlite changed-fact collision must no-op, not error: %v", err)
	}
	var payload string
	if err := p.DB().QueryRowContext(ctx, `SELECT payload FROM audit_outbox WHERE id='import:t:u1'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, "spec-v2") {
		t.Errorf("changed fact overwrote the old row: %s", payload)
	}
}
