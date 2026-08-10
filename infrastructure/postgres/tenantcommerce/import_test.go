package tenantcommerce

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/shared/core"
)

// importTestStore returns a Store over the integration DSN with the
// tenant_commerce outbox tables truncated (the sibling integration tests'
// convention) and a migrated users table. Skips when SSO_TEST_POSTGRES_DSN
// is unset.
func importTestStore(t *testing.T) (postgresbackend.UserProvider, *Store) {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping tenant commerce import integration test")
	}
	db, err := postgresbackend.Open(postgresbackend.Config{DSN: dsn, Dialect: postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	users, err := postgresbackend.NewUserProviderWithDB(db, postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT")))
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewWithDB(db, postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT")))
	if err != nil {
		t.Fatal(err)
	}
	truncateCommerce(t, db)
	// users is NOT truncated (the infrastructure/postgres package tests
	// TRUNCATE it and may run concurrently on the same DSN) — tests use
	// unique IDs and Delete cleanup, mirroring cmd/sso-ctl/importcmd.
	return *users, store
}

func importFact(tenantID, userID, provider string) *commerce.OutboxEvent {
	now := time.Now().UTC()
	key := "import:" + tenantID + ":" + userID
	payload := map[string]string{"user_id": userID, "provider": provider}
	return &commerce.OutboxEvent{
		ID: key, TenantID: tenantID, Type: "snaplink.audit.user.import",
		AggregateType: "user", AggregateID: userID, AggregateVersion: 1,
		IdempotencyKey: key, OccurredAt: now, Payload: payload,
		PayloadDigest: "import-test-digest", Status: commerce.OutboxPending, CreatedAt: now,
	}
}

// TestImportUserTx_PersistsPairAndIdempotent covers the postgres pair-write
// (the exact function the CLI's postgresUserStore adapter calls): commit
// persists user + outbox row atomically; a same-fact re-import is a no-op
// (RowsAffected 0 + ensureOutboxFactTx fact-equality).
func TestImportUserTx_PersistsPairAndIdempotent(t *testing.T) {
	users, store := importTestStore(t)
	ctx := context.Background()
	userID := "importtx:" + t.Name()
	t.Cleanup(func() { _ = users.Delete(ctx, userID) })

	u := &core.User{ID: userID, Email: "pg@x.z", Provider: "csv",
		Attributes: map[string]string{"password_hash": "$2b$h"}}
	if err := ImportUserTx(ctx, store.DB(), u, importFact("tenant-pg", userID, "csv")); err != nil {
		t.Fatalf("ImportUserTx: %v", err)
	}
	got, err := users.GetByID(ctx, userID)
	if err != nil || got.Attributes["password_hash"] != "$2b$h" {
		t.Fatalf("user row missing/attrs wrong: %v %+v", err, got)
	}
	var count int
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tenant_commerce_outbox WHERE tenant_id='tenant-pg' AND aggregate_id=$1`, userID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("outbox rows = %d, want 1", count)
	}

	// Same-fact re-import: no-op, no error, still one row.
	if err := ImportUserTx(ctx, store.DB(), u, importFact("tenant-pg", userID, "csv")); err != nil {
		t.Fatalf("same-fact re-import must no-op: %v", err)
	}
	if err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM tenant_commerce_outbox WHERE tenant_id='tenant-pg' AND aggregate_id=$1`, userID,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Errorf("outbox rows after re-import = %d, want 1", count)
	}
}

// TestImportUserTx_ChangedFactConflictIsRolledBack covers the
// payload-spec-conflict failure mode: a re-import with the same
// deterministic ID/key but a DIFFERENT payload digest surfaces
// commerce.ErrIdempotencyConflict via ensureOutboxFactTx, and the deferred
// rollback undoes the user upsert — the pair never half-applies.
func TestImportUserTx_ChangedFactConflictIsRolledBack(t *testing.T) {
	users, store := importTestStore(t)
	ctx := context.Background()
	userID := "importconflict:" + t.Name()
	t.Cleanup(func() { _ = users.Delete(ctx, userID) })

	u := &core.User{ID: userID, Email: "pg@x.z", Provider: "csv"}
	if err := ImportUserTx(ctx, store.DB(), u, importFact("tenant-pg", userID, "csv")); err != nil {
		t.Fatalf("ImportUserTx: %v", err)
	}
	// Changed payload spec across CLI versions (same ID/key, new digest).
	changed := importFact("tenant-pg", userID, "csv")
	changed.Payload = map[string]string{"user_id": userID, "provider": "csv", "extra": "spec-v2"}
	changed.PayloadDigest = "import-test-digest-v2"
	err := ImportUserTx(ctx, store.DB(), u, changed)
	if !errors.Is(err, commerce.ErrIdempotencyConflict) {
		t.Fatalf("changed-fact conflict err = %v, want ErrIdempotencyConflict", err)
	}
	// The old event row is untouched (rollback of the new pair attempt).
	var payload string
	if err := store.DB().QueryRowContext(ctx,
		`SELECT payload FROM tenant_commerce_outbox WHERE id=$1`, "import:tenant-pg:"+userID,
	).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(payload, "spec-v2") {
		t.Errorf("changed fact overwrote the stored row: %s", payload)
	}
}
