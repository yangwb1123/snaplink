package main

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildsign"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/platform/migrate"
)

// stampSchemaVersion forces the recorded version of a migrate namespace to an
// arbitrary value by inserting directly into its schema_migrations_<ns> table.
// This simulates a NEWER binary having forward-migrated the DB beyond what the
// current binary knows — exactly the canary-rollback state the boot guard must
// refuse. We write the row by hand (rather than applying a real migration)
// because the binary deliberately has no v(n+1) migration to apply; the whole
// point is that the DB is ahead of every migration this binary carries.
func stampSchemaVersion(t *testing.T, store interface{ DB() *sql.DB }, table string, version int) {
	t.Helper()
	if _, err := store.DB().Exec(
		`INSERT INTO `+table+` (version, name, applied_at) VALUES (?, ?, ?)`,
		version, "future", 0); err != nil {
		t.Fatalf("stamp %s to v%d: %v", table, version, err)
	}
}

// TestCheckSQLiteSchema_RefusesAheadDB proves the boot guard fails loud when
// the live DB schema is ahead of the binary's max known version — the rollback
// foot-gun. We open a REAL sqlite client store (no mocks), stamp its version
// table to an impossibly-high version, then assert serverbuildsign.CheckSQLiteSchema returns
// ErrSchemaTooNew so startup aborts before any traffic is served.
func TestCheckSQLiteSchema_RefusesAheadDB(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "clients.db") + "?_journal=WAL"
	store, err := sqlitestores.NewClientStore(dsn)
	if err != nil {
		t.Fatalf("open client store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	binaryMax := sqlitestores.ClientsMaxVersion()
	stampSchemaVersion(t, store, "schema_migrations_clients", binaryMax+1)

	err = serverbuildsign.CheckSQLiteSchema(context.Background(), store, "clients", binaryMax)
	if err == nil {
		t.Fatal("expected fatal error when DB schema is ahead of binary")
	}
	if !errors.Is(err, migrate.ErrSchemaTooNew) {
		t.Errorf("error %v, want errors.Is(err, ErrSchemaTooNew)", err)
	}
}

// TestCheckSQLiteSchema_AllowsEqualAndBehind proves the guard stays out of the
// way for the normal cases: a freshly-migrated DB (equal) and a binary that
// knows newer migrations than the DB carries (behind). Neither is a rollback,
// so the forward-migration path must remain unblocked.
func TestCheckSQLiteSchema_AllowsEqualAndBehind(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "clients.db") + "?_journal=WAL"
	store, err := sqlitestores.NewClientStore(dsn)
	if err != nil {
		t.Fatalf("open client store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx := context.Background()
	binaryMax := sqlitestores.ClientsMaxVersion()

	// Equal: the store just ran its migrations to ClientsMaxVersion().
	if err := serverbuildsign.CheckSQLiteSchema(ctx, store, "clients", binaryMax); err != nil {
		t.Errorf("equal versions: unexpected error: %v", err)
	}
	// Behind: pretend this binary knows a far newer schema than the DB has.
	if err := serverbuildsign.CheckSQLiteSchema(ctx, store, "clients", binaryMax+99); err != nil {
		t.Errorf("db behind binary: unexpected error: %v", err)
	}
}

// TestCheckSQLiteSchema_MemoryBackendNoOps proves the guard silently skips
// backends without a DB() handle (memory stores), mirroring serverbuildsign.AppendReadyCheck's
// additive gating — no false rollback alarm for a process-local store.
func TestCheckSQLiteSchema_MemoryBackendNoOps(t *testing.T) {
	t.Parallel()
	// A value with no DB() *sql.DB method must not trip the guard.
	if err := serverbuildsign.CheckSQLiteSchema(context.Background(), struct{}{}, "clients", 0); err != nil {
		t.Errorf("memory backend: unexpected error: %v", err)
	}
}
