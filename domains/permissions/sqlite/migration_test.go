package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	permsqlite "github.com/snaplink/sso/domains/permissions/sqlite"
	"github.com/snaplink/sso/platform/migrate"

	_ "modernc.org/sqlite"
)

// TestMigration_StampsBaseline proves the permissions backend runs its
// baseline migration and records version 1 under its own namespace.
// (Functional correctness of the 3 tables is locked by the shared
// permissionstest.ConformanceSuite in the package's other tests.)
func TestMigration_StampsBaseline(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := permsqlite.NewWithDB(db); err != nil {
		t.Fatalf("NewWithDB: %v", err)
	}
	v, err := migrate.CurrentVersion(context.Background(), db, "permissions")
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != 1 {
		t.Errorf("version = %d, want 1", v)
	}

	// Idempotent: a second NewWithDB on the same DB must not error or
	// re-stamp.
	if _, err := permsqlite.NewWithDB(db); err != nil {
		t.Fatalf("second NewWithDB: %v", err)
	}
	if v, _ := migrate.CurrentVersion(context.Background(), db, "permissions"); v != 1 {
		t.Errorf("version = %d after re-run, want 1", v)
	}
}
