package sqlite_test

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	permsqlite "github.com/yangwb1123/snaplink/domains/permissions/sqlite"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite"
)

// TestMigration_StampsBaseline proves the permissions backend runs its
// baseline migration and records the current version under its own namespace.
// (Functional correctness of the tables is locked by the shared
// permissionstest.ConformanceSuite in the package's other tests.)
func TestMigration_StampsBaseline(t *testing.T) {
	t.Parallel()
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
	if v != 2 {
		t.Errorf("version = %d, want 2", v)
	}

	// Idempotent: a second NewWithDB on the same DB must not error or
	// re-stamp.
	if _, err := permsqlite.NewWithDB(db); err != nil {
		t.Fatalf("second NewWithDB: %v", err)
	}
	if v, _ := migrate.CurrentVersion(context.Background(), db, "permissions"); v != 2 {
		t.Errorf("version = %d after re-run, want 2", v)
	}
}

func TestMigration_UpgradesV1ToResourceCatalog(t *testing.T) {
	t.Parallel()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()
	if _, err := db.Exec(`
        CREATE TABLE schema_migrations_permissions (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL
        );
        INSERT INTO schema_migrations_permissions(version, name, applied_at)
        VALUES (1, 'baseline_permissions', 1);`); err != nil {
		t.Fatalf("seed v1: %v", err)
	}
	if _, err := permsqlite.NewWithDB(db); err != nil {
		t.Fatalf("NewWithDB: %v", err)
	}
	var table string
	if err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'permissions_resources'`).Scan(&table); err != nil {
		t.Fatalf("resource table missing: %v", err)
	}
	v, err := migrate.CurrentVersion(context.Background(), db, "permissions")
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != 2 {
		t.Fatalf("version = %d, want 2", v)
	}
}
