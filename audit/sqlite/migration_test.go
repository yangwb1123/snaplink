package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/migrate"
)

// TestNew_StampsCurrentVersion proves a fresh sink runs all migrations
// and stamps the current (highest) schema version.
func TestNew_StampsCurrentVersion(t *testing.T) {
	s, err := New("file:" + filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = s.Close() }()
	v, err := migrate.CurrentVersion(context.Background(), s.db, "audit")
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	want := migrations[len(migrations)-1].Version
	if v != want {
		t.Errorf("schema version = %d, want %d", v, want)
	}
}

// TestNewWithDB_AdoptsPreMigrationSchema proves a database that already
// has audit_events (created the pre-migration way, with data) is
// adopted cleanly: NewWithDB succeeds, stamps the latest schema version,
// and preserves pre-existing rows.
func TestNewWithDB_AdoptsPreMigrationSchema(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Simulate a pre-migration deployment: create the baseline schema
	// directly + seed a row (no tenant_id — the v2 migration will add
	// the column with DEFAULT '' so existing rows survive).
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("legacy schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_events (id, type, outcome, ts_unix_ns) VALUES ('e1', 'login_success', 'success', 1)`,
	); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if _, err := NewWithDB(db); err != nil {
		t.Fatalf("NewWithDB adoption: %v", err)
	}
	want := migrations[len(migrations)-1].Version
	if v, _ := migrate.CurrentVersion(context.Background(), db, "audit"); v != want {
		t.Errorf("version = %d, want %d after adoption", v, want)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id='e1'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("pre-existing event lost: n=%d err=%v", n, err)
	}
}
