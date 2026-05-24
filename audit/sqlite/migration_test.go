package sqlite

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/migrate"
)

// TestNew_StampsBaselineVersion proves a fresh sink runs the baseline
// migration and records version 1.
func TestNew_StampsBaselineVersion(t *testing.T) {
	s, err := New("file:" + filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Close()
	v, err := migrate.CurrentVersion(context.Background(), s.db, "audit")
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if v != 1 {
		t.Errorf("schema version = %d, want 1", v)
	}
}

// TestNewWithDB_AdoptsPreMigrationSchema proves a database that already
// has audit_events (created the pre-migration way, with data) is
// adopted cleanly: NewWithDB succeeds, stamps v1, and preserves rows.
func TestNewWithDB_AdoptsPreMigrationSchema(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()

	// Simulate a pre-migration deployment: create the schema directly +
	// seed a row.
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
	if v, _ := migrate.CurrentVersion(context.Background(), db, "audit"); v != 1 {
		t.Errorf("version = %d, want 1 after adoption", v)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id='e1'`).Scan(&n); err != nil || n != 1 {
		t.Errorf("pre-existing event lost: n=%d err=%v", n, err)
	}
}
