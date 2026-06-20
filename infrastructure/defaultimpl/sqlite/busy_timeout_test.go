package sqlite

import (
	"context"
	"database/sql"
	"testing"
)

// busyTimeoutOf opens a raw modernc connection (NO store, so the migration
// runner's one-time PRAGMA busy_timeout does not mask the result) and reads
// the effective busy_timeout the connection hook installed. This is exactly
// the path a recycled / freshly-opened pool connection takes at runtime —
// the one that previously ran with busy_timeout=0.
func busyTimeoutOf(t *testing.T, dsn string) int {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	var ms int
	// The query forces a real connection, firing the registered hook.
	if err := db.QueryRowContext(context.Background(), "PRAGMA busy_timeout").Scan(&ms); err != nil {
		t.Fatalf("query busy_timeout: %v", err)
	}
	return ms
}

// TestBusyTimeout_DefaultApplied verifies the hook injects the default
// busy_timeout on a connection whose DSN does not specify one — the gap this
// fixes (such a connection previously ran with busy_timeout=0 and returned
// SQLITE_BUSY immediately under writer contention).
func TestBusyTimeout_DefaultApplied(t *testing.T) {
	got := busyTimeoutOf(t, "file::memory:")
	if got != defaultBusyTimeoutMS {
		t.Errorf("busy_timeout = %d, want %d (hook must inject the default on a fresh conn)", got, defaultBusyTimeoutMS)
	}
}

// TestBusyTimeout_OperatorOverrideWins verifies an explicit DSN busy_timeout
// is respected — the hook must not clobber operator-supplied config.
func TestBusyTimeout_OperatorOverrideWins(t *testing.T) {
	const want = 1234
	got := busyTimeoutOf(t, "file::memory:?_pragma=busy_timeout(1234)")
	if got != want {
		t.Errorf("busy_timeout = %d, want %d (operator DSN _pragma must win over the hook default)", got, want)
	}
}
