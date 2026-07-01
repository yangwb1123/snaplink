package sqlite

import (
	"database/sql"
	"fmt"
	"sync"
)

// sharedDBGuard ensures we only create one shared DB instance per DSN.
var (
	sharedMu  sync.Mutex
	sharedDBs map[string]*sql.DB
)

// SharedDB returns a shared *sql.DB for the given DSN. The same DSN
// always returns the same *sql.DB, so the 20+ stores in the SSO
// server share one connection pool instead of each calling sql.Open
// independently — eliminating WAL write-lock convoy (§10 direction 1).
//
// Callers MUST NOT close the returned *sql.DB — it is shared across
// all stores until process exit.
//
// The first call for a DSN calls sql.Open and sets MaxOpenConns(1)
// (correct for SQLite — WAL allows one writer at a time) plus
// PRAGMA journal_mode=WAL and synchronous=NORMAL for optimal shared
// access. Subsequent calls for the same DSN return the same *sql.DB.
//
// Safe for concurrent use.
func SharedDB(dsn string) (*sql.DB, error) {
	sharedMu.Lock()
	defer sharedMu.Unlock()

	if sharedDBs == nil {
		sharedDBs = make(map[string]*sql.DB)
	}
	if db, ok := sharedDBs[dsn]; ok {
		return db, nil
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite shared db: open %s: %w", dsn, err)
	}
	db.SetMaxOpenConns(1)

	// Fast WAL mode: concurrent reads, single writer, reduced fsync.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("sqlite shared db: %s: %w", p, err)
		}
	}

	sharedDBs[dsn] = db
	return db, nil
}

// ResetSharedDBs removes all cached shared DB instances. Used in tests
// to avoid DSN collisions across test cases. NOT safe for concurrent
// use with SharedDB — call only from TestMain or init functions.
func ResetSharedDBs() {
	sharedMu.Lock()
	defer sharedMu.Unlock()
	for _, db := range sharedDBs {
		_ = db.Close()
	}
	sharedDBs = nil
}
