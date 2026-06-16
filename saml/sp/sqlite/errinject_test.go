package sqlite

import (
	"context"
	"testing"
	"time"
)

// TestSPSqlite_CheckAndRememberFailsClosedOnDBError drives the fail-closed branch
// of checkAndRemember by dropping the replay table out from under a live
// WithDB-wrapped store: the lazy-GC DELETE then errors ("no such table"), so the
// store MUST return false (reject) and surface the error on its logger — never
// admit a possibly-replayed assertion when freshness can't be confirmed.
func TestSPSqlite_CheckAndRememberFailsClosedOnDBError(t *testing.T) {
	db := openSharedDB(t, "sp_errinject")
	log := &capturingLogger{}
	s, err := NewAssertionReplayStoreWithDB(db, WithLogger(log))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// A first call works (table exists) so we know the store is healthy.
	if !s.CheckAndRemember("a", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("healthy store rejected a fresh id")
	}
	// Now break the schema: the table-bound DELETE/INSERT will fail.
	if _, err := db.Exec(`DROP TABLE saml_sp_assertion_replays`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if s.CheckAndRemember("b", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("store returned FRESH after a DB error; must fail closed")
	}
	if log.count() == 0 {
		t.Fatal("fail-closed DB error was not surfaced on the logger")
	}
}

// TestSPSqlite_NopLoggerSilent proves the default (no WithLogger) store is silent
// on the fail-closed path — the nopLogger.Error no-op is exercised without
// panicking. A WithDB store whose table is dropped mid-flight routes the GC error
// through the default nopLogger (the db!=nil error path, not just the closed
// guard), so the no-op sink is actually invoked.
func TestSPSqlite_NopLoggerSilent(t *testing.T) {
	db := openSharedDB(t, "sp_nop")
	s, err := NewAssertionReplayStoreWithDB(db) // no WithLogger ⇒ nopLogger
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE saml_sp_assertion_replays`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	// The GC DELETE errors; the store logs via the nopLogger (no-op) and fails
	// closed. Must not panic and must reject.
	if s.CheckAndRemember("x", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("silent store must still fail closed on a DB error")
	}

	// Also exercise the closed-store (db==nil) fail-closed branch on a plain store.
	closed, err := NewAssertionReplayStore(uniqDSN("sp_nop_closed"))
	if err != nil {
		t.Fatalf("new closed: %v", err)
	}
	_ = closed.Close()
	if closed.CheckAndRemember("y", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("closed store must fail closed")
	}
}

// TestSPSqlite_CheckAndRememberFailsClosedOnConnError covers the conn-acquisition
// fail-closed branch: a WithDB store whose underlying pool is closed (but whose
// non-nil handle still passes the db==nil guard) can't open a connection, so
// CheckAndRemember rejects rather than admitting a possibly-replayed assertion.
func TestSPSqlite_CheckAndRememberFailsClosedOnConnError(t *testing.T) {
	db := openSharedDB(t, "sp_connerr")
	log := &capturingLogger{}
	s, err := NewAssertionReplayStoreWithDB(db, WithLogger(log))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	// Close the pool directly — the store keeps its (now-closed) *sql.DB handle.
	if err := db.Close(); err != nil {
		t.Fatalf("close pool: %v", err)
	}
	if s.CheckAndRemember("a", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("store returned FRESH after a conn-acquisition error; must fail closed")
	}
	if log.count() == 0 {
		t.Fatal("conn-acquisition error was not surfaced on the logger")
	}
}

// TestSPSqlite_PruneExpiredDBError covers PruneExpired's exec-error branch by
// dropping the table before the prune runs.
func TestSPSqlite_PruneExpiredDBError(t *testing.T) {
	db := openSharedDB(t, "sp_prune_err")
	s, err := NewAssertionReplayStoreWithDB(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE saml_sp_assertion_replays`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := s.PruneExpired(context.Background(), time.Now()); err == nil {
		t.Fatal("PruneExpired against a missing table must error")
	}
}
