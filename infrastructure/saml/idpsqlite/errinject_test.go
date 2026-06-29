package sqlite

import (
	"context"
	"testing"
	"time"
)

// TestIdPSqlite_CheckAndRememberFailsClosedOnDBError drives the fail-closed
// branch of the IdP LogoutReplayStore by dropping the table out from under a live
// WithDB store: the lazy-GC DELETE then errors, so the store MUST reject (a
// captured LogoutRequest can't slip through on a store error) and surface it via
// logErr.
func TestIdPSqlite_CheckAndRememberFailsClosedOnDBError(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_errinject")
	log := &capturingLogger{}
	s, err := NewLogoutReplayStoreWithDB(db, WithLogger(log))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if !s.CheckAndRemember("a", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("healthy store rejected a fresh id")
	}
	if _, err := db.Exec(`DROP TABLE saml_idp_logout_replays`); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if s.CheckAndRemember("b", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("store returned FRESH after a DB error; must fail closed")
	}
	if log.count() == 0 {
		t.Fatal("fail-closed DB error was not surfaced via logErr")
	}
}

// TestIdPSqlite_LogErrNilSafe covers logErr's nil-store / nil-logger guards: a
// silent (no WithLogger) store still fails closed without panicking on the
// closed-DB path.
func TestIdPSqlite_LogErrNilSafe(t *testing.T) {
	t.Parallel()
	s, err := NewLogoutReplayStore(uniqDSN("idp_nop"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_ = s.Close() // db==nil ⇒ logErr("store closed", nil) on the nopLogger
	if s.CheckAndRemember("x", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("silent closed store must still fail closed")
	}
}

// TestIdPSqlite_CheckAndRememberFailsClosedOnConnError covers the IdP logout
// store's conn-acquisition fail-closed branch: a closed pool (non-nil handle)
// can't open a connection, so a captured LogoutRequest is rejected.
func TestIdPSqlite_CheckAndRememberFailsClosedOnConnError(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_connerr")
	log := &capturingLogger{}
	s, err := NewLogoutReplayStoreWithDB(db, WithLogger(log))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close pool: %v", err)
	}
	if s.CheckAndRemember("a", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("store returned FRESH after a conn-acquisition error; must fail closed")
	}
	if log.count() == 0 {
		t.Fatal("conn-acquisition error was not surfaced via logErr")
	}
}

// TestIdPSqlite_RecordConnError covers Record's conn-acquisition error branch
// over a closed pool.
func TestIdPSqlite_RecordConnError(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_record_connerr")
	idx, err := NewSessionIndexWithDB(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close pool: %v", err)
	}
	if err := idx.Record(context.Background(), "sub", row("sp-1")); err == nil {
		t.Fatal("Record on a closed pool must error")
	}
}

// TestIdPSqlite_PruneExpiredDBError covers the logout PruneExpired exec-error
// branch.
func TestIdPSqlite_PruneExpiredDBError(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_prune_err")
	s, err := NewLogoutReplayStoreWithDB(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE saml_idp_logout_replays`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := s.PruneExpired(context.Background(), time.Now()); err == nil {
		t.Fatal("PruneExpired against a missing table must error")
	}
}

// TestIdPSqlite_RecordDBError covers Record's upsert exec-error branch (and its
// ROLLBACK defer) by dropping the index table mid-flight.
func TestIdPSqlite_RecordDBError(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_record_err")
	idx, err := NewSessionIndexWithDB(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE saml_session_index`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if err := idx.Record(context.Background(), "sub", row("sp-1")); err == nil {
		t.Fatal("Record against a missing table must error (rolled back)")
	}
}

// TestIdPSqlite_ListBySubjectDBError covers ListBySubject's query-error branch.
func TestIdPSqlite_ListBySubjectDBError(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_list_err")
	idx, err := NewSessionIndexWithDB(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE saml_session_index`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	if _, err := idx.ListBySubject(context.Background(), "sub"); err == nil {
		t.Fatal("ListBySubject against a missing table must error")
	}
}

// TestIdPSqlite_RemoveDBError covers the exec-error branches of Remove / RemoveAll
// / PruneOlderThan over a real-but-broken DB.
func TestIdPSqlite_RemoveDBError(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_remove_err")
	idx, err := NewSessionIndexWithDB(db)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE saml_session_index`); err != nil {
		t.Fatalf("drop: %v", err)
	}
	ctx := context.Background()
	if err := idx.Remove(ctx, "sub", "sp-1"); err == nil {
		t.Fatal("Remove against a missing table must error")
	}
	if err := idx.RemoveAll(ctx, "sub"); err == nil {
		t.Fatal("RemoveAll against a missing table must error")
	}
	if _, err := idx.PruneOlderThan(ctx, time.Now()); err == nil {
		t.Fatal("PruneOlderThan against a missing table must error")
	}
}
