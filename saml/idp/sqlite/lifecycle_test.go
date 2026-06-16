package sqlite

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// capturingLogger records the fail-closed Error calls so a test can assert the
// LogoutReplayStore surfaced (never swallowed) the DB error on its WithLogger
// seam.
type capturingLogger struct {
	mu   sync.Mutex
	msgs []string
}

func (l *capturingLogger) Error(msg string, _ ...any) {
	l.mu.Lock()
	l.msgs = append(l.msgs, msg)
	l.mu.Unlock()
}

func (l *capturingLogger) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.msgs)
}

// TestIdPSqlite_OpenBadDSN proves the constructors surface an error instead of a
// half-built store when the DSN can't be opened/pinged. A file path under a
// non-existent directory fails at PingContext, exercising the open-path error
// branch + the db.Close() cleanup.
func TestIdPSqlite_OpenBadDSN(t *testing.T) {
	badDSN := "file:" + filepath.Join(t.TempDir(), "no_such_subdir", "saml.db")
	if _, err := NewLogoutReplayStore(badDSN); err == nil {
		t.Fatal("NewLogoutReplayStore accepted a bad DSN")
	}
	if _, err := NewSessionIndex(badDSN); err == nil {
		t.Fatal("NewSessionIndex accepted a bad DSN")
	}
}

// TestIdPSqlite_LogoutDBAndPing covers DB()/Ping() across the open → closed
// lifecycle for the logout replay store.
func TestIdPSqlite_LogoutDBAndPing(t *testing.T) {
	ctx := context.Background()
	s, err := NewLogoutReplayStore(uniqDSN("idp_db_logout"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if s.DB() == nil {
		t.Fatal("DB() nil on open store")
	}
	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping on open store: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if s.DB() != nil {
		t.Fatal("DB() non-nil after Close")
	}
	if err := s.Ping(ctx); err == nil {
		t.Fatal("Ping on closed store must error")
	}
	// Close is idempotent.
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestIdPSqlite_SessionIndexDBAndPing covers DB()/Ping() across the open →
// closed lifecycle for the session index, plus that the index's mutators report
// "closed" errors (fail-loud) once the handle is gone.
func TestIdPSqlite_SessionIndexDBAndPing(t *testing.T) {
	ctx := context.Background()
	idx, err := NewSessionIndex(uniqDSN("idp_db_idx"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if idx.DB() == nil {
		t.Fatal("DB() nil on open index")
	}
	if err := idx.Ping(ctx); err != nil {
		t.Fatalf("Ping on open index: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if idx.DB() != nil {
		t.Fatal("DB() non-nil after Close")
	}
	if err := idx.Ping(ctx); err == nil {
		t.Fatal("Ping on closed index must error")
	}

	// Every closed-store path reports an error rather than silently succeeding.
	if err := idx.Record(ctx, "sub", row("sp-1")); err == nil {
		t.Fatal("Record on closed index must error")
	}
	if _, err := idx.ListBySubject(ctx, "sub"); err == nil {
		t.Fatal("ListBySubject on closed index must error")
	}
	if err := idx.Remove(ctx, "sub", "sp-1"); err == nil {
		t.Fatal("Remove on closed index must error")
	}
	if err := idx.RemoveAll(ctx, "sub"); err == nil {
		t.Fatal("RemoveAll on closed index must error")
	}
	if _, err := idx.PruneOlderThan(ctx, time.Now()); err == nil {
		t.Fatal("PruneOlderThan on closed index must error")
	}
}

// TestIdPSqlite_SessionIndexBlankIgnored proves the blank-subject / blank-SP
// guards are nil-safe no-ops on EVERY index method (memory parity) and never
// touch the DB — a degenerate assertion can't fail the issue path.
func TestIdPSqlite_SessionIndexBlankIgnored(t *testing.T) {
	idx, err := NewSessionIndex(uniqDSN("idp_idx_blank"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	ctx := context.Background()

	if err := idx.Record(ctx, "", row("sp-1")); err != nil {
		t.Fatalf("Record blank subject: %v", err)
	}
	if err := idx.Record(ctx, "sub", row("")); err != nil {
		t.Fatalf("Record blank SP: %v", err)
	}
	if out, err := idx.ListBySubject(ctx, ""); err != nil || out != nil {
		t.Fatalf("ListBySubject blank: out=%v err=%v", out, err)
	}
	if err := idx.Remove(ctx, "", "sp-1"); err != nil {
		t.Fatalf("Remove blank subject: %v", err)
	}
	if err := idx.Remove(ctx, "sub", ""); err != nil {
		t.Fatalf("Remove blank SP: %v", err)
	}
	if err := idx.RemoveAll(ctx, ""); err != nil {
		t.Fatalf("RemoveAll blank: %v", err)
	}
	// Nothing should have been written.
	var n int
	if err := idx.DB().QueryRow(`SELECT COUNT(*) FROM saml_session_index`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("blank-keyed ops wrote %d rows, want 0", n)
	}
}

// TestIdPSqlite_PruneOlderThan proves the age-based growth bound: rows recorded
// before the cutoff are dropped, newer rows survive. This is the shared-store
// replacement for the memory subject-LRU (see DefaultSPsPerSubject's doc).
func TestIdPSqlite_PruneOlderThan(t *testing.T) {
	idx, err := NewSessionIndex(uniqDSN("idp_idx_prune"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	ctx := context.Background()

	_ = idx.Record(ctx, "old@example.com", row("sp-old"))
	time.Sleep(2 * time.Millisecond)
	cutoff := time.Now()
	time.Sleep(2 * time.Millisecond)
	_ = idx.Record(ctx, "new@example.com", row("sp-new"))

	n, err := idx.PruneOlderThan(ctx, cutoff)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1 (only the pre-cutoff row)", n)
	}
	// The old subject is gone; the new one survives.
	if rows, _ := idx.ListBySubject(ctx, "old@example.com"); len(rows) != 0 {
		t.Fatalf("pre-cutoff subject not pruned: %+v", rows)
	}
	if rows, _ := idx.ListBySubject(ctx, "new@example.com"); len(rows) != 1 {
		t.Fatalf("post-cutoff subject wrongly pruned: %+v", rows)
	}
}

// TestIdPSqlite_RemoveAndRemoveAll exercises the single-row Remove and the
// whole-subject RemoveAll over real rows (the closed-store error paths are
// covered above; this covers the happy DELETE).
func TestIdPSqlite_RemoveAndRemoveAll(t *testing.T) {
	idx, err := NewSessionIndex(uniqDSN("idp_idx_remove"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	ctx := context.Background()
	const sub = "u@example.com"

	_ = idx.Record(ctx, sub, row("sp-1"))
	_ = idx.Record(ctx, sub, row("sp-2"))
	_ = idx.Record(ctx, sub, row("sp-3"))

	// Remove a single SP; an unknown pair is a no-op (memory parity).
	if err := idx.Remove(ctx, sub, "sp-2"); err != nil {
		t.Fatalf("remove sp-2: %v", err)
	}
	if err := idx.Remove(ctx, sub, "sp-unknown"); err != nil {
		t.Fatalf("remove unknown: %v", err)
	}
	rows, _ := idx.ListBySubject(ctx, sub)
	if len(rows) != 2 {
		t.Fatalf("after single remove: %d rows, want 2", len(rows))
	}

	// RemoveAll drops the rest; an unknown subject is a no-op.
	if err := idx.RemoveAll(ctx, sub); err != nil {
		t.Fatalf("remove all: %v", err)
	}
	if err := idx.RemoveAll(ctx, "nobody@example.com"); err != nil {
		t.Fatalf("remove all unknown: %v", err)
	}
	if rows, _ := idx.ListBySubject(ctx, sub); len(rows) != 0 {
		t.Fatalf("after RemoveAll: %d rows, want 0", len(rows))
	}
}

// TestIdPSqlite_WithMaxSPsPerSubjectFloor proves a non-positive cap falls back to
// the package default (newIndexConfig's floor), so a misconfiguration can't
// disable the per-subject growth bound.
func TestIdPSqlite_WithMaxSPsPerSubjectFloor(t *testing.T) {
	idx, err := NewSessionIndex(uniqDSN("idp_idx_floor"), WithMaxSPsPerSubject(0))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	if idx.maxSPsPerSubject != DefaultSPsPerSubject {
		t.Fatalf("non-positive cap = %d, want default %d", idx.maxSPsPerSubject, DefaultSPsPerSubject)
	}
	// And a negative override also floors.
	idx2, err := NewSessionIndex(uniqDSN("idp_idx_floor2"), WithMaxSPsPerSubject(-5))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = idx2.Close() })
	if idx2.maxSPsPerSubject != DefaultSPsPerSubject {
		t.Fatalf("negative cap = %d, want default %d", idx2.maxSPsPerSubject, DefaultSPsPerSubject)
	}
}

// TestIdPSqlite_WithLoggerSurfacesFailClosed proves the LogoutReplayStore's
// WithLogger seam receives the fail-closed Error when freshness can't be
// confirmed (here: closed DB), and that WithLogger(nil) doesn't clobber a real
// logger.
func TestIdPSqlite_WithLoggerSurfacesFailClosed(t *testing.T) {
	log := &capturingLogger{}
	s, err := NewLogoutReplayStore(uniqDSN("idp_log"), WithLogger(log), WithLogger(nil))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_ = s.Close()
	if s.CheckAndRemember("id", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("closed store returned FRESH; must fail closed")
	}
	if log.count() == 0 {
		t.Fatal("WithLogger seam never saw the fail-closed Error (nil opt clobbered it?)")
	}
}

// TestIdPSqlite_IsConstraintErr covers the defensive UNIQUE-constraint classifier
// used on the degraded-build INSERT path.
func TestIdPSqlite_IsConstraintErr(t *testing.T) {
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errString("some unrelated error"), false},
		{errString("UNIQUE constraint failed: saml_idp_logout_replays.id"), true},
		{errString("constraint failed"), true},
	}
	for _, c := range cases {
		if got := isConstraintErr(c.err); got != c.want {
			t.Fatalf("isConstraintErr(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// TestIdPSqlite_PruneAfterCloseErrors confirms the logout store's PruneExpired
// reports an error (not a silent 0) once the handle is gone.
func TestIdPSqlite_PruneAfterCloseErrors(t *testing.T) {
	s, _ := NewLogoutReplayStore(uniqDSN("idp_prune_closed"))
	_ = s.Close()
	if _, err := s.PruneExpired(context.Background(), time.Now()); err == nil {
		t.Fatal("logout PruneExpired on closed store must error")
	}
}

// errString is a tiny error stand-in for the classifier test.
type errString string

func (e errString) Error() string { return string(e) }
