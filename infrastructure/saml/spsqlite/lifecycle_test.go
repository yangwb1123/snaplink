package sqlite

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// capturingLogger records the fail-closed Error calls so a test can assert the
// store surfaced (never swallowed) the DB error on its WithLogger seam.
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

// TestSPSqlite_OpenBadDSN proves the constructors surface an error rather than
// returning a half-built store when the DSN can't be opened/pinged. A file path
// under a non-existent directory fails at PingContext ("unable to open database
// file"), exercising the open-path error branch + the db.Close() cleanup.
func TestSPSqlite_OpenBadDSN(t *testing.T) {
	t.Parallel()
	badDSN := "file:" + filepath.Join(t.TempDir(), "no_such_subdir", "saml.db")
	if _, err := NewAssertionReplayStore(badDSN); err == nil {
		t.Fatal("NewAssertionReplayStore accepted a bad DSN")
	}
	if _, err := NewLogoutReplayStore(badDSN); err == nil {
		t.Fatal("NewLogoutReplayStore accepted a bad DSN")
	}
}

// TestSPSqlite_DBAndPing covers the DB()/Ping() readycheck accessors across the
// open → closed lifecycle for both SP stores.
func TestSPSqlite_DBAndPing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	assertS, err := NewAssertionReplayStore(uniqDSN("sp_db_assert"))
	if err != nil {
		t.Fatalf("new assertion: %v", err)
	}
	if assertS.DB() == nil {
		t.Fatal("DB() nil on open assertion store")
	}
	if err := assertS.Ping(ctx); err != nil {
		t.Fatalf("Ping on open assertion store: %v", err)
	}
	if err := assertS.Close(); err != nil {
		t.Fatalf("close assertion: %v", err)
	}
	if assertS.DB() != nil {
		t.Fatal("DB() non-nil after Close")
	}
	if err := assertS.Ping(ctx); err == nil {
		t.Fatal("Ping on closed assertion store must error")
	}
	// Close is idempotent.
	if err := assertS.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	logoutS, err := NewLogoutReplayStore(uniqDSN("sp_db_logout"))
	if err != nil {
		t.Fatalf("new logout: %v", err)
	}
	if logoutS.DB() == nil {
		t.Fatal("DB() nil on open logout store")
	}
	if err := logoutS.Ping(ctx); err != nil {
		t.Fatalf("Ping on open logout store: %v", err)
	}
	_ = logoutS.Close()
	if logoutS.DB() != nil {
		t.Fatal("logout DB() non-nil after Close")
	}
	if err := logoutS.Ping(ctx); err == nil {
		t.Fatal("Ping on closed logout store must error")
	}
}

// TestSPSqlite_LogoutPruneExpired proves the SP-side logout store's prune hook
// drops only lapsed rows (the assertion store's PruneExpired is already covered).
func TestSPSqlite_LogoutPruneExpired(t *testing.T) {
	t.Parallel()
	s, err := NewLogoutReplayStore(uniqDSN("sp_logout_prune"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	t0 := time.Now()
	s.CheckAndRemember("live", t0.Add(time.Hour), t0)
	s.CheckAndRemember("dead", t0.Add(time.Second), t0)

	n, err := s.PruneExpired(ctx, t0.Add(2*time.Second))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	// "live" still a replay; "dead" reads fresh again after prune.
	if s.CheckAndRemember("live", t0.Add(time.Hour), t0.Add(2*time.Second)) {
		t.Fatal("live row was pruned (should survive)")
	}
	if !s.CheckAndRemember("dead", t0.Add(time.Hour), t0.Add(2*time.Second)) {
		t.Fatal("dead row not pruned (should read fresh)")
	}
}

// TestSPSqlite_PruneAfterCloseErrors proves both stores' PruneExpired reports an
// error (not a silent 0) once the DB handle is gone.
func TestSPSqlite_PruneAfterCloseErrors(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	assertS, _ := NewAssertionReplayStore(uniqDSN("sp_prune_closed_a"))
	_ = assertS.Close()
	if _, err := assertS.PruneExpired(ctx, time.Now()); err == nil {
		t.Fatal("assertion PruneExpired on closed store must error")
	}

	logoutS, _ := NewLogoutReplayStore(uniqDSN("sp_prune_closed_l"))
	_ = logoutS.Close()
	if _, err := logoutS.PruneExpired(ctx, time.Now()); err == nil {
		t.Fatal("logout PruneExpired on closed store must error")
	}
}

// TestSPSqlite_WithLoggerSurfacesFailClosed proves the WithLogger seam receives
// the fail-closed Error when the store can't confirm freshness (here: the DB is
// closed under it). It also proves WithLogger(nil) is a no-op that does NOT
// clobber a previously-set real logger.
func TestSPSqlite_WithLoggerSurfacesFailClosed(t *testing.T) {
	t.Parallel()
	log := &capturingLogger{}
	s, err := NewAssertionReplayStore(uniqDSN("sp_log"), WithLogger(log), WithLogger(nil))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_ = s.Close() // now CheckAndRemember hits the db==nil fail-closed branch
	if s.CheckAndRemember("id", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("closed store returned FRESH; must fail closed")
	}
	if log.count() == 0 {
		t.Fatal("WithLogger seam never saw the fail-closed Error (nil opt clobbered it?)")
	}
}

// TestSPSqlite_IsConstraintErr covers the defensive UNIQUE-constraint classifier
// used on the degraded-build INSERT path.
func TestSPSqlite_IsConstraintErr(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errString("some unrelated error"), false},
		{errString("UNIQUE constraint failed: saml_sp_assertion_replays.id"), true},
		{errString("constraint failed"), true},
	}
	for _, c := range cases {
		if got := isConstraintErr(c.err); got != c.want {
			t.Fatalf("isConstraintErr(%v) = %v, want %v", c.err, got, c.want)
		}
	}
}

// errString is a tiny error stand-in for the classifier test (real DB errors are
// driver-internal; the classifier only inspects Error()).
type errString string

func (e errString) Error() string { return string(e) }
