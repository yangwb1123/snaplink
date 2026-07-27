package sqlite

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/saml/samltest"
)

// uniqDSN returns a process-unique shared-cache in-memory DSN so each store gets
// an isolated DB that survives as long as the pool holds a connection. Mirrors
// the SDK sqlite tests' "file::memory:?cache=shared" idiom but namespaced so two
// stores in the same test don't share tables.
func uniqDSN(name string) string {
	return fmt.Sprintf("file:%s_%d?mode=memory&cache=shared", name, time.Now().UnixNano())
}

// TestAssertionReplayConformance_SQLite runs the shared replay-dedup conformance
// suite against the sqlite AssertionReplayStore — the SAME suite the in-memory
// store runs (saml/sp.TestReplayConformance_Memory), so memory==sqlite.
func TestAssertionReplayConformance_SQLite(t *testing.T) {
	t.Parallel()
	samltest.ReplayConformance{
		Factory: func(t *testing.T) samltest.ReplayChecker {
			s, err := NewAssertionReplayStore(uniqDSN("sp_assert_conf"))
			if err != nil {
				t.Fatalf("new assertion replay store: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
	}.Run(t)
}

// TestLogoutReplayConformance_SQLite runs the shared suite against the sqlite
// SP-side LogoutReplayStore.
func TestLogoutReplayConformance_SQLite(t *testing.T) {
	t.Parallel()
	samltest.ReplayConformance{
		Factory: func(t *testing.T) samltest.ReplayChecker {
			s, err := NewLogoutReplayStore(uniqDSN("sp_logout_conf"))
			if err != nil {
				t.Fatalf("new logout replay store: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
	}.Run(t)
}

// TestAssertionReplay_SeparateNamespaces proves the assertion-replay and
// logout-replay sqlite stores DO NOT collide when they share one *sql.DB: an id
// recorded in the assertion table is still FRESH in the logout table (distinct
// tables/namespaces), so the two ID spaces never cross-trigger a false replay.
func TestAssertionReplay_SeparateNamespaces(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "sp_two_stores")
	assertS, err := NewAssertionReplayStoreWithDB(db)
	if err != nil {
		t.Fatalf("assertion store: %v", err)
	}
	logoutS, err := NewLogoutReplayStoreWithDB(db)
	if err != nil {
		t.Fatalf("logout store: %v", err)
	}
	now := time.Now()
	exp := now.Add(time.Hour)
	if !assertS.CheckAndRemember("shared-id", exp, now) {
		t.Fatal("assertion: first sighting read as replay")
	}
	// SAME id in the logout store must still be fresh (separate table).
	if !logoutS.CheckAndRemember("shared-id", exp, now) {
		t.Fatal("logout store falsely treated an AssertionID as a logout replay (table collision)")
	}
	// And each is now a replay within its OWN table.
	if assertS.CheckAndRemember("shared-id", exp, now) {
		t.Fatal("assertion: replay not detected")
	}
	if logoutS.CheckAndRemember("shared-id", exp, now) {
		t.Fatal("logout: replay not detected")
	}
}

// TestAssertionReplay_FailsClosedAfterClose proves the security posture: once the
// store is Closed (its DB handle gone), CheckAndRemember FAILS CLOSED (returns
// false = reject), never silently letting a possibly-replayed assertion through.
func TestAssertionReplay_FailsClosedAfterClose(t *testing.T) {
	t.Parallel()
	s, err := NewAssertionReplayStore(uniqDSN("sp_failclosed"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_ = s.Close()
	if s.CheckAndRemember("id-1", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("closed store returned FRESH; must fail closed (reject)")
	}
}

// TestAssertionReplay_BlankIDShortCircuits proves the defensive blank-id guard:
// a blank id is treated as fresh and records NOTHING (so a 2nd blank is fresh
// too, and the table stays empty). The callers never pass blank — this is purely
// defense-in-depth so a degenerate caller can't write a blank-keyed row.
func TestAssertionReplay_BlankIDShortCircuits(t *testing.T) {
	t.Parallel()
	s, err := NewAssertionReplayStore(uniqDSN("sp_blank"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now()
	exp := now.Add(time.Hour)
	first := s.CheckAndRemember("", exp, now)
	second := s.CheckAndRemember("", exp, now) // a second blank-id call must also read fresh
	if !first || !second {
		t.Fatal("blank id should always read fresh (records nothing)")
	}
	var n int
	if err := s.DB().QueryRow(`SELECT COUNT(*) FROM saml_sp_assertion_replays`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("blank id wrote %d rows, want 0", n)
	}
}

// TestAssertionReplay_PruneExpired proves the opportunistic prune hook drops
// only lapsed rows.
func TestAssertionReplay_PruneExpired(t *testing.T) {
	t.Parallel()
	s, err := NewAssertionReplayStore(uniqDSN("sp_prune"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	t0 := time.Now()
	s.CheckAndRemember("live", t0.Add(time.Hour), t0)
	s.CheckAndRemember("dead", t0.Add(time.Second), t0)
	// Prune as-of t0+2s: "dead" (exp t0+1s) goes, "live" stays.
	n, err := s.PruneExpired(ctx, t0.Add(2*time.Second))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
	// "live" still a replay; "dead" now fresh again.
	if s.CheckAndRemember("live", t0.Add(time.Hour), t0.Add(2*time.Second)) {
		t.Fatal("live row was pruned (should survive)")
	}
	if !s.CheckAndRemember("dead", t0.Add(time.Hour), t0.Add(2*time.Second)) {
		t.Fatal("dead row not pruned (should read fresh)")
	}
}

// TestAssertionReplay_ConcurrentDedup hammers a SINGLE id from many goroutines
// and asserts EXACTLY ONE sees it fresh — the race-free ON CONFLICT atomic must
// admit one winner, never zero or two. Run with -race -count=10.
func TestAssertionReplay_ConcurrentDedup(t *testing.T) {
	t.Parallel()
	s, err := NewAssertionReplayStore(uniqDSN("sp_conc_one"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now()
	exp := now.Add(time.Hour)

	const workers = 32
	var freshCount int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			if s.CheckAndRemember("contended", exp, now) {
				mu.Lock()
				freshCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if freshCount != 1 {
		t.Fatalf("exactly one goroutine must see the id fresh, got %d", freshCount)
	}
}

// TestAssertionReplay_ConcurrentDistinct hammers DISTINCT ids concurrently (no
// false replays under load). Run with -race -count=10.
func TestAssertionReplay_ConcurrentDistinct(t *testing.T) {
	t.Parallel()
	s, err := NewAssertionReplayStore(uniqDSN("sp_conc_many"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	now := time.Now()
	exp := now.Add(time.Hour)

	const workers = 16
	const per = 100
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < per; i++ {
				id := fmt.Sprintf("w%d-i%d", w, i)
				if !s.CheckAndRemember(id, exp, now) {
					t.Errorf("distinct id %s read as replay", id)
				}
			}
		}(w)
	}
	wg.Wait()
}

// TestSPSqlite_MigrationFreshAndPopulated proves the baseline migration applies
// on a fresh DB (records v1) and no-ops on a re-open (still v1) — mirrors the
// SDK's migration test. Both SP namespaces are checked.
func TestSPSqlite_MigrationFreshAndPopulated(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "sp_migrate")
	ctx := context.Background()

	if _, err := NewAssertionReplayStoreWithDB(db); err != nil {
		t.Fatalf("assertion store (fresh): %v", err)
	}
	if _, err := NewLogoutReplayStoreWithDB(db); err != nil {
		t.Fatalf("logout store (fresh): %v", err)
	}
	for _, ns := range []string{"saml_sp_assertion_replay", "saml_sp_logout_replay"} {
		if v, err := migrate.CurrentVersion(ctx, db, ns); err != nil || v != 1 {
			t.Fatalf("namespace %s version = %d (err %v), want 1", ns, v, err)
		}
	}
	// Re-construct against the SAME populated DB: idempotent no-op, still v1.
	if _, err := NewAssertionReplayStoreWithDB(db); err != nil {
		t.Fatalf("assertion store (populated): %v", err)
	}
	if v, _ := migrate.CurrentVersion(ctx, db, "saml_sp_assertion_replay"); v != 1 {
		t.Fatalf("version after re-open = %d, want 1", v)
	}
}
