package sqlite

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/saml/samltest"
)

// TestLogoutReplayConformance_SQLite runs the shared replay-dedup conformance
// suite against the sqlite IdP LogoutReplayStore — the SAME suite the in-memory
// store runs (saml/idp.TestLogoutReplayConformance_Memory), so memory==sqlite.
func TestLogoutReplayConformance_SQLite(t *testing.T) {
	t.Parallel()
	samltest.ReplayConformance{
		Factory: func(t *testing.T) samltest.ReplayChecker {
			s, err := NewLogoutReplayStore(uniqDSN("idp_logout_conf"))
			if err != nil {
				t.Fatalf("new logout replay store: %v", err)
			}
			t.Cleanup(func() { _ = s.Close() })
			return s
		},
	}.Run(t)
}

// TestLogoutReplay_FailsClosedAfterClose proves the security posture: a Closed
// store FAILS CLOSED (rejects) — a captured LogoutRequest can't slip through on
// a store outage.
func TestLogoutReplay_FailsClosedAfterClose(t *testing.T) {
	t.Parallel()
	s, err := NewLogoutReplayStore(uniqDSN("idp_failclosed"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_ = s.Close()
	if s.CheckAndRemember("id-1", time.Now().Add(time.Hour), time.Now()) {
		t.Fatal("closed store returned FRESH; must fail closed (reject)")
	}
}

// TestLogoutReplay_ConcurrentDedup hammers a SINGLE id and asserts EXACTLY ONE
// goroutine sees it fresh — the ON CONFLICT atomic admits one winner. Run with
// -race -count=10.
func TestLogoutReplay_ConcurrentDedup(t *testing.T) {
	t.Parallel()
	s, err := NewLogoutReplayStore(uniqDSN("idp_conc_one"))
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

// TestLogoutReplay_PruneExpired proves the prune hook drops only lapsed rows.
func TestLogoutReplay_PruneExpired(t *testing.T) {
	t.Parallel()
	s, err := NewLogoutReplayStore(uniqDSN("idp_prune"))
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	t0 := time.Now()
	s.CheckAndRemember("live", t0.Add(time.Hour), t0)
	s.CheckAndRemember("dead", t0.Add(time.Second), t0)
	n, err := s.PruneExpired(t.Context(), t0.Add(2*time.Second))
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n != 1 {
		t.Fatalf("pruned %d rows, want 1", n)
	}
}

// TestIdPSqlite_LogoutReplayMigration proves the baseline migration applies on a
// fresh DB (v1) and no-ops on re-open.
func TestIdPSqlite_LogoutReplayMigration(t *testing.T) {
	t.Parallel()
	db := openSharedDB(t, "idp_logout_migrate")
	if _, err := NewLogoutReplayStoreWithDB(db); err != nil {
		t.Fatalf("fresh: %v", err)
	}
	if v, err := migrate.CurrentVersion(t.Context(), db, "saml_idp_logout_replay"); err != nil || v != 1 {
		t.Fatalf("version = %d (err %v), want 1", v, err)
	}
	if _, err := NewLogoutReplayStoreWithDB(db); err != nil {
		t.Fatalf("populated: %v", err)
	}
	if v, _ := migrate.CurrentVersion(t.Context(), db, "saml_idp_logout_replay"); v != 1 {
		t.Fatalf("version after re-open = %d, want 1", v)
	}
}

// Defensive: distinct ids never falsely collide under concurrency.
func TestLogoutReplay_ConcurrentDistinct(t *testing.T) {
	t.Parallel()
	s, err := NewLogoutReplayStore(uniqDSN("idp_conc_many"))
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
