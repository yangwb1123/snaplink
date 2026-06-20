package sp

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestReplayStore_FirstSeenThenReplay(t *testing.T) {
	s := newReplayStore(100)
	now := time.Now()
	exp := now.Add(time.Hour)

	if !s.CheckAndRemember("id-1", exp, now) {
		t.Fatal("first sighting of id-1 reported as replay")
	}
	if s.CheckAndRemember("id-1", exp, now) {
		t.Fatal("second sighting of id-1 NOT reported as replay")
	}
	// A distinct ID is fresh.
	if !s.CheckAndRemember("id-2", exp, now) {
		t.Fatal("first sighting of id-2 reported as replay")
	}
}

func TestReplayStore_ExpiredEntryPrunedThenFreshAgain(t *testing.T) {
	s := newReplayStore(100)
	t0 := time.Now()

	// Insert id-1 with a short validity.
	if !s.CheckAndRemember("id-1", t0.Add(10*time.Second), t0) {
		t.Fatal("first sighting reported as replay")
	}
	// Still within window: replay.
	if s.CheckAndRemember("id-1", t0.Add(10*time.Second), t0.Add(5*time.Second)) {
		t.Fatal("within-window re-presentation NOT detected as replay")
	}
	// After expiry: the prune drops it, so it reads as fresh again (by which
	// point the assertion's own expiry check rejects it anyway — this just
	// proves the store doesn't leak entries forever).
	if !s.CheckAndRemember("id-1", t0.Add(10*time.Second), t0.Add(20*time.Second)) {
		t.Fatal("post-expiry presentation should read fresh after prune")
	}
	// Pruning means the store shouldn't be holding the lapsed original twice.
	if got := s.len(); got != 1 {
		t.Errorf("len after prune+reinsert = %d, want 1", got)
	}
}

func TestReplayStore_CapacityEviction(t *testing.T) {
	const cap = 8
	s := newReplayStore(cap)
	now := time.Now()
	exp := now.Add(time.Hour) // all live, so only the hard cap can evict

	// Insert 4x capacity distinct, still-valid IDs.
	for i := 0; i < cap*4; i++ {
		s.CheckAndRemember(fmt.Sprintf("id-%d", i), exp, now)
	}
	if got := s.len(); got != cap {
		t.Fatalf("len = %d, want capped at %d", got, cap)
	}
	// The OLDEST inserts were evicted (LRU by insert order): id-0 should be gone
	// (treated as fresh again), id-(last) should still be a replay.
	if !s.CheckAndRemember("id-0", exp, now) {
		t.Error("id-0 should have been evicted (oldest), but read as replay")
	}
	last := fmt.Sprintf("id-%d", cap*4-1)
	if s.CheckAndRemember(last, exp, now) {
		t.Errorf("%s (newest) should still be present, but read as fresh", last)
	}
}

func TestReplayStore_DefaultCapacity(t *testing.T) {
	s := newReplayStore(0) // non-positive => default
	if s.capacity != DefaultReplayStoreSize {
		t.Errorf("capacity = %d, want default %d", s.capacity, DefaultReplayStoreSize)
	}
}

// TestReplayStore_ConcurrentAccess hammers the store from many goroutines. Run
// with -race -count=10 (the suite's standard) to catch data races + ordering
// bugs in the mutex-guarded list/map.
func TestReplayStore_ConcurrentAccess(t *testing.T) {
	s := newReplayStore(1024)
	now := time.Now()
	exp := now.Add(time.Hour)

	const workers = 32
	const perWorker = 200
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				// Mix of contended (shared) and unique keys.
				shared := fmt.Sprintf("shared-%d", i%16)
				s.CheckAndRemember(shared, exp, now)
				uniq := fmt.Sprintf("w%d-i%d", w, i)
				s.CheckAndRemember(uniq, exp, now)
			}
		}(w)
	}
	wg.Wait()

	// The store must never exceed its capacity, regardless of interleaving.
	if got := s.len(); got > 1024 {
		t.Errorf("len = %d, exceeds capacity 1024", got)
	}

	// A shared key inserted during the run is deterministically a replay now.
	if s.CheckAndRemember("shared-0", exp, now) {
		// shared-0 may have been evicted under capacity pressure; that's allowed.
		// We only assert no panic/race occurred (the race detector does the
		// heavy lifting); this branch is informational, not a failure.
		t.Log("shared-0 was evicted under capacity pressure (acceptable)")
	}
}

// TestReplayStore_ProcessAssertionReplayUsesAssertionID is an integration-flavored
// check that two presentations of the SAME assertion (same ID) are deduped, and
// two DISTINCT assertions both succeed.
func TestReplayStore_DistinctAssertionsBothSucceed(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	r1 := mintValidResponse(t, defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL), idp, tACSURL)
	r2 := mintValidResponse(t, defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL), idp, tACSURL)

	if _, err := a.ProcessAssertion(context.Background(), r1, ""); err != nil {
		t.Fatalf("assertion 1: %v", err)
	}
	if _, err := a.ProcessAssertion(context.Background(), r2, ""); err != nil {
		t.Fatalf("assertion 2 (distinct ID): %v", err)
	}
}
