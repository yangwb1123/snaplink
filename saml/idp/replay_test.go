package idp

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestLogoutReplayStore_FirstSeenThenReplay: a fresh LogoutRequest ID is
// accepted once and rejected on the second (within-window) sighting.
func TestLogoutReplayStore_FirstSeenThenReplay(t *testing.T) {
	s := newLogoutReplayStore(100)
	now := time.Now()
	exp := now.Add(time.Hour)

	if !s.checkAndRemember("id-1", exp, now) {
		t.Fatal("first sighting of id-1 reported as replay")
	}
	if s.checkAndRemember("id-1", exp, now) {
		t.Fatal("second sighting of id-1 NOT reported as replay")
	}
	if !s.checkAndRemember("id-2", exp, now) {
		t.Fatal("first sighting of id-2 reported as replay")
	}
}

// TestLogoutReplayStore_ExpiredPrunedThenFreshAgain: once an entry's window has
// lapsed it is pruned (a later same-ID sighting reads fresh — by then the
// freshness check rejects it anyway).
func TestLogoutReplayStore_ExpiredPrunedThenFreshAgain(t *testing.T) {
	s := newLogoutReplayStore(100)
	t0 := time.Now()

	if !s.checkAndRemember("id-1", t0.Add(10*time.Second), t0) {
		t.Fatal("first sighting reported as replay")
	}
	if s.checkAndRemember("id-1", t0.Add(10*time.Second), t0.Add(5*time.Second)) {
		t.Fatal("within-window re-presentation NOT detected as replay")
	}
	if !s.checkAndRemember("id-1", t0.Add(10*time.Second), t0.Add(20*time.Second)) {
		t.Fatal("post-expiry presentation should read fresh after prune")
	}
	if got := s.len(); got != 1 {
		t.Errorf("len after prune+reinsert = %d, want 1", got)
	}
}

// TestLogoutReplayStore_CapacityEviction: the hard cap evicts oldest inserts so
// the store never grows past capacity under a flood of distinct IDs.
func TestLogoutReplayStore_CapacityEviction(t *testing.T) {
	const capacity = 8
	s := newLogoutReplayStore(capacity)
	now := time.Now()
	exp := now.Add(time.Hour)

	for i := 0; i < capacity*4; i++ {
		s.checkAndRemember(fmt.Sprintf("id-%d", i), exp, now)
	}
	if got := s.len(); got != capacity {
		t.Fatalf("len = %d, want capped at %d", got, capacity)
	}
	if !s.checkAndRemember("id-0", exp, now) {
		t.Error("id-0 should have been evicted (oldest), but read as replay")
	}
	last := fmt.Sprintf("id-%d", capacity*4-1)
	if s.checkAndRemember(last, exp, now) {
		t.Errorf("%s (newest) should still be present, but read as fresh", last)
	}
}

// TestLogoutReplayStore_DefaultCapacity: a non-positive capacity falls back to
// the default.
func TestLogoutReplayStore_DefaultCapacity(t *testing.T) {
	s := newLogoutReplayStore(0)
	if s.capacity != DefaultLogoutReplayStoreSize {
		t.Errorf("capacity = %d, want default %d", s.capacity, DefaultLogoutReplayStoreSize)
	}
}

// TestLogoutReplayStore_ConcurrentAccess hammers the store from many goroutines.
// Run with -race -count=10 (the suite standard) to catch data races + ordering
// bugs in the mutex-guarded list/map.
func TestLogoutReplayStore_ConcurrentAccess(t *testing.T) {
	s := newLogoutReplayStore(1024)
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
				shared := fmt.Sprintf("shared-%d", i%16)
				s.checkAndRemember(shared, exp, now)
				uniq := fmt.Sprintf("w%d-i%d", w, i)
				s.checkAndRemember(uniq, exp, now)
			}
		}(w)
	}
	wg.Wait()

	if got := s.len(); got > 1024 {
		t.Errorf("len = %d, exceeds capacity 1024", got)
	}
}
