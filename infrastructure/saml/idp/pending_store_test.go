package idp

import (
	"sync"
	"testing"
	"time"
)

// TestPendingStore_SingleUseConsume proves a pending id is usable EXACTLY once:
// the first Consume returns it; a second returns !ok.
func TestPendingStore_SingleUseConsume(t *testing.T) {
	t.Parallel()
	s := NewPendingStore(time.Minute, 100)
	id, err := s.Insert(PendingRequest{SPClientID: "c", RequestID: "r"})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, ok := s.Consume(id); !ok {
		t.Fatal("first Consume returned !ok, want ok")
	}
	if _, ok := s.Consume(id); ok {
		t.Fatal("second Consume returned ok, want !ok (single-use)")
	}
	if n := s.len(); n != 0 {
		t.Errorf("len after consume = %d, want 0", n)
	}
}

// TestPendingStore_UnknownIsNotOk proves an unknown id collapses to !ok.
func TestPendingStore_UnknownIsNotOk(t *testing.T) {
	t.Parallel()
	s := NewPendingStore(time.Minute, 100)
	if _, ok := s.Consume("never-inserted"); ok {
		t.Fatal("Consume of unknown id returned ok")
	}
}

// TestPendingStore_ExpiryPrune proves an expired entry is pruned and Consume
// treats it as unknown.
func TestPendingStore_ExpiryPrune(t *testing.T) {
	t.Parallel()
	s := NewPendingStore(time.Minute, 100)
	id, err := s.Insert(PendingRequest{
		SPClientID: "c", RequestID: "r",
		ExpiresAt: time.Now().Add(-time.Second), // already expired
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, ok := s.Consume(id); ok {
		t.Fatal("Consume of expired entry returned ok, want !ok")
	}
	// An Insert prunes expired entries too.
	id2, _ := s.Insert(PendingRequest{
		SPClientID: "c2", RequestID: "r2",
		ExpiresAt: time.Now().Add(-time.Second),
	})
	if _, err := s.Insert(PendingRequest{SPClientID: "c3", RequestID: "r3"}); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, ok := s.Consume(id2); ok {
		t.Fatal("expired id2 survived a later Insert prune")
	}
}

// TestPendingStore_CapacityEviction proves the hard cap evicts the oldest
// insert so the store never grows past capacity.
func TestPendingStore_CapacityEviction(t *testing.T) {
	t.Parallel()
	const cap = 5
	s := NewPendingStore(time.Hour, cap)
	ids := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		id, err := s.Insert(PendingRequest{SPClientID: "c", RequestID: "r"})
		if err != nil {
			t.Fatalf("insert %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	if n := s.len(); n != cap {
		t.Errorf("len = %d, want %d (capped)", n, cap)
	}
	// The first 5 (oldest) were evicted; the last 5 remain.
	for _, id := range ids[:5] {
		if _, ok := s.Consume(id); ok {
			t.Errorf("evicted id %s still present", id)
		}
	}
}

// TestPendingStore_UniqueIDs proves Insert returns distinct ids.
func TestPendingStore_UniqueIDs(t *testing.T) {
	t.Parallel()
	s := NewPendingStore(time.Hour, 1000)
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		id, err := s.Insert(PendingRequest{SPClientID: "c", RequestID: "r"})
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		if seen[id] {
			t.Fatalf("duplicate pending id %q", id)
		}
		seen[id] = true
	}
}

// TestPendingStore_ConcurrentInsertConsume hammers the store from many
// goroutines to prove race-safety (run under -race -count). Each goroutine
// inserts then consumes its own id exactly once.
func TestPendingStore_ConcurrentInsertConsume(t *testing.T) {
	t.Parallel()
	s := NewPendingStore(time.Hour, 100000)
	const workers = 50
	const per = 100

	var wg sync.WaitGroup
	wg.Add(workers)
	var consumed int64
	var mu sync.Mutex
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			local := 0
			for i := 0; i < per; i++ {
				id, err := s.Insert(PendingRequest{SPClientID: "c", RequestID: "r"})
				if err != nil {
					t.Errorf("insert: %v", err)
					return
				}
				if _, ok := s.Consume(id); ok {
					local++
				}
				// A second consume must always fail.
				if _, ok := s.Consume(id); ok {
					t.Error("double-consume succeeded under concurrency")
					return
				}
			}
			mu.Lock()
			consumed += int64(local)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if consumed != workers*per {
		t.Errorf("consumed = %d, want %d (each id consumed exactly once)", consumed, workers*per)
	}
}
