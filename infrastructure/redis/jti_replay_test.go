package redis

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestJTIFirstVsRepeat: first MarkSeen is the first-sighting (true), a
// repeat within the window is a replay (false).
func TestJTIFirstVsRepeat(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewJTIReplayStore(rdb)
	ctx := context.Background()
	exp := time.Now().Add(5 * time.Minute)

	first, err := s.MarkSeen(ctx, "jti-1", exp)
	if err != nil {
		t.Fatalf("first MarkSeen: %v", err)
	}
	if !first {
		t.Fatalf("first sighting: want true, got false")
	}
	repeat, err := s.MarkSeen(ctx, "jti-1", exp)
	if err != nil {
		t.Fatalf("repeat MarkSeen: %v", err)
	}
	if repeat {
		t.Fatalf("replay: want false, got true")
	}
}

// TestJTIDistinctIndependent: distinct jtis are independent first-sightings.
func TestJTIDistinctIndependent(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewJTIReplayStore(rdb)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	for _, j := range []string{"a", "b", "c"} {
		first, err := s.MarkSeen(ctx, j, exp)
		if err != nil || !first {
			t.Fatalf("jti %q: first=%v err=%v", j, first, err)
		}
	}
}

// TestJTIEmptyShortCircuits: empty jti is always first-sighting (the SPI
// says the call site should short-circuit, but the store must not treat ""
// as a replay sentinel).
func TestJTIEmptyShortCircuits(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewJTIReplayStore(rdb)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		first, err := s.MarkSeen(ctx, "", time.Now().Add(time.Minute))
		if err != nil || !first {
			t.Fatalf("empty jti: first=%v err=%v", first, err)
		}
	}
}

// TestJTIExpiryWindow: after the key's TTL elapses, the same jti is a
// fresh first-sighting again (the window closed).
func TestJTIExpiryWindow(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	s := NewJTIReplayStore(rdb)
	ctx := context.Background()

	if first, _ := s.MarkSeen(ctx, "windowed", time.Now().Add(time.Second)); !first {
		t.Fatalf("initial: want first-sighting")
	}
	mr.FastForward(2 * time.Second)
	if first, _ := s.MarkSeen(ctx, "windowed", time.Now().Add(time.Second)); !first {
		t.Fatalf("after window: want fresh first-sighting")
	}
}

// TestJTIConcurrentSingleWinner: under concurrency exactly one MarkSeen of
// the same jti reports first-sighting (atomic SET NX). Run with -race.
func TestJTIConcurrentSingleWinner(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewJTIReplayStore(rdb)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	const n = 32
	var wg sync.WaitGroup
	var mu sync.Mutex
	firsts := 0
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			first, err := s.MarkSeen(ctx, "race-jti", exp)
			if err != nil {
				t.Errorf("MarkSeen: %v", err)
				return
			}
			if first {
				mu.Lock()
				firsts++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if firsts != 1 {
		t.Fatalf("atomic first-sighting violated: %d firsts, want 1", firsts)
	}
}
