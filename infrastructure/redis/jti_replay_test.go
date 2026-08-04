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

func TestRevocationStoreSharedLoadAndPrune(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	writer := NewRevocationStore(rdb)
	reader := NewRevocationStore(rdb)
	ctx := context.Background()
	now := time.Now().Unix()
	boundary := now + 60
	future := now + 120

	for token, exp := range map[string]int64{
		"expired":  now - 1,
		"boundary": boundary,
		"future":   future,
	} {
		if err := writer.Revoke(ctx, token, exp); err != nil {
			t.Fatalf("Revoke(%q): %v", token, err)
		}
	}
	if count, err := rdb.ZCard(ctx, revocationSetKey).Result(); err != nil || count != 2 {
		t.Fatalf("stored revocations = (%d, %v), want two live entries", count, err)
	}

	loaded, err := reader.Load(ctx)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := loaded["expired"]; ok {
		t.Fatal("Load returned an expired revocation")
	}
	if loaded["boundary"] != boundary || loaded["future"] != future {
		t.Fatalf("shared revocations = %#v, want boundary and future entries", loaded)
	}

	if err := reader.Prune(ctx, boundary); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	loaded, err = writer.Load(ctx)
	if err != nil {
		t.Fatalf("Load after Prune: %v", err)
	}
	if loaded["boundary"] != boundary || loaded["future"] != future {
		t.Fatalf("boundary prune revocations = %#v, want boundary and future entries", loaded)
	}
	if err := reader.Prune(ctx, future+1); err != nil {
		t.Fatalf("final Prune: %v", err)
	}
	if count, err := rdb.ZCard(ctx, revocationSetKey).Result(); err != nil || count != 0 {
		t.Fatalf("stored revocations after final Prune = (%d, %v), want empty", count, err)
	}
}
