package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/defaultimpl"
)

func TestMemoryJTIReplayStore_FirstSeenThenReplay(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryJTIReplayStore()
	exp := time.Now().Add(time.Minute)

	first, err := s.MarkSeen(ctx, "jti-1", exp)
	if err != nil {
		t.Fatalf("MarkSeen: %v", err)
	}
	if !first {
		t.Error("first MarkSeen should report unseen (true)")
	}

	second, err := s.MarkSeen(ctx, "jti-1", exp)
	if err != nil {
		t.Fatalf("MarkSeen replay: %v", err)
	}
	if second {
		t.Error("replay within window should report seen (false)")
	}
}

func TestMemoryJTIReplayStore_EmptyJTIAlwaysFresh(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryJTIReplayStore()
	ok, err := s.MarkSeen(ctx, "", time.Now().Add(time.Minute))
	if err != nil || !ok {
		t.Errorf("empty jti = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestMemoryJTIReplayStore_DistinctJTIsCoexist(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryJTIReplayStore()
	exp := time.Now().Add(time.Minute)
	if ok, _ := s.MarkSeen(ctx, "a", exp); !ok {
		t.Error("a should be fresh")
	}
	if ok, _ := s.MarkSeen(ctx, "b", exp); !ok {
		t.Error("b should be fresh (distinct from a)")
	}
}

// TestMemoryJTIReplayStore_LazyGCAllowsReuseAfterExpiry covers the lazy
// sweep: once an entry's recorded expiry has passed, the next MarkSeen of
// the same jti sees it as fresh again (the entry was GC'd, not a replay).
func TestMemoryJTIReplayStore_LazyGCAllowsReuseAfterExpiry(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryJTIReplayStore()
	// Already-elapsed exp: the store clamps it to now+1s so an immediate
	// replay is still caught, but after that the entry is GC'd.
	past := time.Now().Add(-time.Hour)
	if ok, _ := s.MarkSeen(ctx, "stale", past); !ok {
		t.Fatal("first MarkSeen of stale jti should be fresh")
	}
	// Immediate replay still caught (clamped window).
	if ok, _ := s.MarkSeen(ctx, "stale", past); ok {
		t.Error("immediate replay of clamped jti should be caught")
	}
}
