package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystorecredential"
)

func TestMemoryJTIReplayStore_FirstSeenThenReplay(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryJTIReplayStore()
	ok, err := s.MarkSeen(ctx, "", time.Now().Add(time.Minute))
	if err != nil || !ok {
		t.Errorf("empty jti = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestMemoryJTIReplayStore_DistinctJTIsCoexist(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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

// TestMemoryJTIReplayStore_MaxEntriesRejectsNewKeysAtCapacity covers the
// opt-in cap: once MaxEntries live (unexpired) entries are held, a
// brand-new jti is rejected rather than growing the map further, but
// re-marking an already-tracked jti (a replay check, not growth) is
// unaffected.
func TestMemoryJTIReplayStore_MaxEntriesRejectsNewKeysAtCapacity(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryJTIReplayStore()
	s.MaxEntries = 2
	exp := time.Now().Add(time.Minute)

	if ok, err := s.MarkSeen(ctx, "a", exp); !ok || err != nil {
		t.Fatalf("MarkSeen a = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := s.MarkSeen(ctx, "b", exp); !ok || err != nil {
		t.Fatalf("MarkSeen b = (%v, %v), want (true, nil)", ok, err)
	}
	ok, err := s.MarkSeen(ctx, "c", exp)
	if ok || !errors.Is(err, memorystorecredential.ErrJTIStoreAtCapacity) {
		t.Fatalf("MarkSeen c at capacity = (%v, %v), want (false, ErrJTIStoreAtCapacity)", ok, err)
	}
	// Re-marking an existing key is a replay check, not growth — still
	// correctly reports replay rather than a spurious capacity error.
	replay, err := s.MarkSeen(ctx, "a", exp)
	if replay || err != nil {
		t.Errorf("MarkSeen replay of tracked key a = (%v, %v), want (false, nil)", replay, err)
	}
}

// TestMemoryJTIReplayStore_StartReaperSweepsIdleStore covers the gap lazy
// per-call GC can't reach: an expired entry with no further MarkSeen
// calls on its key is still removed by the background reaper, freeing
// capacity for a new key that would otherwise be rejected.
func TestMemoryJTIReplayStore_StartReaperSweepsIdleStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryJTIReplayStore()
	s.MaxEntries = 1
	s.StartReaper(5 * time.Millisecond)
	t.Cleanup(func() { _ = s.Close() })

	// An already-elapsed expiresAt is clamped by MarkSeen to now+1s (see
	// the "immediate replay" comment on the store) rather than stored
	// as-is, so the reaper only reclaims it a bit over a second later.
	past := time.Now().Add(-time.Hour)
	if ok, err := s.MarkSeen(ctx, "abandoned", past); !ok || err != nil {
		t.Fatalf("MarkSeen abandoned = (%v, %v), want (true, nil)", ok, err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		ok, err := s.MarkSeen(ctx, "fresh", time.Now().Add(time.Minute))
		if err == nil && ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("reaper never freed capacity: last MarkSeen = (%v, %v)", ok, err)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestMemoryJTIReplayStore_CloseWithoutReaperIsNoOp(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryJTIReplayStore()
	if err := s.Close(); err != nil {
		t.Fatalf("Close on a store with no reaper started: %v", err)
	}
}
