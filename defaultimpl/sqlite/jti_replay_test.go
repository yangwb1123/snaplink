package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newJTIReplayStoreForTest(t *testing.T) *JTIReplayStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "jti.db") + "?_journal=WAL&_busy_timeout=5000"
	store, err := NewJTIReplayStore(dsn)
	if err != nil {
		t.Fatalf("NewJTIReplayStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestJTIReplayStore_FirstSightingThenReplay(t *testing.T) {
	store := newJTIReplayStoreForTest(t)
	ctx := context.Background()

	first, err := store.MarkSeen(ctx, "jti-1", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("first MarkSeen: %v", err)
	}
	if !first {
		t.Fatal("first sighting must return true")
	}

	second, err := store.MarkSeen(ctx, "jti-1", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("second MarkSeen: %v", err)
	}
	if second {
		t.Fatal("replay must return false")
	}
}

func TestJTIReplayStore_EmptyJTIAlwaysAccepts(t *testing.T) {
	store := newJTIReplayStoreForTest(t)
	for range 3 {
		ok, err := store.MarkSeen(context.Background(), "", time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("MarkSeen(\"\"): %v", err)
		}
		if !ok {
			t.Fatal("empty jti must always return true (caller-side guard)")
		}
	}
}

func TestJTIReplayStore_DifferentJTIsCoexist(t *testing.T) {
	store := newJTIReplayStoreForTest(t)
	ctx := context.Background()

	for _, jti := range []string{"a", "b", "c", "d", "e"} {
		ok, err := store.MarkSeen(ctx, jti, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("MarkSeen(%q): %v", jti, err)
		}
		if !ok {
			t.Fatalf("MarkSeen(%q): got replay on first sighting", jti)
		}
	}
	// All five must remain blocked on replay.
	for _, jti := range []string{"a", "b", "c", "d", "e"} {
		ok, err := store.MarkSeen(ctx, jti, time.Now().Add(time.Minute))
		if err != nil {
			t.Fatalf("replay MarkSeen(%q): %v", jti, err)
		}
		if ok {
			t.Fatalf("MarkSeen(%q) replay returned true (should be blocked)", jti)
		}
	}
}

func TestJTIReplayStore_ExpiredEntryGCdAndResubmissionAllowed(t *testing.T) {
	store := newJTIReplayStoreForTest(t)
	ctx := context.Background()

	// Record with expiry in the very near past so the next MarkSeen
	// triggers the lazy GC sweep before checking conflict.
	first, err := store.MarkSeen(ctx, "jti-expiring", time.Now().Add(-1*time.Millisecond))
	if err != nil {
		t.Fatalf("first MarkSeen: %v", err)
	}
	if !first {
		t.Fatal("first sighting must return true")
	}

	// Give GC a tick — the bumped 1s expiry from the past-exp branch
	// means we need >1s for the GC to evict on the next call. Sleep
	// a bit longer than the 1s bump.
	time.Sleep(1100 * time.Millisecond)

	// After GC, the same jti should look fresh again.
	second, err := store.MarkSeen(ctx, "jti-expiring", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("post-GC MarkSeen: %v", err)
	}
	if !second {
		t.Fatal("after expiry-window passed, the same jti must accept again")
	}
}

func TestJTIReplayStore_PastExpiryGetsBumpedSoImmediateReplayCaught(t *testing.T) {
	store := newJTIReplayStoreForTest(t)
	ctx := context.Background()

	// Same expired entry — but within the bumped 1s window — must
	// still detect an immediate replay.
	first, err := store.MarkSeen(ctx, "jti-immediate", time.Now().Add(-1*time.Second))
	if err != nil {
		t.Fatalf("first MarkSeen: %v", err)
	}
	if !first {
		t.Fatal("first sighting must return true")
	}

	// Immediate replay (within the bumped 1s window).
	second, err := store.MarkSeen(ctx, "jti-immediate", time.Now().Add(-1*time.Second))
	if err != nil {
		t.Fatalf("second MarkSeen: %v", err)
	}
	if second {
		t.Fatal("immediate replay of expired jti must still be blocked (bumped window)")
	}
}

func TestJTIReplayStore_CrossInstanceSharing(t *testing.T) {
	// Multi-replica defense: a jti seen on one process must be
	// rejected when re-submitted to a second process pointed at the
	// same DB file.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_busy_timeout=5000"

	storeA, err := NewJTIReplayStore(dsn)
	if err != nil {
		t.Fatalf("instance A: %v", err)
	}
	defer storeA.Close()
	storeB, err := NewJTIReplayStore(dsn)
	if err != nil {
		t.Fatalf("instance B: %v", err)
	}
	defer storeB.Close()

	first, err := storeA.MarkSeen(context.Background(), "cross-jti", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("A.MarkSeen: %v", err)
	}
	if !first {
		t.Fatal("A first sighting must be true")
	}
	second, err := storeB.MarkSeen(context.Background(), "cross-jti", time.Now().Add(5*time.Minute))
	if err != nil {
		t.Fatalf("B.MarkSeen: %v", err)
	}
	if second {
		t.Fatal("B replay must be blocked — cross-replica defense is the whole point")
	}
}
