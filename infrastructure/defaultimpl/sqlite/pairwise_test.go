package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/shared/security"
)

func newPairwiseSubjectStoreForTest(t *testing.T) *PairwiseSubjectStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "pairwise.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	store, err := NewPairwiseSubjectStore(dsn)
	if err != nil {
		t.Fatalf("NewPairwiseSubjectStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestPairwiseSubjectStore_MapAndLookup(t *testing.T) {
	t.Parallel()
	store := newPairwiseSubjectStoreForTest(t)
	ctx := context.Background()

	if err := store.MapPairwise(ctx, "pairwise-abc", "alice"); err != nil {
		t.Fatalf("MapPairwise: %v", err)
	}
	local, err := store.LocalSubject(ctx, "pairwise-abc")
	if err != nil {
		t.Fatalf("LocalSubject: %v", err)
	}
	if local != "alice" {
		t.Fatalf("local sub: got %q want alice", local)
	}
}

func TestPairwiseSubjectStore_UnknownReturnsSentinel(t *testing.T) {
	t.Parallel()
	store := newPairwiseSubjectStoreForTest(t)
	_, err := store.LocalSubject(context.Background(), "never-mapped")
	if !errors.Is(err, security.ErrPairwiseUnknown) {
		t.Fatalf("got %v, want ErrPairwiseUnknown", err)
	}
}

func TestPairwiseSubjectStore_MapIsIdempotent(t *testing.T) {
	t.Parallel()
	store := newPairwiseSubjectStoreForTest(t)
	ctx := context.Background()

	for range 5 {
		if err := store.MapPairwise(ctx, "pairwise-abc", "alice"); err != nil {
			t.Fatalf("MapPairwise (repeat): %v", err)
		}
	}
	local, err := store.LocalSubject(ctx, "pairwise-abc")
	if err != nil {
		t.Fatalf("LocalSubject: %v", err)
	}
	if local != "alice" {
		t.Fatalf("local sub after repeated map: got %q want alice", local)
	}
}

func TestPairwiseSubjectStore_RejectsEmptySub(t *testing.T) {
	t.Parallel()
	store := newPairwiseSubjectStoreForTest(t)
	ctx := context.Background()

	if err := store.MapPairwise(ctx, "", "alice"); err == nil {
		t.Fatal("empty pairwise sub must error")
	}
	if err := store.MapPairwise(ctx, "pairwise-abc", ""); err == nil {
		t.Fatal("empty local sub must error")
	}
	// Empty pairwise lookup returns sentinel, not error from scan.
	_, err := store.LocalSubject(ctx, "")
	if !errors.Is(err, security.ErrPairwiseUnknown) {
		t.Fatalf("empty lookup: got %v want ErrPairwiseUnknown", err)
	}
}

func TestPairwiseSubjectStore_DifferentPairwisesMapToDifferentLocals(t *testing.T) {
	t.Parallel()
	store := newPairwiseSubjectStoreForTest(t)
	ctx := context.Background()

	pairs := []struct{ pw, local string }{
		{"pw-alice-rp1", "alice"},
		{"pw-alice-rp2", "alice"}, // same local, different sectors
		{"pw-bob-rp1", "bob"},
	}
	for _, p := range pairs {
		if err := store.MapPairwise(ctx, p.pw, p.local); err != nil {
			t.Fatalf("MapPairwise %q: %v", p.pw, err)
		}
	}
	for _, p := range pairs {
		got, err := store.LocalSubject(ctx, p.pw)
		if err != nil {
			t.Fatalf("LocalSubject %q: %v", p.pw, err)
		}
		if got != p.local {
			t.Fatalf("LocalSubject %q: got %q want %q", p.pw, got, p.local)
		}
	}
}

func TestPairwiseSubjectStore_CrossInstanceSharing(t *testing.T) {
	t.Parallel()
	// The whole multi-replica defense: a pairwise sub minted on
	// replica A is resolvable at /userinfo on replica B against the
	// same DB file.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"

	storeA, err := NewPairwiseSubjectStore(dsn)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	defer func() { _ = storeA.Close() }()
	storeB, err := NewPairwiseSubjectStore(dsn)
	if err != nil {
		t.Fatalf("B: %v", err)
	}
	defer func() { _ = storeB.Close() }()

	if err := storeA.MapPairwise(context.Background(), "shared-pw", "alice"); err != nil {
		t.Fatalf("A.MapPairwise: %v", err)
	}
	local, err := storeB.LocalSubject(context.Background(), "shared-pw")
	if err != nil {
		t.Fatalf("B.LocalSubject: %v", err)
	}
	if local != "alice" {
		t.Fatalf("cross-instance pairwise: got %q want alice", local)
	}
}
