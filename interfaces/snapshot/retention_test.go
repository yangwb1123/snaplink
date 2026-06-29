package snapshot_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/storageinline"
)

func seedInlineStorage(t *testing.T, names ...string) snapshot.Storage {
	t.Helper()
	s := inline.New()
	for _, name := range names {
		if err := s.Put(context.Background(), name, []byte("dummy")); err != nil {
			t.Fatalf("Put %q: %v", name, err)
		}
	}
	return s
}

func TestPruneOldest_NoOpWhenUnderKeepThreshold(t *testing.T) {
	t.Parallel()
	s := seedInlineStorage(t,
		"snap_2026-01-01T00-00-00Z_aaa",
		"snap_2026-01-02T00-00-00Z_bbb",
	)
	deleted, err := snapshot.PruneOldest(context.Background(), s, 5)
	if err != nil {
		t.Fatalf("PruneOldest: %v", err)
	}
	if len(deleted) != 0 {
		t.Errorf("deleted = %v, want empty", deleted)
	}
}

func TestPruneOldest_KeepsLastN(t *testing.T) {
	t.Parallel()
	// Five snapshots, keep 2 — oldest 3 get deleted.
	s := seedInlineStorage(t,
		"snap_2026-01-01T00-00-00Z_aaa",
		"snap_2026-01-02T00-00-00Z_bbb",
		"snap_2026-01-03T00-00-00Z_ccc",
		"snap_2026-01-04T00-00-00Z_ddd",
		"snap_2026-01-05T00-00-00Z_eee",
	)
	deleted, err := snapshot.PruneOldest(context.Background(), s, 2)
	if err != nil {
		t.Fatalf("PruneOldest: %v", err)
	}
	if len(deleted) != 3 {
		t.Fatalf("deleted %d, want 3 (deleted=%v)", len(deleted), deleted)
	}
	// The two newest must remain; the three oldest must be gone.
	remaining, _ := s.List(context.Background())
	if len(remaining) != 2 {
		t.Errorf("remaining = %v, want 2", remaining)
	}
	for _, n := range remaining {
		if !strings.HasPrefix(n, "snap_2026-01-04") && !strings.HasPrefix(n, "snap_2026-01-05") {
			t.Errorf("survivor %q not in expected last-2 set", n)
		}
	}
}

func TestPruneOldest_KeepZeroDeletesEverything(t *testing.T) {
	t.Parallel()
	s := seedInlineStorage(t,
		"snap_2026-01-01T00-00-00Z_aaa",
		"snap_2026-01-02T00-00-00Z_bbb",
	)
	deleted, err := snapshot.PruneOldest(context.Background(), s, 0)
	if err != nil {
		t.Fatalf("PruneOldest: %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %v, want both", deleted)
	}
	remaining, _ := s.List(context.Background())
	if len(remaining) != 0 {
		t.Errorf("remaining = %v, want empty", remaining)
	}
}

func TestPruneOldest_IgnoresNonSnapshotFiles(t *testing.T) {
	t.Parallel()
	// Operator notes / README in the snapshot dir mustn't get
	// deleted — the prefix filter is the safety net.
	s := seedInlineStorage(t,
		"README.txt",
		"operator-notes.md",
		"snap_2026-01-01T00-00-00Z_aaa",
		"snap_2026-01-02T00-00-00Z_bbb",
		"snap_2026-01-03T00-00-00Z_ccc",
	)
	deleted, err := snapshot.PruneOldest(context.Background(), s, 1)
	if err != nil {
		t.Fatalf("PruneOldest: %v", err)
	}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %v, want 2 (only the two oldest snapshots)", deleted)
	}
	for _, n := range deleted {
		if !strings.HasPrefix(n, "snap_") {
			t.Errorf("non-snapshot %q was deleted!", n)
		}
	}
	remaining, _ := s.List(context.Background())
	gotReadme, gotNotes := false, false
	for _, n := range remaining {
		if n == "README.txt" {
			gotReadme = true
		}
		if n == "operator-notes.md" {
			gotNotes = true
		}
	}
	if !gotReadme || !gotNotes {
		t.Errorf("non-snapshot files were deleted: remaining=%v", remaining)
	}
}

func TestPruneOldest_NilStorageRejected(t *testing.T) {
	t.Parallel()
	_, err := snapshot.PruneOldest(context.Background(), nil, 5)
	if err == nil {
		t.Fatal("want error for nil storage")
	}
}

func TestPruneOldest_RespectsContextCancel(t *testing.T) {
	t.Parallel()
	s := seedInlineStorage(t,
		"snap_2026-01-01T00-00-00Z_aaa",
		"snap_2026-01-02T00-00-00Z_bbb",
		"snap_2026-01-03T00-00-00Z_ccc",
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := snapshot.PruneOldest(ctx, s, 0)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

func TestPruneOldest_LexicalOrderingPreservesChronology(t *testing.T) {
	t.Parallel()
	// SnapshotID format snap_<RFC3339-with-dashes>_<rand> is
	// designed so lexical sort matches chronological order. This
	// test pins that invariant against future name-generator
	// changes that would silently break retention.
	s := seedInlineStorage(t,
		"snap_2025-12-31T23-59-59Z_aaa",
		"snap_2026-01-01T00-00-01Z_bbb",
		"snap_2026-01-01T00-00-02Z_ccc",
	)
	deleted, err := snapshot.PruneOldest(context.Background(), s, 1)
	if err != nil {
		t.Fatalf("PruneOldest: %v", err)
	}
	// The 2025 one should be the first victim.
	wantDeleted := []string{"snap_2025-12-31T23-59-59Z_aaa", "snap_2026-01-01T00-00-01Z_bbb"}
	if len(deleted) != 2 {
		t.Fatalf("deleted = %v, want %v", deleted, wantDeleted)
	}
	for i, w := range wantDeleted {
		if deleted[i] != w {
			t.Errorf("deleted[%d] = %q, want %q", i, deleted[i], w)
		}
	}
}
