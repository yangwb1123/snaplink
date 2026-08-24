package configaudit

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryStore_RollbackIfCurrentRejectsStaleVersion(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(0)
	first, err := store.Apply(ctx, AppliedVersion{Digest: "d1", Snapshot: map[string]any{"v": 1}})
	if err != nil {
		t.Fatalf("Apply first: %v", err)
	}
	second, err := store.Apply(ctx, AppliedVersion{Digest: "d2", Snapshot: map[string]any{"v": 2}})
	if err != nil {
		t.Fatalf("Apply second: %v", err)
	}
	if _, err := store.RollbackIfCurrent(ctx, first.ID, "operator", "stale"); !errors.Is(err, ErrRollbackConflict) {
		t.Fatalf("stale rollback error = %v, want ErrRollbackConflict", err)
	}
	current, err := store.Applied(ctx)
	if err != nil || current.ID != second.ID {
		t.Fatalf("stale rollback changed current baseline: %+v, err=%v", current, err)
	}
	rolled, err := store.RollbackIfCurrent(ctx, second.ID, "operator", "approved")
	if err != nil {
		t.Fatalf("current rollback: %v", err)
	}
	if rolled.Snapshot["v"] != float64(1) && rolled.Snapshot["v"] != 1 {
		t.Fatalf("rollback snapshot = %+v, want first snapshot", rolled.Snapshot)
	}
}
