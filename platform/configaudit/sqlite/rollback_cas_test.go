package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/platform/configaudit"
)

func TestStore_RollbackIfCurrentRejectsStaleVersion(t *testing.T) {
	ctx := context.Background()
	store := newTestStore(t)
	first, err := store.Apply(ctx, configaudit.AppliedVersion{Digest: "d1", Snapshot: map[string]any{"v": 1}})
	if err != nil {
		t.Fatalf("Apply first: %v", err)
	}
	second, err := store.Apply(ctx, configaudit.AppliedVersion{Digest: "d2", Snapshot: map[string]any{"v": 2}})
	if err != nil {
		t.Fatalf("Apply second: %v", err)
	}
	if _, err := store.RollbackIfCurrent(ctx, first.ID, "operator", "stale"); !errors.Is(err, configaudit.ErrRollbackConflict) {
		t.Fatalf("stale rollback error = %v, want ErrRollbackConflict", err)
	}
	current, err := store.Applied(ctx)
	if err != nil || current.ID != second.ID {
		t.Fatalf("stale rollback changed current baseline: %+v, err=%v", current, err)
	}
}
