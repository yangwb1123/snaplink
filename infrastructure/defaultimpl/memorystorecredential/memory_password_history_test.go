package memorystorecredential

import (
	"context"
	"testing"
)

func TestMemoryPasswordHistoryStore_RecordThenCheckHistory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMemoryPasswordHistoryStore(3)

	if reused, err := s.CheckHistory(ctx, "alice", "first-password"); err != nil || reused {
		t.Fatalf("CheckHistory on empty ring = (%v, %v), want (false, nil)", reused, err)
	}
	if err := s.Record(ctx, "alice", "first-password"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	reused, err := s.CheckHistory(ctx, "alice", "first-password")
	if err != nil {
		t.Fatalf("CheckHistory: %v", err)
	}
	if !reused {
		t.Error("CheckHistory = false, want true for a previously-recorded password")
	}
	if reused, err := s.CheckHistory(ctx, "alice", "never-used"); err != nil || reused {
		t.Errorf("CheckHistory for a fresh password = (%v, %v), want (false, nil)", reused, err)
	}
}

func TestMemoryPasswordHistoryStore_EvictsOldestBeyondMax(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMemoryPasswordHistoryStore(2)

	for _, pw := range []string{"pw-1", "pw-2", "pw-3"} {
		if err := s.Record(ctx, "alice", pw); err != nil {
			t.Fatalf("Record(%q): %v", pw, err)
		}
	}
	// Ring holds only the last 2 — the oldest ("pw-1") must have been evicted.
	if reused, _ := s.CheckHistory(ctx, "alice", "pw-1"); reused {
		t.Error("pw-1 should have been evicted from a max-2 ring")
	}
	if reused, err := s.CheckHistory(ctx, "alice", "pw-2"); err != nil || !reused {
		t.Errorf("pw-2 should still be in history, got (%v, %v)", reused, err)
	}
	if reused, err := s.CheckHistory(ctx, "alice", "pw-3"); err != nil || !reused {
		t.Errorf("pw-3 should still be in history, got (%v, %v)", reused, err)
	}
}

func TestMemoryPasswordHistoryStore_MaxZeroIsNoOp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMemoryPasswordHistoryStore(0)

	if err := s.Record(ctx, "alice", "any-password"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if reused, err := s.CheckHistory(ctx, "alice", "any-password"); err != nil || reused {
		t.Errorf("max<=0 must disable history entirely, got (%v, %v)", reused, err)
	}
}

func TestMemoryPasswordHistoryStore_PerUserIsolation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMemoryPasswordHistoryStore(3)

	if err := s.Record(ctx, "alice", "shared-password"); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if reused, err := s.CheckHistory(ctx, "bob", "shared-password"); err != nil || reused {
		t.Errorf("bob must not see alice's history, got (%v, %v)", reused, err)
	}
}
