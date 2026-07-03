package degradation

import (
	"context"
	"sync"
	"testing"
)

func TestManager_DefaultsToNormal(t *testing.T) {
	if got := NewManager("").Mode(); got != ModeNormal {
		t.Fatalf("invalid initial mode should fall back to normal, got %q", got)
	}
	if got := NewManager("bogus").Mode(); got != ModeNormal {
		t.Fatalf("unknown initial mode should fall back to normal, got %q", got)
	}
	if got := NewManager(ModeMaintenance).Mode(); got != ModeMaintenance {
		t.Fatalf("valid initial mode not honored, got %q", got)
	}
}

func TestManager_SetModeFiresHookOnTransition(t *testing.T) {
	m := NewManager(ModeNormal)
	var gotFrom, gotTo Mode
	var gotReason string
	var calls int
	m.OnChange(func(_ context.Context, from, to Mode, reason string) {
		calls++
		gotFrom, gotTo, gotReason = from, to, reason
	})

	changed, err := m.SetMode(context.Background(), ModeReadOnly, "replica failover")
	if err != nil || !changed {
		t.Fatalf("SetMode(read_only) = (%v, %v), want (true, nil)", changed, err)
	}
	if m.Mode() != ModeReadOnly {
		t.Fatalf("mode not applied, got %q", m.Mode())
	}
	if calls != 1 || gotFrom != ModeNormal || gotTo != ModeReadOnly || gotReason != "replica failover" {
		t.Fatalf("hook got (%d, %q->%q, %q)", calls, gotFrom, gotTo, gotReason)
	}
}

func TestManager_SetModeNoopDoesNotFireHook(t *testing.T) {
	m := NewManager(ModeReadOnly)
	var calls int
	m.OnChange(func(_ context.Context, _, _ Mode, _ string) { calls++ })

	changed, err := m.SetMode(context.Background(), ModeReadOnly, "same")
	if err != nil || changed {
		t.Fatalf("no-op SetMode = (%v, %v), want (false, nil)", changed, err)
	}
	if calls != 0 {
		t.Fatalf("hook fired on no-op transition (%d calls)", calls)
	}
}

func TestManager_SetModeRejectsInvalid(t *testing.T) {
	m := NewManager(ModeNormal)
	changed, err := m.SetMode(context.Background(), "sideways", "")
	if err != ErrInvalidMode || changed {
		t.Fatalf("SetMode(invalid) = (%v, %v), want (false, ErrInvalidMode)", changed, err)
	}
	if m.Mode() != ModeNormal {
		t.Fatalf("invalid SetMode mutated the mode to %q", m.Mode())
	}
}

// TestManager_ConcurrentReadWrite exercises the lock-free read path against
// concurrent writers; run with -race to prove the atomic swap is data-race free.
func TestManager_ConcurrentReadWrite(t *testing.T) {
	m := NewManager(ModeNormal)
	modes := []Mode{ModeNormal, ModeReadOnly, ModeAuthOnly, ModeLocalOnly, ModeMaintenance}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = m.SetMode(context.Background(), modes[(seed+j)%len(modes)], "churn")
				if !m.Mode().Valid() {
					t.Errorf("observed invalid mode during churn")
					return
				}
			}
		}(i)
	}
	wg.Wait()
}
