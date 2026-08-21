package configaudit

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

func seedCanaryBaseline(t *testing.T, store CanaryStore) AppliedVersion {
	t.Helper()
	v, err := store.Apply(context.Background(), AppliedVersion{
		Actor: "baseline", Digest: "d1", Reason: "seed", Snapshot: map[string]any{"version": 1},
	})
	if err != nil {
		t.Fatalf("seed baseline: %v", err)
	}
	return v
}

func beginTestCanary(t *testing.T, store CanaryStore, deadline time.Time) CanaryState {
	t.Helper()
	now := time.Now().UTC()
	_, state, err := store.BeginCanary(context.Background(), AppliedVersion{
		Actor: "operator", Digest: "d2", Reason: "ticket-2", Snapshot: map[string]any{"version": 2},
	}, CanaryState{StartedAt: now, Deadline: deadline, Status: CanaryObserving})
	if err != nil {
		t.Fatalf("begin canary: %v", err)
	}
	return state
}

func TestCanaryController_HealthyWindowConfirms(t *testing.T) {
	store := NewMemoryStore(0)
	seedCanaryBaseline(t, store)
	sink := audit.NewMemorySink(8)
	c := NewCanaryController(store, []CanaryProbe{{Name: "db", Check: func(context.Context) CanaryHealth { return CanaryHealthy }}}, nil, audit.New(sink))
	state := beginTestCanary(t, store, time.Now().Add(-time.Second))
	c.observe(context.Background())
	got, err := store.Canary(context.Background())
	if err != nil || got.Status != CanaryConfirmed || got.ID != state.ID {
		t.Fatalf("healthy canary state = %+v, err=%v; want confirmed", got, err)
	}
	if events := sinkEventsForCanary(t, sink); len(events) != 1 || events[0].Type != audit.EventConfigCanaryConfirmed {
		t.Fatalf("confirmation audit = %+v", events)
	}
}

func TestCanaryController_UnhealthyRollsBackAndAudits(t *testing.T) {
	store := NewMemoryStore(0)
	baseline := seedCanaryBaseline(t, store)
	sink := audit.NewMemorySink(8)
	c := NewCanaryController(store, []CanaryProbe{{Name: "db", Check: func(context.Context) CanaryHealth { return CanaryUnhealthy }}}, nil, audit.New(sink))
	beginTestCanary(t, store, time.Now().Add(time.Minute))
	c.observe(context.Background())
	got, err := store.Applied(context.Background())
	if err != nil || got.Snapshot["version"] != baseline.Snapshot["version"] {
		t.Fatalf("rollback baseline = %+v, err=%v", got, err)
	}
	state, err := store.Canary(context.Background())
	if err != nil || state.Status != CanaryRolledBack {
		t.Fatalf("rollback state = %+v, err=%v", state, err)
	}
	if events := sinkEventsForCanary(t, sink); len(events) != 1 || events[0].Type != audit.EventConfigCanaryRolledBack {
		t.Fatalf("rollback audit = %+v", events)
	}
}

func TestCanaryStore_ConcurrentMutationIsRejected(t *testing.T) {
	store := NewMemoryStore(0)
	seedCanaryBaseline(t, store)
	beginTestCanary(t, store, time.Now().Add(time.Minute))
	if _, err := store.Apply(context.Background(), AppliedVersion{Snapshot: map[string]any{"version": 3}}); err != ErrCanaryInProgress {
		t.Fatalf("Apply during canary = %v, want ErrCanaryInProgress", err)
	}
	if _, err := store.Rollback(context.Background(), "operator", "manual"); err != ErrCanaryInProgress {
		t.Fatalf("Rollback during canary = %v, want ErrCanaryInProgress", err)
	}
}

func TestCanaryController_RestartFailsSafeToRollback(t *testing.T) {
	store := NewMemoryStore(0)
	baseline := seedCanaryBaseline(t, store)
	state := beginTestCanary(t, store, time.Now().Add(time.Minute))
	c := NewCanaryController(store, []CanaryProbe{{Name: "db", Check: func(context.Context) CanaryHealth { return CanaryHealthy }}}, nil, nil)
	c.recoverActive(context.Background())
	got, err := store.Applied(context.Background())
	if err != nil || got.Snapshot["version"] != baseline.Snapshot["version"] {
		t.Fatalf("restart recovery baseline = %+v, err=%v", got, err)
	}
	recovered, err := store.Canary(context.Background())
	if err != nil || recovered.ID != state.ID || recovered.Status != CanaryRolledBack {
		t.Fatalf("restart recovery state = %+v, err=%v", recovered, err)
	}
}

func sinkEventsForCanary(t *testing.T, sink *audit.MemorySink) []*audit.Event {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{Limit: 8})
	if err != nil {
		t.Fatalf("query canary audit: %v", err)
	}
	return events
}
