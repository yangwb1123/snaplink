package auditgovernance

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
)

func TestManagedRelayReplacementDrainsInflightGeneration(t *testing.T) {
	oldStore := newManagedRelayStore(true)
	newStore := newManagedRelayStore(false)
	factory := ManagedRelayFactory{Build: relayGenerationBuilder(t, oldStore, newStore)}
	manager, err := modules.New([]modules.Definition{{ID: "audit-relay", Factory: factory}}, modules.Options{
		DrainTimeout: time.Second, LifecycleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagedRelayManager(t, manager)
	if _, err := manager.Activate(context.Background(), "audit-relay", []byte(`{"enabled":true}`)); err != nil {
		t.Fatal(err)
	}
	waitForManagedClaim(t, oldStore.entered)
	replacement, err := manager.Activate(context.Background(), "audit-relay", []byte(`{"enabled":true,"revision":2}`))
	if err != nil {
		t.Fatal(err)
	}
	assertRetirementPending(t, replacement.Retirement)
	close(oldStore.release)
	waitForManagedRetirement(t, replacement.Retirement)
	waitForManagedClaim(t, newStore.entered)
}

func TestManagedRelayDisableStopsNewClaims(t *testing.T) {
	store := newManagedRelayStore(false)
	factory := ManagedRelayFactory{Build: relayGenerationBuilder(t, store)}
	manager, err := modules.New([]modules.Definition{{ID: "audit-relay", Factory: factory}}, modules.Options{
		DrainTimeout: time.Second, LifecycleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(context.Background(), "audit-relay", nil); err != nil {
		t.Fatal(err)
	}
	waitForManagedClaim(t, store.entered)
	retirement, err := manager.Disable("audit-relay")
	if err != nil {
		t.Fatal(err)
	}
	waitForManagedRetirement(t, retirement)
	before := store.claimCount()
	time.Sleep(20 * time.Millisecond)
	if after := store.claimCount(); after != before {
		t.Fatalf("claims after retirement = %d, want %d", after, before)
	}
	closeManagedRelayManager(t, manager)
}

func TestManagedRelayFactoryRejectsDuplicateNames(t *testing.T) {
	store := newManagedRelayStore(false)
	factory := ManagedRelayFactory{Build: func(context.Context, []byte, uint64) ([]ManagedRelay, error) {
		relay := newManagedRelayForTest(t, store, "owner")
		return []ManagedRelay{{Name: "commerce", Relay: relay}, {Name: "commerce", Relay: relay}}, nil
	}}
	manager, err := modules.New([]modules.Definition{{ID: "audit-relay", Factory: factory}}, modules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Activate(context.Background(), "audit-relay", nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Activate() error = %v, want %v", err, ErrInvalidConfig)
	}
	closeManagedRelayManager(t, manager)
}

func relayGenerationBuilder(
	t *testing.T, stores ...*managedRelayStore,
) ManagedRelayBuilder {
	t.Helper()
	return func(_ context.Context, _ []byte, generation uint64) ([]ManagedRelay, error) {
		index := int(generation - 1)
		if index < 0 || index >= len(stores) {
			return nil, fmt.Errorf("unexpected generation %d", generation)
		}
		relay := newManagedRelayForTest(t, stores[index], fmt.Sprintf("owner-%d", generation))
		return []ManagedRelay{{
			Name: "commerce", Relay: relay, IdlePause: time.Millisecond,
			AuthPause: time.Millisecond, ErrorPause: time.Millisecond,
		}}, nil
	}
}

func newManagedRelayForTest(t *testing.T, store commerce.OutboxStore, owner string) *Relay {
	t.Helper()
	relay, err := NewRelay(store, managedRelayClient{}, RelayConfig{Owner: owner})
	if err != nil {
		t.Fatal(err)
	}
	return relay
}

func waitForManagedClaim(t *testing.T, entered <-chan struct{}) {
	t.Helper()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("relay did not claim")
	}
}

func assertRetirementPending(t *testing.T, retirement *modules.Retirement) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := retirement.Wait(ctx); err != context.DeadlineExceeded {
		t.Fatalf("retirement error = %v, want deadline", err)
	}
}

func waitForManagedRetirement(t *testing.T, retirement *modules.Retirement) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := retirement.Wait(ctx); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
}

func closeManagedRelayManager(t *testing.T, manager *modules.Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

type managedRelayClient struct{}

func (managedRelayClient) Publish(context.Context, *commerce.OutboxEvent) (Receipt, error) {
	return Receipt{}, nil
}

type managedRelayStore struct {
	mu      sync.Mutex
	claims  int
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newManagedRelayStore(block bool) *managedRelayStore {
	store := &managedRelayStore{entered: make(chan struct{}, 1)}
	if block {
		store.release = make(chan struct{})
	}
	return store
}

func (s *managedRelayStore) ClaimOutbox(
	ctx context.Context, _ string, _ time.Time, _ time.Duration, _ int,
) ([]*commerce.OutboxEvent, error) {
	s.mu.Lock()
	s.claims++
	s.mu.Unlock()
	s.once.Do(func() { s.entered <- struct{}{} })
	if s.release != nil {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-s.release:
		}
	}
	return nil, nil
}

func (s *managedRelayStore) claimCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.claims
}

func (*managedRelayStore) CompleteOutbox(context.Context, string, string, time.Time) error {
	return nil
}

func (*managedRelayStore) FailOutbox(
	context.Context, string, string, string, time.Time, time.Time, int,
) error {
	return nil
}

func (*managedRelayStore) QuarantineOutbox(
	context.Context, string, string, string, time.Time,
) error {
	return nil
}

func (*managedRelayStore) ListDeadOutbox(context.Context, int) ([]*commerce.OutboxEvent, error) {
	return nil, nil
}

func (*managedRelayStore) ReplayOutbox(context.Context, string, time.Time) error { return nil }
