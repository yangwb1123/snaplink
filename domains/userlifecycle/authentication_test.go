package userlifecycle_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/domains/userlifecycle/memory"
)

type projectedStateStore struct {
	fullReads int
}

func (s *projectedStateStore) Get(context.Context, string) (userlifecycle.Record, error) {
	s.fullReads++
	return userlifecycle.Record{}, errors.New("full record read should not run")
}

func (*projectedStateStore) GetState(context.Context, string) (userlifecycle.State, error) {
	return userlifecycle.StateActive, nil
}

func (*projectedStateStore) Append(context.Context, string, userlifecycle.Transition) error {
	return nil
}

func (*projectedStateStore) ListByState(context.Context, userlifecycle.State) ([]string, error) {
	return nil, nil
}

func TestAllowsAuthenticationOnlyActive(t *testing.T) {
	t.Parallel()
	states := []userlifecycle.State{
		userlifecycle.StateNone, userlifecycle.StateInvited,
		userlifecycle.StateSuspended, userlifecycle.StateInactive,
		userlifecycle.StateArchived, userlifecycle.StatePurged,
	}
	if !userlifecycle.AllowsAuthentication(userlifecycle.StateActive) {
		t.Fatal("active user was denied")
	}
	for _, state := range states {
		if userlifecycle.AllowsAuthentication(state) {
			t.Errorf("state %q was allowed", state)
		}
	}
}

func TestReadStatePreservesProjectionThroughObserver(t *testing.T) {
	t.Parallel()
	base := &projectedStateStore{}
	store := userlifecycle.ObserveTransitions(base, func(context.Context, string, userlifecycle.Transition) {})
	state, err := userlifecycle.ReadState(context.Background(), store, "u1")
	if err != nil || state != userlifecycle.StateActive {
		t.Fatalf("ReadState = (%q, %v), want active", state, err)
	}
	if base.fullReads != 0 {
		t.Fatalf("full record reads = %d, want zero", base.fullReads)
	}
}

func TestObserveTransitionsRunsAfterCommit(t *testing.T) {
	t.Parallel()
	base := memory.New()
	var observed userlifecycle.Transition
	store := userlifecycle.ObserveTransitions(base, func(ctx context.Context, userID string, transition userlifecycle.Transition) {
		if userID != "user-1" {
			t.Errorf("observer user = %q", userID)
		}
		record, err := base.Get(ctx, userID)
		if err != nil || record.State != transition.To {
			t.Errorf("observer ran before commit: record=%+v err=%v", record, err)
		}
		observed = transition
	})
	transition := userlifecycle.NewTransition(
		userlifecycle.StateActive, userlifecycle.StateSuspended, "hold", "admin", time.Now(),
	)
	if err := store.Append(context.Background(), "user-1", transition); err != nil {
		t.Fatal(err)
	}
	if observed.To != userlifecycle.StateSuspended {
		t.Fatalf("observed transition = %+v", observed)
	}
}

func TestLifecycleDispatchDetachesCanceledRequest(t *testing.T) {
	t.Parallel()
	bus := userlifecycle.NewLifecycleEventBus()
	called := false
	bus.OnUserSuspended(func(ctx context.Context, _ string) error {
		called = true
		if err := ctx.Err(); err != nil {
			t.Errorf("reaction inherited canceled request: %v", err)
		}
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	bus.Dispatch(ctx, "user-1", userlifecycle.StateSuspended)
	if !called {
		t.Fatal("synchronous reaction was not called")
	}
}
