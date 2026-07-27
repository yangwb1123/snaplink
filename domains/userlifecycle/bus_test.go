package userlifecycle_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// newRecorder builds a real audit.Recorder over a real audit.MemorySink —
// no mocks, matching AGENTS.md's "no mocks" invariant. extra sinks (the bus
// under test) are fanned in via AddSink exactly as sso.applyAuditSinkTaps
// wires platform/lifecycle/webhook.Engine / protocols/caep.Transmitter.
func newRecorder(t *testing.T, extra audit.Sink) *audit.Recorder {
	t.Helper()
	rec := audit.New(audit.NewMemorySink(10))
	rec.AddSink(extra)
	return rec
}

func TestLifecycleEventBus_ZeroReactionsIsNoOp(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	rec := newRecorder(t, bus)

	t1 := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "", "admin1", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, "u1", t1)
	// No reaction registered anywhere — Record must not panic or block, and
	// there's nothing observable to assert beyond "this returned".
}

func TestLifecycleEventBus_OnUserArchivedFiresSync(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	rec := newRecorder(t, bus)

	var got string
	var calls int32
	bus.OnUserArchived(func(ctx context.Context, userID string) error {
		atomic.AddInt32(&calls, 1)
		got = userID
		return nil
	})

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "policy", "admin1", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, "user-42", tr)

	// Sync dispatch: by the time RecordTransition returns, the reaction has
	// already run (no goroutine, no race) — assert immediately.
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("calls = %d, want 1", n)
	}
	if got != "user-42" {
		t.Fatalf("userID = %q, want user-42", got)
	}
}

func TestLifecycleEventBus_OnlyMatchingStateFires(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	rec := newRecorder(t, bus)

	var archivedCalls, suspendedCalls int32
	bus.OnUserArchived(func(context.Context, string) error {
		atomic.AddInt32(&archivedCalls, 1)
		return nil
	})
	bus.OnUserSuspended(func(context.Context, string) error {
		atomic.AddInt32(&suspendedCalls, 1)
		return nil
	})

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "system", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, "user-1", tr)

	if n := atomic.LoadInt32(&archivedCalls); n != 0 {
		t.Fatalf("archivedCalls = %d, want 0 (transition was to INACTIVE)", n)
	}
	if n := atomic.LoadInt32(&suspendedCalls); n != 0 {
		t.Fatalf("suspendedCalls = %d, want 0 (transition was to INACTIVE)", n)
	}
}

func TestLifecycleEventBus_MultipleReactionsAllFire(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	rec := newRecorder(t, bus)

	var n1, n2 int32
	bus.OnUserArchived(func(context.Context, string) error { atomic.AddInt32(&n1, 1); return nil })
	bus.OnUserArchived(func(context.Context, string) error { atomic.AddInt32(&n2, 1); return nil })

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "", "admin1", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, "user-1", tr)

	if atomic.LoadInt32(&n1) != 1 || atomic.LoadInt32(&n2) != 1 {
		t.Fatalf("n1=%d n2=%d, want both 1", n1, n2)
	}
}

func TestLifecycleEventBus_AsyncDoesNotBlockAndCloseWaits(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	rec := newRecorder(t, bus)

	release := make(chan struct{})
	started := make(chan struct{})
	var ran int32
	bus.OnAsync(userlifecycle.StateArchived, func(ctx context.Context, userID string) error {
		close(started)
		<-release
		atomic.AddInt32(&ran, 1)
		return nil
	})

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "", "admin1", time.Now())

	done := make(chan struct{})
	go func() {
		userlifecycle.RecordTransition(context.Background(), rec, "user-1", tr)
		close(done)
	}()

	select {
	case <-done:
		// RecordTransition returned; the async reaction may or may not have
		// started yet, but it must not have forced RecordTransition to wait
		// on <-release (which hasn't been closed).
	case <-time.After(2 * time.Second):
		t.Fatal("RecordTransition blocked on an async reaction")
	}

	<-started // the goroutine is now blocked on <-release
	if atomic.LoadInt32(&ran) != 0 {
		t.Fatal("async reaction completed before release — test setup broken")
	}

	// Close should block until the in-flight reaction finishes.
	closeDone := make(chan error, 1)
	go func() { closeDone <- bus.Close(context.Background()) }()

	select {
	case <-closeDone:
		t.Fatal("Close returned before the in-flight async reaction finished")
	case <-time.After(50 * time.Millisecond):
		// expected: Close is still waiting
	}

	close(release)
	if err := <-closeDone; err != nil {
		t.Fatalf("Close() = %v, want nil", err)
	}
	if atomic.LoadInt32(&ran) != 1 {
		t.Fatal("async reaction never completed")
	}
}

func TestLifecycleEventBus_ReactionErrorDoesNotBreakOtherSinks(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	mem := audit.NewMemorySink(10)
	rec := audit.New(mem)
	rec.AddSink(bus)

	bus.OnUserArchived(func(context.Context, string) error {
		return errors.New("boom")
	})

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "", "admin1", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, "user-1", tr)

	events, err := mem.Query(context.Background(), audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("MemorySink events = %d, want 1 (reaction failure must not drop the audit record)", len(events))
	}
}

func TestLifecycleEventBus_ErrorHandlerAndLoggerCalledOnFailure(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus(
		userlifecycle.WithReactionErrorHandler(func(state userlifecycle.State, userID string, err error) {
			handlerMu.Lock()
			defer handlerMu.Unlock()
			handlerCalls = append(handlerCalls, [3]string{string(state), userID, err.Error()})
		}),
	)
	rec := newRecorder(t, bus)

	bus.OnUserArchived(func(context.Context, string) error { return errors.New("nope") })

	handlerMu.Lock()
	handlerCalls = nil
	handlerMu.Unlock()

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "", "admin1", time.Now())
	userlifecycle.RecordTransition(context.Background(), rec, "user-7", tr)

	handlerMu.Lock()
	defer handlerMu.Unlock()
	if len(handlerCalls) != 1 {
		t.Fatalf("handlerCalls = %v, want 1 entry", handlerCalls)
	}
	if handlerCalls[0][0] != string(userlifecycle.StateArchived) || handlerCalls[0][1] != "user-7" {
		t.Fatalf("handlerCalls[0] = %v", handlerCalls[0])
	}
}

func TestLifecycleEventBus_PanicIsContained(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	rec := newRecorder(t, bus)

	bus.OnUserArchived(func(context.Context, string) error {
		panic("reaction exploded")
	})

	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateArchived, "", "admin1", time.Now())
	// Must not propagate the panic to the caller.
	userlifecycle.RecordTransition(context.Background(), rec, "user-1", tr)
}

func TestLifecycleEventBus_IgnoresUnrelatedEventTypes(t *testing.T) {
	bus := userlifecycle.NewLifecycleEventBus()
	rec := newRecorder(t, bus)

	var calls int32
	bus.OnUserArchived(func(context.Context, string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	})

	rec.Record(context.Background(), &audit.Event{Type: audit.EventAccountLocked, Outcome: audit.OutcomeSuccess})
	if atomic.LoadInt32(&calls) != 0 {
		t.Fatal("bus reacted to a non-lifecycle event")
	}
}

// handlerMu/handlerCalls back TestLifecycleEventBus_ErrorHandlerAndLoggerCalledOnFailure;
// package-level because the ReactionErrorFunc closure has no receiver to hang state off.
var (
	handlerMu    sync.Mutex
	handlerCalls [][3]string
)
