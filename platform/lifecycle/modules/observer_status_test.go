package modules

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestTransitionObserverReceivesBoundedLifecycleFacts(t *testing.T) {
	recorder := &transitionRecorder{events: make(chan TransitionEvent, 32)}
	manager, err := New([]Definition{{ID: "module-a", Factory: newFakeFactory()}}, Options{
		TransitionObserver: recorder,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activateForTest(t, manager, "module-a", []byte(`{"client_secret":"must-not-escape"}`))
	disableAndWait(t, manager, "module-a")
	events := recorder.until(t, TransitionRetired)
	assertTransitionTypes(t, events, TransitionActivated, TransitionDisableStarted, TransitionRetired)
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("Marshal(events) error = %v", err)
	}
	if strings.Contains(string(encoded), "must-not-escape") || strings.Contains(string(encoded), "client_secret") {
		t.Fatalf("observer events leaked config: %s", encoded)
	}
	for _, event := range events {
		if event.ModuleID != "module-a" || event.Generation == 0 || event.OccurredAt.IsZero() {
			t.Fatalf("invalid bounded event = %+v", event)
		}
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestBlockingTransitionObserverCannotBlockReplacement(t *testing.T) {
	observer := newBlockingObserver()
	manager, err := New([]Definition{{ID: "module-a", Factory: newFakeFactory()}}, Options{
		TransitionObserver: observer, ObserverQueueSize: 1, ObserverTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activateForTest(t, manager, "module-a", nil)
	<-observer.entered
	started := time.Now()
	activation := activateForTest(t, manager, "module-a", nil)
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("replacement blocked on observer for %v", elapsed)
	}
	waitForObserverDrop(t, manager)
	close(observer.release)
	if err := activation.Retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestWaitObserverWaitsForAcceptedCallbacks(t *testing.T) {
	observer := newBlockingObserver()
	manager, err := New([]Definition{{ID: "module-a", Factory: newFakeFactory()}}, Options{
		TransitionObserver: observer,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activateForTest(t, manager, "module-a", nil)
	<-observer.entered
	done := make(chan error, 1)
	go func() { done <- manager.WaitObserver(context.Background()) }()
	select {
	case err := <-done:
		t.Fatalf("WaitObserver returned while callback was blocked: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(observer.release)
	if err := <-done; err != nil {
		t.Fatalf("WaitObserver() error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestObserverFailureIsFailOpenAndObservable(t *testing.T) {
	observerErr := errors.New("observer unavailable")
	var bounded atomic.Bool
	observer := TransitionObserverFunc(func(ctx context.Context, _ TransitionEvent) error {
		_, ok := ctx.Deadline()
		bounded.Store(ok)
		return observerErr
	})
	manager, err := New([]Definition{{ID: "module-a", Factory: newFakeFactory()}}, Options{
		TransitionObserver: observer, ObserverTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activateForTest(t, manager, "module-a", nil)
	waitForObserverFailure(t, manager)
	if !bounded.Load() {
		t.Fatal("observer callback had no deadline")
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestStatusIncludesRetiringGenerationUntilDrainCompletes(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	first := activateForTest(t, manager, "module-a", nil)
	lease, err := manager.Acquire("module-a", LeaseRequest)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	second := activateForTest(t, manager, "module-a", nil)
	status := moduleStatus(t, manager, "module-a")
	if status.Generation != second.Generation || status.State != StateActive {
		t.Fatalf("current status = %+v", status)
	}
	if len(status.Retiring) != 1 || status.Retiring[0].Generation != first.Generation {
		t.Fatalf("retiring status = %+v", status.Retiring)
	}
	if status.Retiring[0].Leases[LeaseRequest] != 1 {
		t.Fatalf("retiring leases = %+v", status.Retiring[0].Leases)
	}
	lease.Release()
	if err := second.Retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
	if retiring := moduleStatus(t, manager, "module-a").Retiring; len(retiring) != 0 {
		t.Fatalf("retiring generations after Stop = %+v", retiring)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestConcurrentReplacementDoesNotReportFalseDraining(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	activateForTest(t, manager, "module-a", nil)
	ctx, cancel := context.WithCancel(context.Background())
	var failures atomic.Int64
	var workers sync.WaitGroup
	for index := 0; index < 16; index++ {
		workers.Add(1)
		go strictAcquisitionWorker(ctx, manager, &failures, &workers)
	}
	retirements := make([]*Retirement, 0, 50)
	for generation := 0; generation < 50; generation++ {
		activation := activateForTest(t, manager, "module-a", []byte{byte(generation)})
		retirements = append(retirements, activation.Retirement)
	}
	cancel()
	workers.Wait()
	for _, retirement := range retirements {
		if err := retirement.Wait(context.Background()); err != nil {
			t.Fatalf("retirement error = %v", err)
		}
	}
	if failures.Load() != 0 {
		t.Fatalf("acquisition errors while slot stayed active = %d", failures.Load())
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func strictAcquisitionWorker(
	ctx context.Context, manager *Manager, failures *atomic.Int64, workers *sync.WaitGroup,
) {
	defer workers.Done()
	for ctx.Err() == nil {
		lease, err := manager.Acquire("module-a", LeaseRequest)
		if err != nil {
			failures.Add(1)
			continue
		}
		lease.Release()
	}
}

type transitionRecorder struct {
	events chan TransitionEvent
}

func (r *transitionRecorder) Observe(_ context.Context, event TransitionEvent) error {
	r.events <- event
	return nil
}

func (r *transitionRecorder) until(t *testing.T, final TransitionEventType) []TransitionEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var result []TransitionEvent
	for {
		select {
		case event := <-r.events:
			result = append(result, event)
			if event.Type == final {
				return result
			}
		case <-ctx.Done():
			t.Fatalf("observer did not receive %q; events=%+v", final, result)
		}
	}
}

func assertTransitionTypes(t *testing.T, events []TransitionEvent, expected ...TransitionEventType) {
	t.Helper()
	seen := make(map[TransitionEventType]bool, len(events))
	for _, event := range events {
		seen[event.Type] = true
	}
	for _, eventType := range expected {
		if !seen[eventType] {
			t.Fatalf("missing transition %q in %+v", eventType, events)
		}
	}
}

type blockingObserver struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingObserver() *blockingObserver {
	return &blockingObserver{entered: make(chan struct{}), release: make(chan struct{})}
}

func (o *blockingObserver) Observe(context.Context, TransitionEvent) error {
	o.once.Do(func() { close(o.entered) })
	<-o.release
	return nil
}

func waitForObserverDrop(t *testing.T, manager *Manager) {
	t.Helper()
	waitForObserverStatus(t, manager, func(status ObserverStatus) bool { return status.Dropped > 0 })
}

func waitForObserverFailure(t *testing.T, manager *Manager) {
	t.Helper()
	waitForObserverStatus(t, manager, func(status ObserverStatus) bool { return status.Failures > 0 })
}

func waitForObserverStatus(t *testing.T, manager *Manager, ready func(ObserverStatus) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ready(manager.ObserverStatus()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("observer status did not converge: %+v", manager.ObserverStatus())
}

func moduleStatus(t *testing.T, manager *Manager, moduleID string) Status {
	t.Helper()
	for _, status := range manager.Status() {
		if status.ModuleID == moduleID {
			return status
		}
	}
	t.Fatalf("status for %q not found", moduleID)
	return Status{}
}
