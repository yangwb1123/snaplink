package modules

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeInstance struct {
	generation uint64
	readyErr   error
	mu         sync.Mutex
	events     []string
	stopped    atomic.Bool
}

func (i *fakeInstance) Start(context.Context) error {
	i.record("start")
	return nil
}

func (i *fakeInstance) Ready(context.Context) error {
	i.record("ready")
	return i.readyErr
}

func (i *fakeInstance) Quiesce(context.Context) error {
	i.record("quiesce")
	return nil
}

func (i *fakeInstance) Stop(context.Context) error {
	i.record("stop")
	i.stopped.Store(true)
	return nil
}

func (i *fakeInstance) Use() error {
	if i.stopped.Load() {
		return errors.New("used stopped instance")
	}
	return nil
}

func (i *fakeInstance) record(event string) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.events = append(i.events, event)
}

func (i *fakeInstance) lifecycle() []string {
	i.mu.Lock()
	defer i.mu.Unlock()
	return append([]string(nil), i.events...)
}

type fakeFactory struct {
	mu        sync.Mutex
	instances map[uint64]*fakeInstance
	failReady uint64
	requests  []PrepareRequest
}

func newFakeFactory() *fakeFactory {
	return &fakeFactory{instances: make(map[uint64]*fakeInstance)}
}

func (f *fakeFactory) Prepare(_ context.Context, request PrepareRequest) (Instance, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	instance := &fakeInstance{generation: request.Generation}
	if request.Generation == f.failReady {
		instance.readyErr = errors.New("not ready")
	}
	f.instances[request.Generation] = instance
	request.Config = append([]byte(nil), request.Config...)
	f.requests = append(f.requests, request)
	return instance, nil
}

func (f *fakeFactory) instance(generation uint64) *fakeInstance {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.instances[generation]
}

func newTestManager(t *testing.T, factory Factory, dependencies ...string) *Manager {
	t.Helper()
	manager, err := New([]Definition{{ID: "module-a", Dependencies: dependencies, Factory: factory}}, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return manager
}

func TestManagerBlueGreenReplacementDrainsOldLease(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	first := activateForTest(t, manager, "module-a", []byte(`{"version":1}`))
	lease, err := manager.Acquire("module-a", LeaseRequest)
	if err != nil || lease.Generation() != first.Generation {
		t.Fatalf("Acquire() = (%+v, %v)", lease, err)
	}
	second := activateForTest(t, manager, "module-a", []byte(`{"version":2}`))
	assertGeneration(t, manager, second.Generation)
	assertWaitDeadline(t, second.Retirement)
	if factory.instance(first.Generation).stopped.Load() {
		t.Fatal("old generation stopped while request lease was held")
	}
	lease.Release()
	if err := second.Retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
	want := []string{"start", "ready", "quiesce", "stop"}
	if got := factory.instance(first.Generation).lifecycle(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("old lifecycle = %v, want %v", got, want)
	}
}

func activateForTest(t *testing.T, manager *Manager, id string, config []byte) *Activation {
	t.Helper()
	activation, err := manager.Activate(context.Background(), id, config)
	if err != nil {
		t.Fatalf("Activate(%s) error = %v", id, err)
	}
	return activation
}

func assertGeneration(t *testing.T, manager *Manager, want uint64) {
	t.Helper()
	lease, err := manager.Acquire("module-a", LeaseRequest)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	defer lease.Release()
	if lease.Generation() != want {
		t.Fatalf("generation = %d, want %d", lease.Generation(), want)
	}
}

func assertWaitDeadline(t *testing.T, retirement *Retirement) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := retirement.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Wait() error = %v", err)
	}
}

func TestManagerFailedCandidateNeverReplacesActiveGeneration(t *testing.T) {
	factory := newFakeFactory()
	factory.failReady = 2
	manager := newTestManager(t, factory)
	first := activateForTest(t, manager, "module-a", nil)
	if _, err := manager.Activate(context.Background(), "module-a", []byte("bad")); err == nil {
		t.Fatal("Activate() candidate error = nil")
	}
	assertGeneration(t, manager, first.Generation)
	failed := factory.instance(2)
	if !failed.stopped.Load() {
		t.Fatal("failed candidate was not cleaned up")
	}
}

func TestManagerDisableWaitsForBackgroundLease(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	activateForTest(t, manager, "module-a", nil)
	lease, err := manager.Acquire("module-a", LeaseBackground)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	retirement, err := manager.Disable("module-a")
	if err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	if _, err := manager.Acquire("module-a", LeaseRequest); !errors.Is(err, ErrModuleInactive) {
		t.Fatalf("Acquire() after disable error = %v", err)
	}
	assertWaitDeadline(t, retirement)
	lease.Release()
	lease.Release()
	if err := retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
}
