package modules

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagerConcurrentAcquisitionNeverUsesStoppedGeneration(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	activateForTest(t, manager, "module-a", nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var failures atomic.Int64
	var wait sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go acquisitionWorker(ctx, manager, &failures, &wait)
	}
	for generation := 0; generation < 30; generation++ {
		activation := activateForTest(t, manager, "module-a", []byte{byte(generation)})
		if err := activation.Retirement.Wait(context.Background()); err != nil {
			t.Fatalf("retirement error = %v", err)
		}
	}
	cancel()
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("stopped-generation uses = %d", failures.Load())
	}
}

func acquisitionWorker(
	ctx context.Context, manager *Manager, failures *atomic.Int64, wait *sync.WaitGroup,
) {
	defer wait.Done()
	for ctx.Err() == nil {
		lease, err := manager.Acquire("module-a", LeaseRequest)
		if err != nil {
			continue
		}
		instance := lease.Instance().(*fakeInstance)
		if instance.Use() != nil {
			failures.Add(1)
		}
		lease.Release()
	}
}

func TestManagerReadinessReportsStuckDrainAndRecovers(t *testing.T) {
	factory := newFakeFactory()
	manager, err := New([]Definition{{ID: "module-a", Factory: factory}}, Options{
		DrainTimeout: 10 * time.Millisecond, LifecycleTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activateForTest(t, manager, "module-a", nil)
	lease, _ := manager.Acquire("module-a", LeaseRequest)
	retirement, err := manager.Disable("module-a")
	if err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	waitForReadyError(t, manager, ErrDrainTimeout)
	lease.Release()
	if err := retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
	waitForReadyError(t, manager, nil)
}

func waitForReadyError(t *testing.T, manager *Manager, want error) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		err := manager.Ready(context.Background())
		if want == nil && err == nil || want != nil && errors.Is(err, want) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("Ready() did not reach error %v", want)
}

func TestManagerRejectsOversizedConfigAndDependencyLease(t *testing.T) {
	manager, err := New([]Definition{{ID: "module-a", Factory: newFakeFactory()}}, Options{MaxConfigBytes: 2})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := manager.Activate(context.Background(), "module-a", []byte("123")); !errors.Is(err, ErrConfigTooLarge) {
		t.Fatalf("Activate() error = %v", err)
	}
	activateForTest(t, manager, "module-a", nil)
	if _, err := manager.Acquire("module-a", LeaseDependency); !errors.Is(err, ErrDefinitionInvalid) {
		t.Fatalf("Acquire(dependency) error = %v", err)
	}
}
