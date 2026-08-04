package modules

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGenerationControllerPinsOnlyItsGeneration(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	first := activateForTest(t, manager, "module-a", nil)
	oldController := factory.requests[0].Controller
	oldLease, err := oldController.AcquireBackground()
	if err != nil || oldLease.Generation() != first.Generation {
		t.Fatalf("old background lease = (%v, %v)", oldLease, err)
	}
	second := activateForTest(t, manager, "module-a", nil)
	if _, err := oldController.AcquireBackground(); !errors.Is(err, ErrModuleDraining) {
		t.Fatalf("old controller acquisition error = %v", err)
	}
	newLease, err := factory.requests[1].Controller.AcquireBackground()
	if err != nil || newLease.Generation() != second.Generation {
		t.Fatalf("new background lease = (%v, %v)", newLease, err)
	}
	assertWaitDeadline(t, second.Retirement)
	oldLease.Release()
	newLease.Release()
	if err := second.Retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retirement error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestStopFailureRetainsDependencyPinAndDegradesReadiness(t *testing.T) {
	stopErr := errors.New("child stop failed")
	baseFactory := newFakeFactory()
	child := &lifecycleProbe{stopErr: stopErr}
	manager := dependencyManager(t, baseFactory, FactoryFunc(func(context.Context, PrepareRequest) (Instance, error) {
		return child, nil
	}))
	activateForTest(t, manager, "base", nil)
	activateForTest(t, manager, "child", nil)
	retirement, err := manager.Disable("child")
	if err != nil {
		t.Fatalf("Disable(child) error = %v", err)
	}
	if err := retirement.Wait(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("child retirement error = %v", err)
	}
	if _, err := manager.Disable("base"); !errors.Is(err, ErrDependentsActive) {
		t.Fatalf("Disable(base) error = %v", err)
	}
	if err := manager.Ready(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("Ready() error = %v", err)
	}
	status := moduleStatus(t, manager, "child")
	if status.State != StateDraining || len(status.Retiring) != 1 {
		t.Fatalf("failed Stop status = %+v", status)
	}
	if !strings.Contains(status.Retiring[0].LastError, stopErr.Error()) {
		t.Fatalf("failed Stop last error = %q", status.Retiring[0].LastError)
	}
}

func TestCandidateCleanupErrorIsReturnedAndDegradesReadiness(t *testing.T) {
	readyErr := errors.New("candidate not ready")
	stopErr := errors.New("candidate stop failed")
	baseFactory := newFakeFactory()
	candidate := &lifecycleProbe{readyErr: readyErr, stopErr: stopErr}
	manager := dependencyManager(t, baseFactory, FactoryFunc(func(context.Context, PrepareRequest) (Instance, error) {
		return candidate, nil
	}))
	activateForTest(t, manager, "base", nil)
	_, err := manager.Activate(context.Background(), "child", nil)
	if !errors.Is(err, readyErr) || !errors.Is(err, stopErr) {
		t.Fatalf("Activate(child) error = %v", err)
	}
	if err := manager.Ready(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("Ready() error = %v", err)
	}
	if _, err := manager.Disable("base"); !errors.Is(err, ErrDependentsActive) {
		t.Fatalf("Disable(base) error = %v", err)
	}
}

func TestPrepareErrorWithInstanceRunsObservableCleanup(t *testing.T) {
	prepareErr := errors.New("prepare failed")
	stopErr := errors.New("prepared instance stop failed")
	instance := &lifecycleProbe{stopErr: stopErr}
	manager := newTestManager(t, FactoryFunc(func(context.Context, PrepareRequest) (Instance, error) {
		return instance, prepareErr
	}))
	_, err := manager.Activate(context.Background(), "module-a", nil)
	if !errors.Is(err, prepareErr) || !errors.Is(err, stopErr) {
		t.Fatalf("Activate() error = %v", err)
	}
	if !instance.saw("quiesce") || !instance.saw("stop") {
		t.Fatalf("cleanup calls = %+v", instance.seenSnapshot())
	}
	if err := manager.Ready(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("Ready() error = %v", err)
	}
}

func TestFailedCandidateBackgroundWorkDrainsBeforeCleanup(t *testing.T) {
	readyErr := errors.New("candidate not ready")
	instance := &lifecycleProbe{readyErr: readyErr}
	var background BackgroundLease
	factory := FactoryFunc(func(_ context.Context, request PrepareRequest) (Instance, error) {
		var err error
		background, err = request.Controller.AcquireBackground()
		return instance, err
	})
	manager, err := New([]Definition{{ID: "module-a", Factory: factory}}, Options{
		DrainTimeout: 5 * time.Millisecond, LifecycleTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = manager.Activate(context.Background(), "module-a", nil)
	if !errors.Is(err, readyErr) || !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Activate() error = %v", err)
	}
	if instance.saw("stop") {
		t.Fatal("candidate stopped while background lease was held")
	}
	background.Release()
	waitForLifecycleCall(t, instance, "stop")
	waitForReadyError(t, manager, nil)
}

func TestNilCandidateDrainsBackgroundBeforeReleasingDependencies(t *testing.T) {
	prepareErr := errors.New("prepare returned no instance")
	baseFactory := newFakeFactory()
	var background BackgroundLease
	var controller GenerationController
	childFactory := FactoryFunc(func(_ context.Context, request PrepareRequest) (Instance, error) {
		controller = request.Controller
		var err error
		background, err = controller.AcquireBackground()
		return nil, errors.Join(prepareErr, err)
	})
	manager, err := New([]Definition{
		{ID: "base", Factory: baseFactory},
		{ID: "child", Dependencies: []string{"base"}, Factory: childFactory},
	}, Options{DrainTimeout: 5 * time.Millisecond, LifecycleTimeout: time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activateForTest(t, manager, "base", nil)
	_, err = manager.Activate(context.Background(), "child", nil)
	if !errors.Is(err, prepareErr) || !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("Activate(child) error = %v", err)
	}
	if _, err := controller.AcquireBackground(); !errors.Is(err, ErrModuleDraining) {
		t.Fatalf("draining candidate controller error = %v", err)
	}
	if _, err := manager.Disable("base"); !errors.Is(err, ErrDependentsActive) {
		t.Fatalf("Disable(base) before candidate drain error = %v", err)
	}
	background.Release()
	waitForDependencyRelease(t, manager, "base")
	disableAndWait(t, manager, "base")
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func waitForDependencyRelease(t *testing.T, manager *Manager, moduleID string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status := moduleStatus(t, manager, moduleID)
		if status.Leases[LeaseDependency] == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("dependency lease did not release: %+v", moduleStatus(t, manager, moduleID))
}

func waitForLifecycleCall(t *testing.T, instance *lifecycleProbe, stage string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if instance.saw(stage) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("lifecycle call %q was not observed", stage)
}

func TestCloseAfterDeadlineWaitsForSharedCompletion(t *testing.T) {
	factory := newFakeFactory()
	manager := newTestManager(t, factory)
	activation := activateForTest(t, manager, "module-a", nil)
	lease, err := manager.Acquire("module-a", LeaseRequest)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	assertCloseDeadline(t, manager)
	assertCloseDeadline(t, manager)
	lease.Release()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("third Close() error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("completed Close() error = %v", err)
	}
	if !factory.instance(activation.Generation).stopped.Load() {
		t.Fatal("Close() completion preceded Stop()")
	}
}

func TestCloseReturnsTheSameStopFailureToEveryCaller(t *testing.T) {
	stopErr := errors.New("stop failed")
	instance := &lifecycleProbe{stopErr: stopErr}
	manager := newTestManager(t, FactoryFunc(func(context.Context, PrepareRequest) (Instance, error) {
		return instance, nil
	}))
	activateForTest(t, manager, "module-a", nil)
	if err := manager.Close(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := manager.Close(context.Background()); !errors.Is(err, stopErr) {
		t.Fatalf("second Close() error = %v", err)
	}
}

func TestConcurrentCloseCallersShareOneCompletion(t *testing.T) {
	manager := newTestManager(t, newFakeFactory())
	activateForTest(t, manager, "module-a", nil)
	lease, err := manager.Acquire("module-a", LeaseRequest)
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	const callers = 16
	start := make(chan struct{})
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			<-start
			results <- manager.Close(context.Background())
		}()
	}
	close(start)
	for !manager.closed.Load() {
		time.Sleep(time.Millisecond)
	}
	select {
	case err := <-results:
		t.Fatalf("Close() returned before lease release: %v", err)
	case <-time.After(10 * time.Millisecond):
	}
	lease.Release()
	for index := 0; index < callers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
}

func assertCloseDeadline(t *testing.T, manager *Manager) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := manager.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestEveryLifecycleCallbackReceivesABoundedContext(t *testing.T) {
	for _, stage := range []string{"prepare", "start", "ready", "quiesce", "stop"} {
		t.Run(stage, func(t *testing.T) {
			probe := &lifecycleProbe{timeoutStage: stage}
			factory := &deadlineFactory{timeoutStage: stage, instance: probe}
			manager, err := New([]Definition{{ID: "module-a", Factory: factory}}, Options{
				DrainTimeout: time.Second, LifecycleTimeout: 5 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			err = runTimedStage(manager, stage)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("%s error = %v", stage, err)
			}
			if !factory.stageWasBounded(stage, probe) {
				t.Fatalf("%s did not receive a deadline", stage)
			}
		})
	}
}

func runTimedStage(manager *Manager, stage string) error {
	if stage == "prepare" || stage == "start" || stage == "ready" {
		_, err := manager.Activate(context.Background(), "module-a", nil)
		return err
	}
	if _, err := manager.Activate(context.Background(), "module-a", nil); err != nil {
		return err
	}
	retirement, err := manager.Disable("module-a")
	if err != nil {
		return err
	}
	return retirement.Wait(context.Background())
}

type deadlineFactory struct {
	timeoutStage string
	instance     *lifecycleProbe
	mu           sync.Mutex
	bounded      bool
}

func (f *deadlineFactory) Prepare(ctx context.Context, _ PrepareRequest) (Instance, error) {
	_, bounded := ctx.Deadline()
	f.mu.Lock()
	f.bounded = bounded
	f.mu.Unlock()
	if f.timeoutStage == "prepare" {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.instance, nil
}

func (f *deadlineFactory) stageWasBounded(stage string, probe *lifecycleProbe) bool {
	if stage != "prepare" {
		return probe.wasBounded(stage)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bounded
}

type lifecycleProbe struct {
	mu           sync.Mutex
	timeoutStage string
	readyErr     error
	stopErr      error
	seen         map[string]bool
}

func (p *lifecycleProbe) Start(ctx context.Context) error {
	return p.call(ctx, "start", nil)
}

func (p *lifecycleProbe) Ready(ctx context.Context) error {
	return p.call(ctx, "ready", p.readyErr)
}

func (p *lifecycleProbe) Quiesce(ctx context.Context) error {
	return p.call(ctx, "quiesce", nil)
}

func (p *lifecycleProbe) Stop(ctx context.Context) error {
	return p.call(ctx, "stop", p.stopErr)
}

func (p *lifecycleProbe) call(ctx context.Context, stage string, result error) error {
	_, bounded := ctx.Deadline()
	p.mu.Lock()
	if p.seen == nil {
		p.seen = make(map[string]bool)
	}
	p.seen[stage] = bounded
	p.mu.Unlock()
	if p.timeoutStage == stage {
		<-ctx.Done()
		return ctx.Err()
	}
	return result
}

func (p *lifecycleProbe) saw(stage string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.seen[stage]
	return exists
}

func (p *lifecycleProbe) wasBounded(stage string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.seen[stage]
}

func (p *lifecycleProbe) seenSnapshot() map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	result := make(map[string]bool, len(p.seen))
	for stage, bounded := range p.seen {
		result[stage] = bounded
	}
	return result
}
