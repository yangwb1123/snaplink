package modules

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestLifecycleCallbackCanQueryStatusAndReentryFailsFast(t *testing.T) {
	var manager *Manager
	var callbackStatus Status
	var readyErr, reentryErr error
	factory := FactoryFunc(func(ctx context.Context, request PrepareRequest) (Instance, error) {
		callbackStatus = moduleStatus(t, manager, request.ModuleID)
		readyErr = manager.Ready(ctx)
		_, reentryErr = manager.Activate(ctx, request.ModuleID, nil)
		return &fakeInstance{generation: request.Generation}, nil
	})
	var err error
	manager, err = New([]Definition{{ID: "module-a", Factory: factory}}, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	activateForTest(t, manager, "module-a", nil)
	if !callbackStatus.Transitioning || callbackStatus.State != StateInactive {
		t.Fatalf("callback status = %+v", callbackStatus)
	}
	if readyErr != nil {
		t.Fatalf("callback Ready() error = %v", readyErr)
	}
	if !errors.Is(reentryErr, ErrTransitionInProgress) {
		t.Fatalf("same-module reentry error = %v", reentryErr)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestLifecycleCallbackCloseFailsFastAndLaterConverges(t *testing.T) {
	var manager *Manager
	var closeErr error
	var candidate *fakeInstance
	factory := FactoryFunc(func(_ context.Context, request PrepareRequest) (Instance, error) {
		closeErr = manager.Close(context.Background())
		candidate = &fakeInstance{generation: request.Generation}
		return candidate, nil
	})
	var err error
	manager, err = New([]Definition{{ID: "module-a", Factory: factory}}, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = manager.Activate(context.Background(), "module-a", nil)
	if !errors.Is(closeErr, ErrTransitionInProgress) {
		t.Fatalf("callback Close() error = %v", closeErr)
	}
	if !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Activate() error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("converged Close() error = %v", err)
	}
	if !candidate.stopped.Load() {
		t.Fatal("unpublished candidate was not stopped")
	}
}

func TestSlowLifecycleOnOneModuleDoesNotBlockAnother(t *testing.T) {
	slow := newBlockingFactory()
	manager, err := New([]Definition{
		{ID: "module-a", Factory: slow},
		{ID: "module-b", Factory: newFakeFactory()},
	}, Options{LifecycleTimeout: time.Second})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	slowResult := make(chan error, 1)
	go func() {
		_, err := manager.Activate(context.Background(), "module-a", nil)
		slowResult <- err
	}()
	<-slow.entered
	started := time.Now()
	activateForTest(t, manager, "module-b", nil)
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("independent activation blocked for %v", elapsed)
	}
	close(slow.release)
	if err := <-slowResult; err != nil {
		t.Fatalf("slow Activate() error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestConcurrentTransitionOnSameModuleFailsFast(t *testing.T) {
	factory := newBlockingFactory()
	manager := newTestManager(t, factory)
	firstResult := make(chan error, 1)
	go func() {
		_, err := manager.Activate(context.Background(), "module-a", nil)
		firstResult <- err
	}()
	<-factory.entered
	started := time.Now()
	_, err := manager.Activate(context.Background(), "module-a", nil)
	if !errors.Is(err, ErrTransitionInProgress) {
		t.Fatalf("concurrent Activate() error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("same-module rejection blocked for %v", elapsed)
	}
	close(factory.release)
	if err := <-firstResult; err != nil {
		t.Fatalf("first Activate() error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestCloseRacingReplacementAbortsCandidateAndWaits(t *testing.T) {
	factory := newReplacementFactory()
	manager := newTestManager(t, factory)
	first := activateForTest(t, manager, "module-a", nil)
	replacement := make(chan error, 1)
	go func() {
		_, err := manager.Activate(context.Background(), "module-a", nil)
		replacement <- err
	}()
	<-factory.readyEntered
	if err := manager.Close(context.Background()); !errors.Is(err, ErrTransitionInProgress) {
		t.Fatalf("Close() during replacement error = %v", err)
	}
	close(factory.readyRelease)
	if err := <-replacement; !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("replacement error = %v", err)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() completion error = %v", err)
	}
	if !factory.instance(first.Generation).stopped.Load() {
		t.Fatal("Close() did not stop the active generation")
	}
	if !factory.instance(first.Generation + 1).stopped.Load() {
		t.Fatal("Close() did not clean the unpublished candidate")
	}
}

func TestCloseAdmissionDoesNotRaceTransitionRegistration(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		manager := newTestManager(t, newFakeFactory())
		start := make(chan struct{})
		activation := make(chan error, 1)
		closed := make(chan error, 1)
		go func() {
			<-start
			_, err := manager.Activate(context.Background(), "module-a", nil)
			activation <- err
		}()
		go func() {
			<-start
			closed <- manager.Close(context.Background())
		}()
		close(start)
		if err := <-activation; err != nil && !errors.Is(err, ErrManagerClosed) {
			t.Fatalf("Activate() error = %v", err)
		}
		if err := <-closed; err != nil {
			if !errors.Is(err, ErrTransitionInProgress) {
				t.Fatalf("Close() error = %v", err)
			}
			if err := manager.Close(context.Background()); err != nil {
				t.Fatalf("Close() retry error = %v", err)
			}
		}
	}
}

func TestConcurrentCloseRunsOneReverseDependencyRetirement(t *testing.T) {
	log := &stopLog{}
	baseFactory := &orderedStopFactory{id: "base", log: log}
	childFactory := &orderedStopFactory{id: "child", log: log}
	manager := dependencyManager(t, baseFactory, childFactory)
	activateForTest(t, manager, "base", nil)
	activateForTest(t, manager, "child", nil)
	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	for index := 0; index < callers; index++ {
		go func() {
			<-start
			results <- manager.Close(context.Background())
		}()
	}
	close(start)
	for index := 0; index < callers; index++ {
		if err := <-results; err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if order := log.snapshot(); len(order) != 2 || order[0] != "child" || order[1] != "base" {
		t.Fatalf("Stop order = %v", order)
	}
	if baseFactory.stops.Load() != 1 || childFactory.stops.Load() != 1 {
		t.Fatalf("Stop calls = base:%d child:%d", baseFactory.stops.Load(), childFactory.stops.Load())
	}
}

func TestDependentActivationForcesConcurrentReplacementRollback(t *testing.T) {
	baseFactory := newReplacementFactory()
	childFactory := newFakeFactory()
	manager := dependencyManager(t, baseFactory, childFactory)
	first := activateForTest(t, manager, "base", nil)
	replacement := make(chan activationAttempt, 1)
	go func() {
		activation, err := manager.Activate(context.Background(), "base", nil)
		replacement <- activationAttempt{activation: activation, err: err}
	}()
	<-baseFactory.readyEntered
	activateForTest(t, manager, "child", nil)
	if childFactory.requests[0].Dependencies["base"] != baseFactory.instance(first.Generation) {
		t.Fatal("dependent did not pin the visible base generation")
	}
	close(baseFactory.readyRelease)
	result := <-replacement
	if result.activation != nil || !errors.Is(result.err, ErrDependentsActive) {
		t.Fatalf("replacement result = (%+v, %v)", result.activation, result.err)
	}
	lease, err := manager.Acquire("base", LeaseRequest)
	if err != nil || lease.Generation() != first.Generation {
		t.Fatalf("visible base after rollback = (%v, %v)", lease, err)
	}
	lease.Release()
	if !baseFactory.instance(first.Generation + 1).stopped.Load() {
		t.Fatal("rejected replacement candidate was not cleaned up")
	}
	disableAndWait(t, manager, "child")
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestDependentActivationAndDependencyDisableCommitAtomically(t *testing.T) {
	for iteration := 0; iteration < 50; iteration++ {
		exerciseDependencyDisableRace(t)
	}
}

func exerciseDependencyDisableRace(t *testing.T) {
	manager := dependencyManager(t, newFakeFactory(), newFakeFactory())
	activateForTest(t, manager, "base", nil)
	start := make(chan struct{})
	childResult := make(chan error, 1)
	disableResult := make(chan retirementAttempt, 1)
	go func() {
		<-start
		_, err := manager.Activate(context.Background(), "child", nil)
		childResult <- err
	}()
	go func() {
		<-start
		retirement, err := manager.Disable("base")
		disableResult <- retirementAttempt{retirement: retirement, err: err}
	}()
	close(start)
	childErr, disabled := <-childResult, <-disableResult
	if childErr == nil {
		assertDependentWonRace(t, manager, disabled)
	} else {
		assertDisableWonRace(t, manager, childErr, disabled)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func assertDependentWonRace(t *testing.T, manager *Manager, disabled retirementAttempt) {
	t.Helper()
	if !errors.Is(disabled.err, ErrDependentsActive) || disabled.retirement != nil {
		t.Fatalf("disable result after dependent commit = (%v, %v)", disabled.retirement, disabled.err)
	}
	lease, err := manager.Acquire("base", LeaseRequest)
	if err != nil {
		t.Fatalf("dependent pinned a hidden base: %v", err)
	}
	lease.Release()
	disableAndWait(t, manager, "child")
	disableAndWait(t, manager, "base")
}

func assertDisableWonRace(
	t *testing.T, manager *Manager, childErr error, disabled retirementAttempt,
) {
	t.Helper()
	if !errors.Is(childErr, ErrDependencyInactive) {
		t.Fatalf("dependent activation error = %v", childErr)
	}
	if disabled.err != nil || disabled.retirement == nil {
		t.Fatalf("disable result = (%v, %v)", disabled.retirement, disabled.err)
	}
	if err := disabled.retirement.Wait(context.Background()); err != nil {
		t.Fatalf("base retirement error = %v", err)
	}
}

type activationAttempt struct {
	activation *Activation
	err        error
}

type retirementAttempt struct {
	retirement *Retirement
	err        error
}

type stopLog struct {
	mu    sync.Mutex
	order []string
}

func (l *stopLog) append(id string) {
	l.mu.Lock()
	l.order = append(l.order, id)
	l.mu.Unlock()
}

func (l *stopLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.order...)
}

type orderedStopFactory struct {
	id    string
	log   *stopLog
	stops atomic.Int64
}

func (f *orderedStopFactory) Prepare(context.Context, PrepareRequest) (Instance, error) {
	return &orderedStopInstance{factory: f}, nil
}

type orderedStopInstance struct {
	factory *orderedStopFactory
}

func (i *orderedStopInstance) Start(context.Context) error   { return nil }
func (i *orderedStopInstance) Ready(context.Context) error   { return nil }
func (i *orderedStopInstance) Quiesce(context.Context) error { return nil }
func (i *orderedStopInstance) Stop(context.Context) error {
	i.factory.stops.Add(1)
	i.factory.log.append(i.factory.id)
	return nil
}

type blockingFactory struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func newBlockingFactory() *blockingFactory {
	return &blockingFactory{entered: make(chan struct{}), release: make(chan struct{})}
}

func (f *blockingFactory) Prepare(ctx context.Context, request PrepareRequest) (Instance, error) {
	f.once.Do(func() { close(f.entered) })
	select {
	case <-f.release:
		return &fakeInstance{generation: request.Generation}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

type replacementFactory struct {
	mu           sync.Mutex
	instances    map[uint64]*replacementInstance
	readyEntered chan struct{}
	readyRelease chan struct{}
}

func newReplacementFactory() *replacementFactory {
	return &replacementFactory{
		instances:    make(map[uint64]*replacementInstance),
		readyEntered: make(chan struct{}), readyRelease: make(chan struct{}),
	}
}

func (f *replacementFactory) Prepare(_ context.Context, request PrepareRequest) (Instance, error) {
	instance := &replacementInstance{
		generation: request.Generation, blockReady: request.Generation == 2,
		readyEntered: f.readyEntered, readyRelease: f.readyRelease,
	}
	f.mu.Lock()
	f.instances[request.Generation] = instance
	f.mu.Unlock()
	return instance, nil
}

func (f *replacementFactory) instance(generation uint64) *replacementInstance {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.instances[generation]
}

type replacementInstance struct {
	generation   uint64
	blockReady   bool
	readyEntered chan struct{}
	readyRelease chan struct{}
	stopped      atomic.Bool
}

func (i *replacementInstance) Start(context.Context) error { return nil }

func (i *replacementInstance) Ready(ctx context.Context) error {
	if !i.blockReady {
		return nil
	}
	close(i.readyEntered)
	select {
	case <-i.readyRelease:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (i *replacementInstance) Quiesce(context.Context) error { return nil }

func (i *replacementInstance) Stop(context.Context) error {
	i.stopped.Store(true)
	return nil
}
