package auditgovernance

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
)

const defaultManagedRelayPause = 500 * time.Millisecond

// ManagedRelay describes one durable outbox worker in a precompiled module
// generation. A generation lease covers each claim-and-deliver batch, so a
// replacement stops old claims while allowing its in-flight batch to finish.
type ManagedRelay struct {
	Name       string
	Relay      *Relay
	IdlePause  time.Duration
	AuthPause  time.Duration
	ErrorPause time.Duration
}

// ManagedRelayBuilder prepares fresh relay instances for one generation.
// Config bytes are copied and bounded by the lifecycle manager before this is
// called; builders must still decode them strictly.
type ManagedRelayBuilder func(
	context.Context, []byte, uint64,
) ([]ManagedRelay, error)

// ManagedRelayEvent is a bounded operational signal. It deliberately omits
// source events, credentials, tenant identifiers, and underlying error text.
type ManagedRelayEvent struct {
	Name       string
	Generation uint64
	Class      string
}

// ManagedRelayObserver receives best-effort worker state signals.
type ManagedRelayObserver func(ManagedRelayEvent)

// ManagedRelayFactory adapts durable audit relays to the safe module manager.
// It does not discover or load executable code at runtime.
type ManagedRelayFactory struct {
	Build   ManagedRelayBuilder
	Observe ManagedRelayObserver
}

func (f ManagedRelayFactory) Prepare(
	ctx context.Context, request modules.PrepareRequest,
) (modules.Instance, error) {
	if f.Build == nil || request.Controller == nil {
		return nil, modules.ErrDefinitionInvalid
	}
	runners, err := f.Build(ctx, append([]byte(nil), request.Config...), request.Generation)
	if err != nil {
		return nil, err
	}
	if err := validateManagedRelays(runners); err != nil {
		return nil, err
	}
	return &managedRelayInstance{
		generation: request.Generation, controller: request.Controller,
		runners: runners, observe: f.Observe,
	}, nil
}

type managedRelayInstance struct {
	generation uint64
	controller modules.GenerationController
	runners    []ManagedRelay
	observe    ManagedRelayObserver

	mu      sync.Mutex
	started bool
	cancel  context.CancelFunc
	done    chan struct{}
	wait    sync.WaitGroup
}

func validateManagedRelays(runners []ManagedRelay) error {
	if len(runners) == 0 {
		return ErrInvalidConfig
	}
	seen := make(map[string]struct{}, len(runners))
	for index := range runners {
		runner := &runners[index]
		if runner.Name == "" || runner.Relay == nil {
			return ErrInvalidConfig
		}
		if _, duplicate := seen[runner.Name]; duplicate {
			return ErrInvalidConfig
		}
		seen[runner.Name] = struct{}{}
		normalizeManagedRelay(runner)
	}
	return nil
}

func normalizeManagedRelay(runner *ManagedRelay) {
	if runner.IdlePause <= 0 {
		runner.IdlePause = defaultManagedRelayPause
	}
	if runner.AuthPause <= 0 {
		runner.AuthPause = time.Minute
	}
	if runner.ErrorPause <= 0 {
		runner.ErrorPause = 5 * time.Second
	}
}

func (i *managedRelayInstance) Start(context.Context) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.started {
		return modules.ErrTransitionInProgress
	}
	workerCtx, cancel := context.WithCancel(context.Background())
	i.started, i.cancel, i.done = true, cancel, make(chan struct{})
	for _, runner := range i.runners {
		i.wait.Add(1)
		go i.run(workerCtx, runner)
	}
	go func() {
		i.wait.Wait()
		close(i.done)
	}()
	return nil
}

func (i *managedRelayInstance) Ready(ctx context.Context) error {
	i.mu.Lock()
	started, done := i.started, i.done
	i.mu.Unlock()
	if !started {
		return modules.ErrModuleInactive
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return modules.ErrModuleInactive
	default:
		return nil
	}
}

func (i *managedRelayInstance) Quiesce(context.Context) error {
	i.cancelWorkers()
	return nil
}

func (i *managedRelayInstance) Stop(ctx context.Context) error {
	i.cancelWorkers()
	i.mu.Lock()
	done := i.done
	i.mu.Unlock()
	if done == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

func (i *managedRelayInstance) cancelWorkers() {
	i.mu.Lock()
	cancel := i.cancel
	i.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (i *managedRelayInstance) run(ctx context.Context, runner ManagedRelay) {
	defer i.wait.Done()
	for ctx.Err() == nil {
		pause, keepRunning := i.runOnce(ctx, runner)
		if !keepRunning || !waitForPoll(ctx, pause) {
			return
		}
	}
}

func (i *managedRelayInstance) runOnce(
	ctx context.Context, runner ManagedRelay,
) (time.Duration, bool) {
	lease, err := i.controller.AcquireBackground()
	if errors.Is(err, modules.ErrModuleDraining) {
		return 0, false
	}
	if err != nil {
		i.emit(runner.Name, "lease_error")
		return runner.ErrorPause, true
	}
	result, runErr := runner.Relay.RunOnce(ctx)
	lease.Release()
	if ctx.Err() != nil {
		return 0, false
	}
	if runErr == nil {
		if result.Claimed > 0 {
			return 0, true
		}
		return runner.IdlePause, true
	}
	if errors.Is(runErr, ErrAuthorizationRejected) {
		i.emit(runner.Name, "authorization_rejected")
		return runner.AuthPause, true
	}
	i.emit(runner.Name, "operational_error")
	return runner.ErrorPause, true
}

func (i *managedRelayInstance) emit(name, class string) {
	if i.observe != nil {
		i.observe(ManagedRelayEvent{Name: name, Generation: i.generation, Class: class})
	}
}

var _ modules.Factory = ManagedRelayFactory{}
var _ modules.Instance = (*managedRelayInstance)(nil)
