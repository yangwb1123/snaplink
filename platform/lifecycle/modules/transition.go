package modules

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Activation struct {
	ModuleID    string
	Generation  uint64
	PublishedAt time.Time
	Retirement  *Retirement
}

type Retirement struct {
	done chan struct{}
	mu   sync.RWMutex
	err  error
}

func newRetirement() *Retirement { return &Retirement{done: make(chan struct{})} }

func completedRetirement(err error) *Retirement {
	retirement := newRetirement()
	retirement.complete(err)
	return retirement
}

func (r *Retirement) complete(err error) {
	r.mu.Lock()
	r.err = err
	close(r.done)
	r.mu.Unlock()
}

func (r *Retirement) Wait(ctx context.Context) error {
	if r == nil {
		return nil
	}
	select {
	case <-r.done:
		r.mu.RLock()
		defer r.mu.RUnlock()
		return r.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *Manager) Activate(ctx context.Context, moduleID string, config []byte) (*Activation, error) {
	if m == nil || m.closed.Load() {
		return nil, ErrManagerClosed
	}
	if len(config) > m.options.MaxConfigBytes {
		return nil, ErrConfigTooLarge
	}
	config = append([]byte(nil), config...)
	slot, err := m.beginTransition(moduleID)
	if err != nil {
		return nil, err
	}
	defer m.endTransition(slot)
	definition, ok := m.catalog.definitions[moduleID]
	if !ok {
		return nil, ErrModuleUnknown
	}
	previous := m.slots[moduleID].current.Load()
	if err := m.rejectActiveDependents(previous); err != nil {
		return nil, err
	}
	dependencies, err := m.acquireDependencies(definition)
	if err != nil {
		return nil, err
	}
	candidate, err := m.prepareCandidate(ctx, definition, config, dependencies)
	if err != nil {
		return nil, err
	}
	activation, err := m.commitCandidate(moduleID, candidate, previous)
	if err != nil {
		return nil, errors.Join(err, m.cleanupCandidate(candidate))
	}
	return activation, nil
}

func (m *Manager) acquireDependencies(definition Definition) ([]*Lease, error) {
	m.graphMu.Lock()
	defer m.graphMu.Unlock()
	leases := make([]*Lease, 0, len(definition.Dependencies))
	for _, dependency := range definition.Dependencies {
		lease, err := m.acquire(dependency, LeaseDependency)
		if err != nil {
			releaseLeases(leases)
			return nil, fmt.Errorf("%w: %s", ErrDependencyInactive, dependency)
		}
		leases = append(leases, lease)
	}
	return leases, nil
}

func (m *Manager) prepareCandidate(
	ctx context.Context, definition Definition, config []byte, dependencies []*Lease,
) (*generation, error) {
	number := m.slots[definition.ID].next.Add(1)
	candidate := newGeneration(definition.ID, number, nil, configDigest(config), dependencies)
	request := PrepareRequest{
		ModuleID: definition.ID, Generation: number, Config: config,
		Dependencies: dependencyInstances(definition.Dependencies, dependencies),
		Controller:   &generationController{generation: candidate},
	}
	instance, err := m.prepareInstance(ctx, definition.Factory, request)
	candidate.instance = instance
	if err != nil || instance == nil {
		m.emitTransition(TransitionPrepareFailed, candidate, 0)
		return nil, m.rejectCandidate(candidate, errors.Join(ErrDefinitionInvalid, err))
	}
	if err := m.callLifecycle(ctx, instance.Start); err != nil {
		m.emitTransition(TransitionStartFailed, candidate, 0)
		return nil, m.rejectCandidate(candidate, err)
	}
	if err := m.callLifecycle(ctx, instance.Ready); err != nil {
		m.emitTransition(TransitionReadyFailed, candidate, 0)
		return nil, m.rejectCandidate(candidate, err)
	}
	candidate.activatedAt = time.Now().UTC()
	return candidate, nil
}

func (m *Manager) prepareInstance(
	parent context.Context, factory Factory, request PrepareRequest,
) (Instance, error) {
	ctx, cancel := m.lifecycleContext(parent)
	defer cancel()
	return factory.Prepare(ctx, request)
}

func (m *Manager) callLifecycle(parent context.Context, call func(context.Context) error) error {
	ctx, cancel := m.lifecycleContext(parent)
	defer cancel()
	return call(ctx)
}

func (m *Manager) lifecycleContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, m.options.LifecycleTimeout)
}

func (m *Manager) rejectCandidate(candidate *generation, cause error) error {
	return errors.Join(cause, m.cleanupCandidate(candidate))
}

func dependencyInstances(ids []string, leases []*Lease) map[string]Instance {
	result := make(map[string]Instance, len(ids))
	for index, id := range ids {
		result[id] = leases[index].Instance()
	}
	return result
}

func (m *Manager) cleanupCandidate(candidate *generation) error {
	m.beginRetirement(candidate, TransitionCandidateDrainStarted, 0)
	ctx, cancel := context.WithTimeout(context.Background(), m.options.DrainTimeout)
	defer cancel()
	if err := candidate.waitDrained(ctx); err != nil {
		drainErr := errors.Join(ErrDrainTimeout, err)
		m.setHealth(generationHealthKey(candidate), drainErr)
		m.emitTransition(TransitionDrainTimedOut, candidate, 0)
		m.retirementTasks.Add(1)
		go func() {
			defer m.retirementTasks.Done()
			m.finishCandidateDrain(candidate)
		}()
		return drainErr
	}
	return m.finishCandidate(candidate)
}

func (m *Manager) finishCandidateDrain(candidate *generation) {
	_ = candidate.waitDrained(context.Background())
	m.setHealth(generationHealthKey(candidate), nil)
	_ = m.finishCandidate(candidate)
}

func (m *Manager) finishCandidate(candidate *generation) error {
	if candidate.instance != nil {
		return m.stopGeneration(candidate)
	}
	releaseGenerationDependencies(candidate)
	m.untrackRetiring(candidate)
	m.emitTransition(TransitionRetired, candidate, 0)
	return nil
}

func (m *Manager) commitCandidate(
	moduleID string, candidate, previous *generation,
) (*Activation, error) {
	if err := m.commitCandidateSlot(moduleID, candidate, previous); err != nil {
		return nil, err
	}
	return m.finishCandidateCommit(moduleID, candidate, previous), nil
}

func (m *Manager) commitCandidateSlot(
	moduleID string, candidate, previous *generation,
) error {
	m.admissionMu.Lock()
	defer m.admissionMu.Unlock()
	if m.closed.Load() {
		return ErrManagerClosed
	}
	m.graphMu.Lock()
	defer m.graphMu.Unlock()
	if m.slots[moduleID].current.Load() != previous {
		return ErrTransitionInProgress
	}
	if previous != nil && previous.leaseCount(LeaseDependency) > 0 {
		return ErrDependentsActive
	}
	m.slots[moduleID].current.Store(candidate)
	if previous != nil {
		previous.beginDrain()
	}
	return nil
}

func (m *Manager) finishCandidateCommit(
	moduleID string, candidate, previous *generation,
) *Activation {
	previousNumber := uint64(0)
	if previous != nil {
		previousNumber = previous.number
	}
	m.emitTransition(TransitionActivated, candidate, previousNumber)
	retirement := completedRetirement(nil)
	if previous != nil {
		m.trackRetiring(previous)
		m.emitTransition(TransitionReplacementStarted, previous, candidate.number)
		retirement = m.retire(previous)
	}
	return &Activation{
		ModuleID: moduleID, Generation: candidate.number,
		PublishedAt: candidate.activatedAt, Retirement: retirement,
	}
}

func (m *Manager) rejectActiveDependents(generation *generation) error {
	if generation == nil {
		return nil
	}
	m.graphMu.Lock()
	defer m.graphMu.Unlock()
	if generation.leaseCount(LeaseDependency) > 0 {
		return ErrDependentsActive
	}
	return nil
}

func (m *Manager) Disable(moduleID string) (*Retirement, error) {
	if m == nil || m.closed.Load() {
		return nil, ErrManagerClosed
	}
	slot, err := m.beginTransition(moduleID)
	if err != nil {
		return nil, err
	}
	defer m.endTransition(slot)
	current, err := m.disableTransition(moduleID)
	if err != nil {
		return nil, err
	}
	return m.retire(current), nil
}

func (m *Manager) disableTransition(moduleID string) (*generation, error) {
	current, err := m.commitDisable(moduleID)
	if err != nil {
		return nil, err
	}
	m.trackRetiring(current)
	m.emitTransition(TransitionDisableStarted, current, 0)
	return current, nil
}

func (m *Manager) commitDisable(moduleID string) (*generation, error) {
	m.admissionMu.Lock()
	defer m.admissionMu.Unlock()
	if m.closed.Load() {
		return nil, ErrManagerClosed
	}
	m.graphMu.Lock()
	defer m.graphMu.Unlock()
	slot := m.slots[moduleID]
	current := slot.current.Load()
	if current == nil {
		return nil, ErrModuleInactive
	}
	if current.leaseCount(LeaseDependency) > 0 {
		return nil, ErrDependentsActive
	}
	current.beginDrain()
	slot.current.Store(nil)
	return current, nil
}

func configDigest(config []byte) string {
	digest := sha256.Sum256(config)
	return hex.EncodeToString(digest[:])
}

func releaseLeases(leases []*Lease) {
	for index := len(leases) - 1; index >= 0; index-- {
		leases[index].Release()
	}
}

func releaseGenerationDependencies(generation *generation) {
	releaseLeases(generation.dependencies)
	generation.dependencies = nil
}

func (m *Manager) retire(generation *generation) *Retirement {
	m.trackRetiring(generation)
	retirement := newRetirement()
	m.retirementTasks.Add(1)
	go func() {
		defer m.retirementTasks.Done()
		retirement.complete(m.retireGeneration(generation))
	}()
	return retirement
}

func (m *Manager) retireGeneration(generation *generation) error {
	key := generationHealthKey(generation)
	timer := time.NewTimer(m.options.DrainTimeout)
	defer timer.Stop()
	select {
	case <-generation.drained:
	case <-timer.C:
		m.setHealth(key, ErrDrainTimeout)
		m.emitTransition(TransitionDrainTimedOut, generation, 0)
		<-generation.drained
		m.setHealth(key, nil)
	}
	return m.stopGeneration(generation)
}

func (m *Manager) stopGeneration(generation *generation) error {
	quiesceErr := m.callLifecycle(context.Background(), generation.instance.Quiesce)
	stopErr := m.callLifecycle(context.Background(), generation.instance.Stop)
	err := errors.Join(quiesceErr, stopErr)
	key := generationHealthKey(generation)
	if quiesceErr != nil {
		m.emitTransition(TransitionQuiesceFailed, generation, 0)
	}
	if stopErr != nil {
		m.emitTransition(TransitionStopFailed, generation, 0)
	} else {
		releaseGenerationDependencies(generation)
		m.untrackRetiring(generation)
		m.emitTransition(TransitionRetired, generation, 0)
	}
	if err != nil {
		m.setHealth(key, err)
	} else {
		m.setHealth(key, nil)
	}
	return err
}

func generationHealthKey(generation *generation) string {
	return fmt.Sprintf("%s/%d", generation.id, generation.number)
}

func (m *Manager) beginRetirement(
	generation *generation, kind TransitionEventType, related uint64,
) {
	generation.beginDrain()
	m.trackRetiring(generation)
	m.emitTransition(kind, generation, related)
}
