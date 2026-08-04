package modules

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

type slot struct {
	current       atomic.Pointer[generation]
	next          atomic.Uint64
	transitionMu  sync.RWMutex
	transitioning bool
}

type Manager struct {
	catalog *catalog
	options Options
	slots   map[string]*slot

	admissionMu       sync.Mutex
	graphMu           sync.Mutex
	transitions       sync.WaitGroup
	activeTransitions atomic.Int64
	retirementTasks   sync.WaitGroup
	closed            atomic.Bool
	closing           *Retirement
	observer          *transitionDispatcher
	healthMu          sync.RWMutex
	health            map[string]error
	retiringMu        sync.RWMutex
	retiring          map[string]map[uint64]*generation
}

func New(definitions []Definition, options Options) (*Manager, error) {
	catalog, err := buildCatalog(definitions)
	if err != nil {
		return nil, err
	}
	options = normalizeOptions(options)
	manager := &Manager{
		catalog: catalog, options: options, slots: make(map[string]*slot, len(definitions)),
		closing: newRetirement(), health: make(map[string]error),
		retiring: make(map[string]map[uint64]*generation),
	}
	manager.observer = newTransitionDispatcher(options)
	for id := range catalog.definitions {
		manager.slots[id] = &slot{}
	}
	return manager, nil
}

func normalizeOptions(options Options) Options {
	defaults := defaultOptions()
	if options.MaxConfigBytes <= 0 {
		options.MaxConfigBytes = defaults.MaxConfigBytes
	}
	if options.DrainTimeout <= 0 {
		options.DrainTimeout = defaults.DrainTimeout
	}
	if options.LifecycleTimeout <= 0 {
		options.LifecycleTimeout = defaults.LifecycleTimeout
	}
	if options.ObserverQueueSize <= 0 {
		options.ObserverQueueSize = defaults.ObserverQueueSize
	}
	if options.ObserverQueueSize > maxObserverQueueSize {
		options.ObserverQueueSize = maxObserverQueueSize
	}
	if options.ObserverTimeout <= 0 {
		options.ObserverTimeout = defaults.ObserverTimeout
	}
	if options.ObserverTimeout > maxObserverTimeout {
		options.ObserverTimeout = maxObserverTimeout
	}
	return options
}

func (m *Manager) Acquire(moduleID string, class LeaseClass) (*Lease, error) {
	if m == nil || m.closed.Load() {
		return nil, ErrManagerClosed
	}
	if class == LeaseDependency || !validLeaseClass(class) {
		return nil, ErrDefinitionInvalid
	}
	return m.acquire(moduleID, class)
}

func (m *Manager) acquire(moduleID string, class LeaseClass) (*Lease, error) {
	slot, ok := m.slots[moduleID]
	if !ok {
		return nil, ErrModuleUnknown
	}
	for {
		current := slot.current.Load()
		if current == nil {
			return nil, ErrModuleInactive
		}
		if lease, acquired := current.acquire(class); acquired {
			return lease, nil
		}
		if slot.current.Load() == current {
			return nil, ErrModuleDraining
		}
	}
}

func (m *Manager) Ready(ctx context.Context) error {
	if m == nil || m.closed.Load() {
		return ErrManagerClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.healthMu.RLock()
	defer m.healthMu.RUnlock()
	var result error
	for id, err := range m.health {
		result = errors.Join(result, fmt.Errorf("%s: %w", id, err))
	}
	return result
}

func (m *Manager) setHealth(key string, err error) {
	m.healthMu.Lock()
	defer m.healthMu.Unlock()
	if err == nil {
		delete(m.health, key)
		return
	}
	m.health[key] = err
}

// Close atomically rejects new transitions and starts one background shutdown.
// If a lifecycle transition is active, it returns ErrTransitionInProgress so a
// callback can never wait on its own transition; a later call waits for the
// shared completion subject to its context.
func (m *Manager) Close(ctx context.Context) error {
	if m == nil {
		return nil
	}
	m.admissionMu.Lock()
	start := !m.closed.Load()
	if start {
		m.closed.Store(true)
	}
	active := m.activeTransitions.Load()
	m.admissionMu.Unlock()
	if start {
		go m.closeAll()
	}
	if active > 0 {
		return ErrTransitionInProgress
	}
	return m.closing.Wait(ctx)
}

func (m *Manager) closeAll() {
	m.transitions.Wait()
	retirements := m.disableAll()
	var result error
	for _, retirement := range retirements {
		if err := retirement.Wait(context.Background()); err != nil {
			result = errors.Join(result, err)
		}
	}
	m.retirementTasks.Wait()
	m.observer.closeAndDrain()
	m.closing.complete(result)
}

func (m *Manager) disableAll() []*Retirement {
	result := make([]*Retirement, 0, len(m.catalog.order))
	for index := len(m.catalog.order) - 1; index >= 0; index-- {
		id := m.catalog.order[index]
		current := m.detachForClose(id)
		if current == nil {
			continue
		}
		m.trackRetiring(current)
		m.emitTransition(TransitionCloseStarted, current, 0)
		result = append(result, m.retire(current))
	}
	return result
}

func (m *Manager) detachForClose(moduleID string) *generation {
	m.graphMu.Lock()
	defer m.graphMu.Unlock()
	slot := m.slots[moduleID]
	current := slot.current.Load()
	if current != nil {
		current.beginDrain()
		slot.current.Store(nil)
	}
	return current
}

func (m *Manager) beginTransition(moduleID string) (*slot, error) {
	m.admissionMu.Lock()
	defer m.admissionMu.Unlock()
	if m.closed.Load() {
		return nil, ErrManagerClosed
	}
	slot, ok := m.slots[moduleID]
	if !ok {
		return nil, ErrModuleUnknown
	}
	if !slot.beginTransition() {
		return nil, ErrTransitionInProgress
	}
	m.transitions.Add(1)
	m.activeTransitions.Add(1)
	return slot, nil
}

func (m *Manager) endTransition(slot *slot) {
	slot.endTransition()
	m.activeTransitions.Add(-1)
	m.transitions.Done()
}

func (s *slot) beginTransition() bool {
	s.transitionMu.Lock()
	defer s.transitionMu.Unlock()
	if s.transitioning {
		return false
	}
	s.transitioning = true
	return true
}

func (s *slot) endTransition() {
	s.transitionMu.Lock()
	s.transitioning = false
	s.transitionMu.Unlock()
}

func (s *slot) transitionStatus() bool {
	s.transitionMu.RLock()
	defer s.transitionMu.RUnlock()
	return s.transitioning
}
