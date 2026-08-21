package modules

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultObserverQueueSize = 256
	maxObserverQueueSize     = 4096
	maxObserverTimeout       = 30 * time.Second
)

type transitionDispatcher struct {
	observer TransitionObserver
	timeout  time.Duration
	events   chan TransitionEvent
	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once
	stateMu  sync.RWMutex
	closed   bool
	pending  int
	idle     chan struct{}
	dropped  atomic.Uint64
	failures atomic.Uint64
}

func newTransitionDispatcher(options Options) *transitionDispatcher {
	if options.TransitionObserver == nil {
		return nil
	}
	dispatcher := &transitionDispatcher{
		observer: options.TransitionObserver, timeout: options.ObserverTimeout,
		events: make(chan TransitionEvent, options.ObserverQueueSize),
		stop:   make(chan struct{}), done: make(chan struct{}),
	}
	dispatcher.idle = make(chan struct{})
	close(dispatcher.idle)
	go dispatcher.run()
	return dispatcher
}

func (d *transitionDispatcher) emit(event TransitionEvent) {
	if d == nil {
		return
	}
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	if d.closed {
		d.dropped.Add(1)
		return
	}
	select {
	case d.events <- event:
		if d.pending == 0 {
			d.idle = make(chan struct{})
		}
		d.pending++
	default:
		d.dropped.Add(1)
	}
}

func (d *transitionDispatcher) run() {
	defer close(d.done)
	for {
		select {
		case event := <-d.events:
			d.deliver(event)
		case <-d.stop:
			d.drain()
			return
		}
	}
}

func (d *transitionDispatcher) drain() {
	for {
		select {
		case event := <-d.events:
			d.deliver(event)
		default:
			return
		}
	}
}

func (d *transitionDispatcher) deliver(event TransitionEvent) {
	defer d.markComplete()
	ctx, cancel := context.WithTimeout(context.Background(), d.timeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			d.failures.Add(1)
		}
	}()
	if err := d.observer.Observe(ctx, event); err != nil {
		d.failures.Add(1)
	}
}

func (d *transitionDispatcher) markComplete() {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	if d.pending == 0 {
		return
	}
	d.pending--
	if d.pending == 0 {
		close(d.idle)
	}
}

func (d *transitionDispatcher) wait(ctx context.Context) error {
	if d == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	d.stateMu.RLock()
	idle := d.idle
	d.stateMu.RUnlock()
	select {
	case <-idle:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *transitionDispatcher) closeAndDrain() {
	if d == nil {
		return
	}
	d.stopOnce.Do(func() {
		d.stateMu.Lock()
		d.closed = true
		close(d.stop)
		d.stateMu.Unlock()
	})
	timer := time.NewTimer(d.timeout)
	defer timer.Stop()
	select {
	case <-d.done:
	case <-timer.C:
		d.failures.Add(1)
	}
}

func (d *transitionDispatcher) status() ObserverStatus {
	if d == nil {
		return ObserverStatus{}
	}
	d.stateMu.RLock()
	pending := d.pending
	d.stateMu.RUnlock()
	return ObserverStatus{
		Pending: pending, Dropped: d.dropped.Load(), Failures: d.failures.Load(),
	}
}

func (m *Manager) emitTransition(kind TransitionEventType, generation *generation, related uint64) {
	if m == nil || generation == nil {
		return
	}
	m.observer.emit(TransitionEvent{
		Type: kind, ModuleID: generation.id, Generation: generation.number,
		RelatedGeneration: related, OccurredAt: time.Now().UTC(),
	})
}

func (m *Manager) ObserverStatus() ObserverStatus {
	if m == nil {
		return ObserverStatus{}
	}
	return m.observer.status()
}

// WaitObserver waits until all transition callbacks already accepted by the
// observer dispatcher finish. It does not block future transitions. Hosts use
// it at startup when a callback mutates a sink that will be wired immediately
// afterward.
func (m *Manager) WaitObserver(ctx context.Context) error {
	if m == nil {
		return nil
	}
	return m.observer.wait(ctx)
}
