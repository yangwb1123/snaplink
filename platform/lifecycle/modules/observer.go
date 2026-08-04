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
	go dispatcher.run()
	return dispatcher
}

func (d *transitionDispatcher) emit(event TransitionEvent) {
	if d == nil {
		return
	}
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	if d.closed {
		d.dropped.Add(1)
		return
	}
	select {
	case d.events <- event:
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
	return ObserverStatus{
		Pending: len(d.events), Dropped: d.dropped.Load(), Failures: d.failures.Load(),
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
