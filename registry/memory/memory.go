// Package memory implements registry.Registry in-process. Suitable for tests,
// single-node deployments, and as a reference when porting to a real backend.
package memory

import (
	"context"
	"errors"
	"maps"
	"sync"
	"time"

	"github.com/snaplink/sso/registry"
)

// defaultJanitorInterval is how often TTL'd entries are scanned.
const defaultJanitorInterval = time.Second

// ErrClosed is returned by operations on a closed Registry.
var ErrClosed = errors.New("registry/memory: registry closed")

// Registry is the in-process implementation. Instances are kept in a name →
// id → entry map; Watch subscribers receive a copy of every Event.
type Registry struct {
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	done      chan struct{}

	// services[serviceName][instanceID] = entry
	services map[string]map[string]*entry

	// watchers[serviceName] = active subscriber channels
	watchers map[string][]chan registry.Event
}

type entry struct {
	svc       *registry.Service
	expiresAt time.Time // zero if no TTL
}

func New() *Registry {
	r := &Registry{
		services: make(map[string]map[string]*entry),
		watchers: make(map[string][]chan registry.Event),
		done:     make(chan struct{}),
	}
	go r.janitor()
	return r
}

func (r *Registry) Register(_ context.Context, svc *registry.Service) error {
	if svc == nil || svc.ID == "" || svc.Name == "" {
		return errors.New("registry/memory: service id and name required")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	if r.services[svc.Name] == nil {
		r.services[svc.Name] = make(map[string]*entry)
	}
	_, replacing := r.services[svc.Name][svc.ID]
	r.services[svc.Name][svc.ID] = &entry{
		svc:       cloneService(svc),
		expiresAt: ttlDeadline(svc.TTL),
	}
	evtType := registry.EventAdded
	if replacing {
		evtType = registry.EventUpdated
	}
	r.mu.Unlock()
	r.broadcast(svc.Name, registry.Event{Type: evtType, Service: cloneService(svc)})
	return nil
}

func (r *Registry) Deregister(_ context.Context, instanceID string) error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	var (
		name    string
		removed *registry.Service
	)
	for n, instances := range r.services {
		if e, ok := instances[instanceID]; ok {
			removed = e.svc
			delete(instances, instanceID)
			if len(instances) == 0 {
				delete(r.services, n)
			}
			name = n
			break
		}
	}
	r.mu.Unlock()
	if removed != nil {
		r.broadcast(name, registry.Event{Type: registry.EventRemoved, Service: removed})
	}
	return nil
}

func (r *Registry) Discover(_ context.Context, serviceName string) ([]*registry.Service, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, ErrClosed
	}
	instances := r.services[serviceName]
	if len(instances) == 0 {
		return nil, registry.ErrNotFound
	}
	now := time.Now()
	out := make([]*registry.Service, 0, len(instances))
	for _, e := range instances {
		if e.expiresAt.IsZero() || now.Before(e.expiresAt) {
			out = append(out, cloneService(e.svc))
		}
	}
	if len(out) == 0 {
		return nil, registry.ErrNotFound
	}
	return out, nil
}

func (r *Registry) Watch(ctx context.Context, serviceName string) (<-chan registry.Event, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrClosed
	}
	ch := make(chan registry.Event, 16)
	r.watchers[serviceName] = append(r.watchers[serviceName], ch)
	r.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-r.done:
		}
		r.removeWatcher(serviceName, ch)
	}()
	return ch, nil
}

func (r *Registry) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		close(r.done)
		for name, chans := range r.watchers {
			for _, ch := range chans {
				close(ch)
			}
			delete(r.watchers, name)
		}
		r.mu.Unlock()
	})
	return nil
}

func (r *Registry) broadcast(serviceName string, evt registry.Event) {
	// Hold the read lock across BOTH the watcher lookup AND the sends. Close
	// and removeWatcher close watcher channels only under the write lock, so
	// the read lock here makes "send on ch" mutually exclusive with
	// "close(ch)" — without it, a non-blocking send racing a concurrent close
	// panics (the default: only guards a FULL channel, never a CLOSED one).
	// Every broadcast caller (Register/Deregister/evictExpired) already
	// released the write lock before calling, so re-acquiring the read lock
	// here does not deadlock. The send is non-blocking, so a slow subscriber
	// can't pin the lock.
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, ch := range r.watchers[serviceName] {
		select {
		case ch <- evt:
		default:
			// Slow consumer — drop rather than block. Watch contract is
			// "best-effort streaming"; consumers needing guaranteed delivery
			// should re-Discover periodically.
		}
	}
}

func (r *Registry) removeWatcher(serviceName string, ch chan registry.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	chans := r.watchers[serviceName]
	for i, c := range chans {
		if c == ch {
			r.watchers[serviceName] = append(chans[:i], chans[i+1:]...)
			close(ch)
			return
		}
	}
}

// janitor evicts TTL-expired entries every defaultJanitorInterval.
func (r *Registry) janitor() {
	t := time.NewTicker(defaultJanitorInterval)
	defer t.Stop()
	for {
		select {
		case <-r.done:
			return
		case now := <-t.C:
			r.evictExpired(now)
		}
	}
}

func (r *Registry) evictExpired(now time.Time) {
	type expired struct {
		name string
		svc  *registry.Service
	}
	var toRemove []expired

	r.mu.Lock()
	for name, instances := range r.services {
		for id, e := range instances {
			if !e.expiresAt.IsZero() && now.After(e.expiresAt) {
				toRemove = append(toRemove, expired{name: name, svc: e.svc})
				delete(instances, id)
			}
		}
		if len(instances) == 0 {
			delete(r.services, name)
		}
	}
	r.mu.Unlock()

	for _, ex := range toRemove {
		r.broadcast(ex.name, registry.Event{Type: registry.EventRemoved, Service: ex.svc})
	}
}

func ttlDeadline(ttl time.Duration) time.Time {
	if ttl <= 0 {
		return time.Time{}
	}
	return time.Now().Add(ttl)
}

// cloneService returns a defensive deep-enough copy so callers mutating their
// supplied Service (or the slice returned from Discover) can't corrupt the
// registry's state.
func cloneService(s *registry.Service) *registry.Service {
	if s == nil {
		return nil
	}
	cp := *s
	if s.Tags != nil {
		cp.Tags = append([]string{}, s.Tags...)
	}
	if s.Metadata != nil {
		cp.Metadata = make(map[string]string, len(s.Metadata))
		maps.Copy(cp.Metadata, s.Metadata)
	}
	if s.HealthCheck != nil {
		hc := *s.HealthCheck
		cp.HealthCheck = &hc
	}
	return &cp
}
