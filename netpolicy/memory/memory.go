// Package memory is the in-process netpolicy.Store. Suitable for single-node
// deployments, tests, and dev. For multi-replica SSO servers use
// netpolicy/etcd instead so policy changes propagate.
package memory

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/snaplink/sso/netpolicy"
)

// ErrClosed is returned by Apply/Get/Watch after Close.
var ErrClosed = errors.New("netpolicy/memory: store closed")

// Store is the in-memory implementation of netpolicy.Store.
type Store struct {
	mu       sync.RWMutex
	closed   bool
	closeOne sync.Once
	done     chan struct{}

	byName  map[string]*netpolicy.Policy
	version int64

	watchersMu sync.Mutex
	watchers   []chan netpolicy.Event
}

// New constructs an empty Store. Use Apply to populate.
func New() *Store {
	return &Store{
		byName: make(map[string]*netpolicy.Policy),
		done:   make(chan struct{}),
	}
}

func (s *Store) Get(_ context.Context, name string) (*netpolicy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	p, ok := s.byName[name]
	if !ok {
		return nil, netpolicy.ErrNotFound
	}
	return p.Clone(), nil
}

func (s *Store) List(_ context.Context) ([]*netpolicy.Policy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	out := make([]*netpolicy.Policy, 0, len(s.byName))
	for _, p := range s.byName {
		out = append(out, p.Clone())
	}
	return out, nil
}

func (s *Store) Apply(_ context.Context, p *netpolicy.Policy) (*netpolicy.Policy, error) {
	if p == nil || p.Name == "" {
		return nil, errors.New("netpolicy/memory: policy.Name required")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrClosed
	}
	_, existed := s.byName[p.Name]
	s.version++
	stamped := p.Clone()
	stamped.Version = s.version
	stamped.UpdatedAt = time.Now().UTC()
	s.byName[p.Name] = stamped
	s.mu.Unlock()

	evtType := netpolicy.EventAdded
	if existed {
		evtType = netpolicy.EventUpdated
	}
	s.broadcast(netpolicy.Event{Type: evtType, Policy: stamped.Clone()})
	return stamped.Clone(), nil
}

func (s *Store) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrClosed
	}
	p, ok := s.byName[name]
	if !ok {
		s.mu.Unlock()
		return nil
	}
	delete(s.byName, name)
	s.mu.Unlock()
	s.broadcast(netpolicy.Event{
		Type:   netpolicy.EventRemoved,
		Policy: &netpolicy.Policy{Name: p.Name, Version: p.Version},
	})
	return nil
}

func (s *Store) Watch(ctx context.Context) (<-chan netpolicy.Event, error) {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return nil, ErrClosed
	}
	s.mu.RUnlock()

	ch := make(chan netpolicy.Event, 32)
	s.watchersMu.Lock()
	s.watchers = append(s.watchers, ch)
	s.watchersMu.Unlock()

	// The watcher goroutine is the sole owner of ch's close. Close() signals
	// shutdown via s.done; ctx cancellation does the same per-subscriber. The
	// close happens inside detachWatcher UNDER watchersMu so it cannot race a
	// concurrent broadcast send on the same channel — a send on a CLOSED
	// channel panics regardless of the non-blocking select (the default: only
	// guards a FULL channel). broadcast holds watchersMu across its sends, so
	// detach+close and send are mutually exclusive.
	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		s.detachWatcher(ch)
	}()
	return ch, nil
}

func (s *Store) Close() error {
	s.closeOne.Do(func() {
		s.mu.Lock()
		s.closed = true
		close(s.done)
		s.mu.Unlock()
	})
	return nil
}

func (s *Store) broadcast(evt netpolicy.Event) {
	// Hold watchersMu across BOTH the watcher lookup AND the sends so a send
	// cannot race detachWatcher's close of the same channel (which also runs
	// under watchersMu). The send is non-blocking, so a slow subscriber can't
	// pin the lock.
	s.watchersMu.Lock()
	defer s.watchersMu.Unlock()
	for _, ch := range s.watchers {
		select {
		case ch <- evt:
		default:
			// Slow consumer; drop. The Watch contract documents this and tells
			// clients to seed via List on reconnect.
		}
	}
}

// detachWatcher removes ch from the watcher list and closes it, both under
// watchersMu so the close is mutually exclusive with a concurrent broadcast
// send. Each watcher's goroutine calls this exactly once, so closing inside
// the found-branch can never double-close.
func (s *Store) detachWatcher(ch chan netpolicy.Event) {
	s.watchersMu.Lock()
	defer s.watchersMu.Unlock()
	for i, w := range s.watchers {
		if w == ch {
			s.watchers = append(s.watchers[:i], s.watchers[i+1:]...)
			close(ch)
			return
		}
	}
}
