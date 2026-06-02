// Package memory is the in-process [signingkeys.Registry] peer. It fans
// announcements to every Subscriber in the same process — which is all a
// single-node deployment needs, and the building block multi-process
// backends (etcd) layer onto. Mirrors the best-effort broadcast + cleanup
// semantics of cluster/memory: a slow subscriber's Event is dropped rather
// than allowed to block the publisher.
//
// The memory peer has no real lease expiry: a single process is the only
// announcer, so there is no peer whose absence must be detected. A Publish
// replaces the announcer's prior announcement wholesale, which is sufficient
// for v1 and for tests. Cross-process lease expiry (so a crashed replica's
// keys eventually drop everywhere) arrives with the etcd backend.
package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/signingkeys"
)

// ErrClosed is returned by operations after the Registry is closed.
var ErrClosed = errors.New("signingkeys/memory: registry closed")

// Registry is an in-process fan-out implementation of signingkeys.Registry.
type Registry struct {
	mu     sync.RWMutex
	closed bool

	// announcements maps replicaID -> its latest announcement. A Publish
	// upserts; List snapshots the union.
	announcements map[string]signingkeys.Announcement

	subs      []chan signingkeys.Event
	done      chan struct{}
	closeOnce sync.Once
}

var _ signingkeys.Registry = (*Registry)(nil)

// New returns a ready in-process Registry.
func New() *Registry {
	return &Registry{
		announcements: make(map[string]signingkeys.Announcement),
		done:          make(chan struct{}),
	}
}

// Publish upserts ann under its ReplicaID and fans an EventKeysUpserted to
// every current subscriber, best-effort: a subscriber whose buffer is full
// is skipped (it falls back to a periodic List), never blocked on.
func (r *Registry) Publish(_ context.Context, ann signingkeys.Announcement) error {
	if ann.ReplicaID == "" {
		return errors.New("signingkeys/memory: announcement replica_id required")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return ErrClosed
	}
	r.announcements[ann.ReplicaID] = cloneAnnouncement(ann)
	subs := append([]chan signingkeys.Event(nil), r.subs...)
	r.mu.Unlock()

	evt := signingkeys.Event{Type: signingkeys.EventKeysUpserted, Announcement: cloneAnnouncement(ann)}
	for _, ch := range subs {
		select {
		case ch <- evt:
		default:
			// Slow consumer — drop. Adoption is idempotent and List is the
			// safety net.
		}
	}
	return nil
}

// List returns a snapshot of every currently live announcement.
func (r *Registry) List(_ context.Context) ([]signingkeys.Announcement, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return nil, ErrClosed
	}
	out := make([]signingkeys.Announcement, 0, len(r.announcements))
	for _, ann := range r.announcements {
		out = append(out, cloneAnnouncement(ann))
	}
	return out, nil
}

// Subscribe registers a new stream, removed automatically when ctx is
// cancelled or the Registry closes.
func (r *Registry) Subscribe(ctx context.Context) (<-chan signingkeys.Event, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil, ErrClosed
	}
	ch := make(chan signingkeys.Event, 16)
	r.subs = append(r.subs, ch)
	r.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-r.done:
		}
		r.removeSub(ch)
	}()
	return ch, nil
}

// Close stops the Registry and closes every subscriber stream. Idempotent.
func (r *Registry) Close() error {
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		close(r.done)
		for _, ch := range r.subs {
			close(ch)
		}
		r.subs = nil
		r.mu.Unlock()
	})
	return nil
}

func (r *Registry) removeSub(ch chan signingkeys.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		// Close already drained and closed every channel; nothing to do.
		return
	}
	for i, c := range r.subs {
		if c == ch {
			r.subs = append(r.subs[:i], r.subs[i+1:]...)
			close(ch)
			return
		}
	}
}

// cloneAnnouncement returns a defensive copy so a caller mutating its
// supplied announcement (or a value returned from List) can't corrupt the
// registry's stored state. core.JWK is a flat value struct, so a fresh
// slice with copied elements is a full deep copy.
func cloneAnnouncement(ann signingkeys.Announcement) signingkeys.Announcement {
	cp := ann
	if ann.Keys != nil {
		cp.Keys = append([]core.JWK(nil), ann.Keys...)
	}
	return cp
}
