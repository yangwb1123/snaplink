// Package memory is the in-process [cluster.Bus] peer. It fans Events to
// every Subscriber in the same process — which is all a single-node
// deployment needs, and the building block multi-process backends (etcd,
// redis) layer onto. Mirrors the best-effort broadcast semantics of
// registry/memory: a slow subscriber's Event is dropped rather than
// allowed to block the publisher.
package memory

import (
	"context"
	"errors"
	"sync"

	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// ErrClosed is returned by Publish/Subscribe after the Bus is closed.
var ErrClosed = errors.New("cluster/memory: bus closed")

// Bus is an in-process fan-out implementation of cluster.Bus.
type Bus struct {
	mu        sync.RWMutex
	subs      []chan cluster.Event
	closed    bool
	done      chan struct{}
	closeOnce sync.Once
}

var _ cluster.Bus = (*Bus)(nil)

// New returns a ready in-process Bus.
func New() *Bus {
	return &Bus{done: make(chan struct{})}
}

// Publish broadcasts evt to every current subscriber, best-effort:
// a subscriber whose buffer is full is skipped (it will fall back to its
// cache TTL), never blocked on.
//
// The publish call runs synchronously on the caller's goroutine (often the
// admin-mutation request path, sometimes a background self-heal loop), so
// the span it starts is parented on ctx directly — no detach needed, unlike
// the genuinely async worker paths (audit delivery, CAEP SET push).
func (b *Bus) Publish(ctx context.Context, evt cluster.Event) error {
	_, span := tracing.StartSpan(ctx, "cluster.bus.publish")
	defer span.End()
	span.SetAttributes(
		attribute.String("cluster.bus.backend", "memory"),
		attribute.String("cluster.bus.kind", string(evt.Kind)),
	)

	// Hold the read lock across BOTH the closed-check AND the sends. Close and
	// removeSub close subscriber channels only under the write lock, so the
	// read lock here makes "send on ch" mutually exclusive with "close(ch)" —
	// without it, a non-blocking send racing a concurrent close panics (the
	// default: only guards a FULL channel, never a CLOSED one).
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		tracing.SetError(span, ErrClosed)
		return ErrClosed
	}
	for _, ch := range b.subs {
		select {
		case ch <- evt:
		default:
			// Slow consumer — drop. Invalidation is idempotent and the
			// subscriber's TTL is the safety net.
		}
	}
	return nil
}

// Subscribe registers a new stream, removed automatically when ctx is
// cancelled or the Bus closes.
func (b *Bus) Subscribe(ctx context.Context) (<-chan cluster.Event, error) {
	_, span := tracing.StartSpan(ctx, "cluster.bus.subscribe")
	defer span.End()
	span.SetAttributes(attribute.String("cluster.bus.backend", "memory"))

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		tracing.SetError(span, ErrClosed)
		return nil, ErrClosed
	}
	ch := make(chan cluster.Event, 16)
	b.subs = append(b.subs, ch)
	b.mu.Unlock()

	go func() {
		select {
		case <-ctx.Done():
		case <-b.done:
		}
		b.removeSub(ch)
	}()
	return ch, nil
}

// Close stops the Bus and closes every subscriber stream. Idempotent.
func (b *Bus) Close() error {
	b.closeOnce.Do(func() {
		b.mu.Lock()
		b.closed = true
		close(b.done)
		for _, ch := range b.subs {
			close(ch)
		}
		b.subs = nil
		b.mu.Unlock()
	})
	return nil
}

func (b *Bus) removeSub(ch chan cluster.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	for i, c := range b.subs {
		if c == ch {
			b.subs = append(b.subs[:i], b.subs[i+1:]...)
			close(ch)
			return
		}
	}
}
