// Package sse fans redacted server events out to Server-Sent-Events
// subscribers (the admin console's EventSource). The Broker is
// transport-agnostic: it assigns monotonic event ids, keeps a bounded
// replay ring so a reconnecting client can catch up from its
// Last-Event-ID, and NEVER blocks a publisher — a subscriber whose
// buffer is full is evicted instead (the SSE client auto-reconnects
// and replays what it missed from the ring). Delivery is therefore
// at-least-once within the ring window; consumers must treat events
// as idempotent notifications and fetch authoritative detail from the
// admin audit query API.
package sse

import (
	"errors"
	"sync"
)

// ErrMaxSubscribers is returned by Subscribe when the broker already
// serves MaxSubscribers live connections. The HTTP handler maps it to
// 503 so the admin console backs off and retries.
var ErrMaxSubscribers = errors.New("sse: max subscribers reached")

// ErrBrokerClosed is returned by Subscribe after Close — the server is
// shutting down and no new streams may attach.
var ErrBrokerClosed = errors.New("sse: broker closed")

// Defaults applied by NewBroker for zero Options fields. Sized for an
// admin-console audience (tens of dashboards), not a public fan-out.
const (
	DefaultSubscriberBuffer = 64
	DefaultReplayBuffer     = 256
	DefaultMaxSubscribers   = 32
)

// Options bounds the broker's memory: per-subscriber channel capacity,
// replay ring capacity, and the live-subscriber cap. Zero values fall
// back to the package defaults.
type Options struct {
	SubscriberBuffer int
	ReplayBuffer     int
	MaxSubscribers   int
}

// Event is one broker message. ID is assigned by Publish (monotonic,
// process-local — it doubles as the SSE `id:` field so Last-Event-ID
// comparisons are a plain integer order). Data is the pre-marshaled
// JSON payload written verbatim into the `data:` line.
type Event struct {
	ID       uint64
	Type     string
	TenantID string
	Data     []byte
}

// Filter restricts which events a subscriber receives. Zero value
// matches everything.
type Filter struct {
	Types    []string // empty = all types
	TenantID string   // empty = all tenants
}

func (f Filter) matches(ev Event) bool {
	if f.TenantID != "" && ev.TenantID != f.TenantID {
		return false
	}
	if len(f.Types) == 0 {
		return true
	}
	for _, t := range f.Types {
		if t == ev.Type {
			return true
		}
	}
	return false
}

// Broker fans published events out to live subscribers and retains the
// most recent ReplayBuffer events for Last-Event-ID reconnects. Safe
// for concurrent use.
type Broker struct {
	mu     sync.Mutex
	opts   Options
	nextID uint64
	ring   []Event // circular once len == opts.ReplayBuffer
	ringAt int     // oldest entry (== next overwrite slot) once circular
	subs   map[*Subscriber]struct{}
	closed bool
}

// NewBroker constructs a Broker, applying package defaults for any
// zero (or negative) Options field.
func NewBroker(opts Options) *Broker {
	if opts.SubscriberBuffer <= 0 {
		opts.SubscriberBuffer = DefaultSubscriberBuffer
	}
	if opts.ReplayBuffer <= 0 {
		opts.ReplayBuffer = DefaultReplayBuffer
	}
	if opts.MaxSubscribers <= 0 {
		opts.MaxSubscribers = DefaultMaxSubscribers
	}
	return &Broker{opts: opts, subs: map[*Subscriber]struct{}{}}
}

// Publish assigns the next monotonic id to ev, appends it to the
// replay ring, and fans it out to every matching subscriber. A
// subscriber whose buffer is full is evicted (channel closed) rather
// than blocking the publisher — audit recording sits upstream and must
// never stall on a slow admin console. Returns the assigned id; no-op
// (id unassigned) after Close.
func (b *Broker) Publish(ev Event) uint64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return b.nextID
	}
	b.nextID++
	ev.ID = b.nextID
	b.appendRingLocked(ev)
	for s := range b.subs {
		if !s.filter.matches(ev) {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			b.removeLocked(s)
		}
	}
	return ev.ID
}

// Subscribe registers a live subscriber. The returned Subscriber's
// channel is closed by the broker on eviction (slow consumer) or
// Close; the caller MUST call Subscriber.Close when done.
func (b *Broker) Subscribe(f Filter) (*Subscriber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil, ErrBrokerClosed
	}
	if len(b.subs) >= b.opts.MaxSubscribers {
		return nil, ErrMaxSubscribers
	}
	s := &Subscriber{ch: make(chan Event, b.opts.SubscriberBuffer), filter: f, b: b}
	b.subs[s] = struct{}{}
	return s, nil
}

// Replay returns the ring-buffered events with id > afterID that match
// f, oldest first. Events older than the ring window are gone — the
// reconnecting client silently skips the gap (at-least-once within the
// window, by design).
func (b *Broker) Replay(afterID uint64, f Filter) []Event {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(b.ring)
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		// ringAt is 0 while the ring is still filling, so this walks
		// oldest-to-newest in both the filling and circular phases.
		ev := b.ring[(b.ringAt+i)%n]
		if ev.ID > afterID && f.matches(ev) {
			out = append(out, ev)
		}
	}
	return out
}

// Close evicts every subscriber (closing their channels so streaming
// handlers unblock and return) and refuses new subscriptions. Called
// during server shutdown BEFORE the graceful HTTP drain — otherwise
// idle EventSource connections would pin Shutdown to its full deadline.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	for s := range b.subs {
		b.removeLocked(s)
	}
}

func (b *Broker) appendRingLocked(ev Event) {
	if len(b.ring) < b.opts.ReplayBuffer {
		b.ring = append(b.ring, ev)
		return
	}
	b.ring[b.ringAt] = ev
	b.ringAt = (b.ringAt + 1) % len(b.ring)
}

// removeLocked is the single place a subscriber channel is closed; the
// map-membership guard makes eviction and Subscriber.Close idempotent
// against each other (no double-close race).
func (b *Broker) removeLocked(s *Subscriber) {
	if _, ok := b.subs[s]; !ok {
		return
	}
	delete(b.subs, s)
	close(s.ch)
}

func (b *Broker) remove(s *Subscriber) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.removeLocked(s)
}

// Subscriber is one live SSE connection's receive side.
type Subscriber struct {
	ch     chan Event
	filter Filter
	b      *Broker
}

// C is the receive channel. Closed by the broker on eviction or
// shutdown — a closed channel tells the handler to end the response so
// the client reconnects with Last-Event-ID.
func (s *Subscriber) C() <-chan Event { return s.ch }

// Filter returns the filter fixed at Subscribe time (reused by the
// handler for Last-Event-ID replay so both paths select identically).
func (s *Subscriber) Filter() Filter { return s.filter }

// Close detaches the subscriber. Safe to call after eviction.
func (s *Subscriber) Close() { s.b.remove(s) }
