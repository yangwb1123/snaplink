package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel/attribute"

	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/tracing"
)

// DefaultBusChannel is the pub/sub channel a redis-backed invalidation bus
// publishes to unless WithChannel overrides it. Namespaced so the channel
// stays visually distinct from keyspace keys and does not collide with other
// applications sharing the instance; it deliberately carries no {hashTag}
// because pub/sub channels are NOT part of the Redis keyspace and are NOT
// slot-routed on Redis Cluster (a PUBLISH fans out to every node).
const DefaultBusChannel = "snaplink:cluster:bus"

// subscribeChannelBuffer matches the memory/etcd/mqtt peers' out-channel
// size: generous enough that a burst of Events does not trip the
// slow-consumer drop under ordinary load. A full buffer drops the event
// rather than blocking the pub/sub receive loop — the SPI's TTL fallback is
// the safety net — and is never unbounded (a stuck consumer must not grow
// memory without bound).
const subscribeChannelBuffer = 16

const (
	// busSubscribeTimeout bounds the synchronous subscribe-ack wait in
	// Subscribe: a Redis that accepts the connection but never acks the
	// SUBSCRIBE must surface as a boot error, not a silent hang.
	busSubscribeTimeout = 10 * time.Second

	// busReceiveIdle bounds the subscriber's read between messages. An idle
	// timeout triggers a PING round-trip liveness probe (see livenessProbe)
	// instead of ending the subscription, and also bounds how long a blocked
	// read can outlive a caller ctx cancellation.
	busReceiveIdle = 3 * time.Second

	// busProbeTimeout bounds the liveness probe's PING round-trip.
	busProbeTimeout = 3 * time.Second
)

// ErrClosed is returned by Publish/Subscribe once Close has been called.
var ErrClosed = errors.New("redis: cluster bus closed")

// busEnvelope is the wire form of one Event: the cluster.Event fields inline
// (so the JSON is {"kind":...,"key":...,"payload":...,"instance":...}) plus an
// additive, optional instance field carrying the publisher's self-skip id.
// Version-safe in both directions: an older peer that predates the field
// ignores it (encoding/json skips unknown fields), and a newer peer treats its
// absence as self-skip off.
type busEnvelope struct {
	cluster.Event
	Instance string `json:"instance,omitempty"`
}

// BusOption configures a Bus. Options are applied in order; unset options use
// the documented defaults.
type BusOption func(*busOptions)

type busOptions struct {
	channel    string
	instanceID string
}

// WithChannel namespaces this Bus's pub/sub channel. Empty selects the
// default (snaplink:cluster:bus), so multiple issuers sharing one logical
// Redis can each publish on their own channel by setting a distinct name.
func WithChannel(channel string) BusOption {
	return func(o *busOptions) { o.channel = channel }
}

// WithInstanceID arms the publisher self-skip: events published by THIS Bus
// are filtered out of its own subscription stream. A node already invalidates
// its own caches in-process at the mutation site, so re-applying its own
// events is wasted work. Filtering is strictly by exact own-ID match — a
// peer's event is never suppressed — and the filter is purely advisory:
// invalidation is idempotent, so receiving your own event is always safe.
// Empty (the default) disables self-skip, keeping the wire behavior
// byte-identical to the memory/etcd backends. The id MUST be unique per
// process: two replicas sharing one id would suppress each other's events.
func WithInstanceID(id string) BusOption {
	return func(o *busOptions) { o.instanceID = id }
}

// Bus is the Redis pub/sub implementation of cluster.Bus. It publishes one
// JSON envelope per Event on a single channel and forwards every received
// message to each subscription's buffered out-channel.
//
// The transport is deliberately best-effort, matching the SPI and the
// memory/etcd/mqtt peers: no persistence, no replay, no ordering, no
// sequence numbers. A dropped Event degrades a replica to its existing TTL
// fallback; the recovery loop's re-seed (cache flush + revocation deny-set
// re-seed) repairs whatever a lost subscription missed.
//
// The Bus never closes the shared rdb client — the bootstrap layer owns it —
// and adds no readiness check of its own (the existing redis readycheck
// covers transport; a lost subscription surfaces via the closed stream, which
// InvalidationBusReady covers).
type Bus struct {
	rdb        goredis.UniversalClient
	channel    string
	instanceID string

	// mu guards closed and the live-subscription set. Publish/Subscribe/Close
	// are safe for concurrent use; the set lets Close terminate in-flight
	// subscription streams instead of leaking a registration per resubscribe
	// cycle for the life of the process.
	mu     sync.Mutex
	closed bool
	subs   map[*goredis.PubSub]struct{}
}

var _ cluster.Bus = (*Bus)(nil)

// NewBus returns a ready Bus over the shared client. rdb may be nil only in
// error: the constructor is infallible, so a nil client yields a Bus whose
// first Publish/Subscribe returns a descriptive error instead of panicking
// (the build layer rejects backend=redis without a redis block before
// construction). NewBus does not dial.
func NewBus(rdb goredis.UniversalClient, opts ...BusOption) *Bus {
	o := busOptions{}
	for _, opt := range opts {
		if opt != nil {
			opt(&o)
		}
	}
	if o.channel == "" {
		o.channel = DefaultBusChannel
	}
	return &Bus{
		rdb:        rdb,
		channel:    o.channel,
		instanceID: o.instanceID,
		subs:       make(map[*goredis.PubSub]struct{}),
	}
}

// Channel returns the pub/sub channel this Bus publishes to (the default
// when WithChannel was not set).
func (b *Bus) Channel() string { return b.channel }

// InstanceID returns the self-skip identity ("" when self-skip is off).
func (b *Bus) InstanceID() string { return b.instanceID }

// Publish marshals evt into the wire envelope and PUBLISHes it on the
// channel. Fire-and-forget is the caller's problem, not the Bus's: the SPI
// says Publish returns an error only for transport-level failures, and
// callers log-and-continue because the local mutation already succeeded.
// Returns ErrClosed after Close.
func (b *Bus) Publish(ctx context.Context, evt cluster.Event) error {
	_, span := tracing.StartSpan(ctx, "cluster.bus.publish")
	defer span.End()
	span.SetAttributes(
		attribute.String("cluster.bus.backend", "redis"),
		attribute.String("cluster.bus.kind", string(evt.Kind)),
	)

	if err := b.openErr(); err != nil {
		tracing.SetError(span, err)
		return err
	}
	if b.rdb == nil {
		err := errors.New("redis: cluster bus has no client (nil rdb)")
		tracing.SetError(span, err)
		return err
	}
	body, err := json.Marshal(busEnvelope{Event: evt, Instance: b.instanceID})
	if err != nil {
		err = fmt.Errorf("redis: marshal event: %w", err)
		tracing.SetError(span, err)
		return err
	}
	if err := b.rdb.Publish(ctx, b.channel, body).Err(); err != nil {
		err = fmt.Errorf("redis: publish: %w", err)
		tracing.SetError(span, err)
		return err
	}
	return nil
}

// Subscribe opens a pub/sub subscription and returns a receive-only stream of
// decoded Events. The stream closes exactly when (a) ctx is cancelled, (b)
// Close was called, or (c) the pub/sub connection is lost — a lost
// subscription must look exactly like a closed channel, never like a healthy
// one, because that closure is the single signal the self-heal loop
// (runInvalidationBus) uses to degrade, resubscribe, and re-seed. The bus
// performs no internal reconnect: resubscription is the recovery loop's job,
// so subscribe-before-reseed ordering is never raced by the transport.
//
// The initial subscribe is synchronous: a dial/SUBSCRIBE failure returns an
// error here, so a boot-time transport fault fails boot (the StartInvalidationBus
// contract) instead of surfacing as an async channel close.
func (b *Bus) Subscribe(ctx context.Context) (<-chan cluster.Event, error) {
	_, span := tracing.StartSpan(ctx, "cluster.bus.subscribe")
	defer span.End()
	span.SetAttributes(attribute.String("cluster.bus.backend", "redis"))

	if err := b.openErr(); err != nil {
		tracing.SetError(span, err)
		return nil, err
	}
	if b.rdb == nil {
		err := errors.New("redis: cluster bus has no client (nil rdb)")
		tracing.SetError(span, err)
		return nil, err
	}

	ps := b.rdb.Subscribe(ctx, b.channel)
	// Consume the synchronous subscribe ack so a dial/SUBSCRIBE failure
	// surfaces HERE instead of as an async channel close.
	if _, err := ps.ReceiveTimeout(ctx, busSubscribeTimeout); err != nil {
		_ = ps.Close()
		err = fmt.Errorf("redis: subscribe %q: %w", b.channel, err)
		tracing.SetError(span, err)
		return nil, err
	}

	out := make(chan cluster.Event, subscribeChannelBuffer)
	if err := b.register(ps); err != nil { // Close raced the ack wait
		_ = ps.Close()
		tracing.SetError(span, err)
		return nil, err
	}
	go b.subscriber(ctx, ps, out)
	return out, nil
}

// Close marks the Bus closed — subsequent Publish/Subscribe calls return
// ErrClosed — and closes every live subscription's pub/sub connection so an
// in-flight Subscribe stream terminates. Idempotent. The shared rdb client is
// NOT closed (the bootstrap layer owns it).
func (b *Bus) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	subs := make([]*goredis.PubSub, 0, len(b.subs))
	for ps := range b.subs {
		subs = append(subs, ps)
	}
	b.subs = make(map[*goredis.PubSub]struct{})
	b.mu.Unlock()

	// Closing each pub/sub connection terminates its blocked Receive, which
	// closes that subscription's out channel — the same "lost subscription
	// looks exactly like a closed channel" signal the recovery loop uses.
	for _, ps := range subs {
		_ = ps.Close()
	}
	return nil
}

// subscriber drains ps for the life of the subscription and closes out
// exactly once on every exit path (ctx cancel, Bus close, or transport loss).
// It consumes the go-redis receive channel exactly once — no internal
// reconnect, so closure can never be masked by a retry loop.
func (b *Bus) subscriber(ctx context.Context, ps *goredis.PubSub, out chan<- cluster.Event) {
	defer close(out)
	defer func() { _ = ps.Close() }()
	defer b.unregister(ps)
	for {
		if ctx.Err() != nil {
			return
		}
		msg, err := ps.ReceiveTimeout(ctx, busReceiveIdle)
		if err != nil {
			if b.retryAfterReceiveError(ctx, ps, out, err) {
				continue
			}
			return
		}
		if m, ok := msg.(*goredis.Message); ok {
			b.forward(m, out)
		}
	}
}

// retryAfterReceiveError classifies a Receive error. It returns true only for
// the idle-probe-success case; everything else ends the subscription: a
// cancelled ctx is the clean-shutdown path, and a transport loss or closed
// pool under a live ctx is the degraded signal runInvalidationBus needs.
func (b *Bus) retryAfterReceiveError(ctx context.Context, ps *goredis.PubSub, out chan<- cluster.Event, err error) bool {
	if ctx.Err() != nil {
		return false // caller cancelled — clean shutdown, not a degraded signal
	}
	if !isIdleTimeout(err) {
		return false // transport loss or pool closed — the degraded signal
	}
	return b.livenessProbe(ctx, ps, out)
}

// livenessProbe distinguishes an idle-but-healthy connection from a silently
// dead one (a half-open socket delivers no read error until something is
// written): send a PING and require a PONG (or any traffic) round-trip on the
// same connection. go-redis's own Channel() health check does the same ping
// cadence but never closes on failure; this probe closes instead, keeping the
// "lost subscription = closed channel" invariant.
func (b *Bus) livenessProbe(ctx context.Context, ps *goredis.PubSub, out chan<- cluster.Event) bool {
	probeCtx, cancel := context.WithTimeout(ctx, busProbeTimeout)
	defer cancel()
	if err := ps.Ping(probeCtx); err != nil {
		return false
	}
	msg, err := ps.ReceiveTimeout(probeCtx, busProbeTimeout)
	if err != nil {
		return false
	}
	if m, ok := msg.(*goredis.Message); ok {
		b.forward(m, out)
	}
	return true
}

// forward decodes one pub/sub message into a cluster.Event and delivers it to
// out. Undecodable payloads are dropped — never propagated as events (a
// garbage message must not crash the consumer loop; mirrors the mqtt/etcd
// decodeEvent precedent) — and a full out buffer drops the event rather than
// blocking the receive loop.
func (b *Bus) forward(m *goredis.Message, out chan<- cluster.Event) {
	var env busEnvelope
	if err := json.Unmarshal([]byte(m.Payload), &env); err != nil {
		return // garbage payload: dropped, never propagated
	}
	if b.instanceID != "" && env.Instance == b.instanceID {
		return // own event — the local mutation already invalidated in-process
	}
	select {
	case out <- env.Event:
	default:
		// Slow consumer: drop rather than block the pub/sub receive loop (the
		// SPI's TTL fallback is the safety net).
	}
}

// openErr returns ErrClosed after Close. The closed flag is mutex-guarded so
// Publish/Subscribe are safe for concurrent use with Close.
func (b *Bus) openErr() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	return nil
}

// register adds ps to the live-subscription set, refusing after Close so a
// Subscribe racing Close never leaves a leaked registration.
func (b *Bus) register(ps *goredis.PubSub) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	b.subs[ps] = struct{}{}
	return nil
}

func (b *Bus) unregister(ps *goredis.PubSub) {
	b.mu.Lock()
	delete(b.subs, ps)
	b.mu.Unlock()
}

// isIdleTimeout reports whether err is a read-idle timeout on a live context,
// as opposed to a ctx cancellation or a transport failure. go-redis returns
// the conn's net timeout error when its read deadline expires.
func isIdleTimeout(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
