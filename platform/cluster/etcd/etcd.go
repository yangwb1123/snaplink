// Package etcd implements cluster.Bus against etcd v3, giving the
// invalidation bus genuine cross-process reach (the memory peer only
// fans out within one process).
//
// A coordination Event is transient, not durable state, so the wire
// shape is deliberately light: Publish writes the JSON-encoded Event to
// a unique key under <Prefix> with a short lease, and Subscribe runs an
// etcd prefix WATCH translating each PUT back into an Event. The lease
// self-cleans published keys so they don't accumulate; the lease-expiry
// DELETE that follows is ignored (only PUTs carry a payload). A WATCH is
// established at the current revision, so a subscriber never replays
// Events published before it joined — exactly the best-effort,
// fall-back-to-TTL contract cluster.Bus promises.
package etcd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/tracing"
	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.opentelemetry.io/otel/attribute"
)

// Defaults applied when a corresponding Config field is zero.
const (
	DefaultPrefix      = "/snaplink/cluster/bus"
	DefaultDialTimeout = 5 * time.Second
	// DefaultEventTTL bounds how long a published key lingers before its
	// lease expires and etcd reaps it. Short because the Event is consumed
	// the instant it is written; the TTL only guards against key buildup
	// if a publisher races etcd reaping.
	DefaultEventTTL = 10 * time.Second
)

// Config configures the etcd Bus.
type Config struct {
	Endpoints   []string      // etcd cluster endpoints, e.g. ["localhost:2379"]
	Prefix      string        // key namespace; defaults to DefaultPrefix
	DialTimeout time.Duration // connect timeout; defaults to DefaultDialTimeout
	EventTTL    time.Duration // published-key lease TTL; defaults to DefaultEventTTL
	Username    string
	Password    string
}

// Bus is the etcd-backed cluster.Bus. The caller owns the lifecycle —
// call Close to release the connection.
type Bus struct {
	client   *clientv3.Client
	prefix   string
	eventTTL time.Duration

	closeOnce sync.Once
}

var _ cluster.Bus = (*Bus)(nil)

// New connects to etcd and returns a Bus.
func New(cfg Config) (*Bus, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("cluster/etcd: at least one endpoint required")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	if cfg.Prefix == "" {
		cfg.Prefix = DefaultPrefix
	}
	if cfg.EventTTL <= 0 {
		cfg.EventTTL = DefaultEventTTL
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.DialTimeout,
		Username:    cfg.Username,
		Password:    cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("cluster/etcd: dial: %w", err)
	}
	return &Bus{client: cli, prefix: cfg.Prefix, eventTTL: cfg.EventTTL}, nil
}

// NewWithClient wraps an existing etcd client (shared-connection
// deployments, tests). The caller retains ownership of the client.
func NewWithClient(cli *clientv3.Client, cfg Config) *Bus {
	if cfg.Prefix == "" {
		cfg.Prefix = DefaultPrefix
	}
	if cfg.EventTTL <= 0 {
		cfg.EventTTL = DefaultEventTTL
	}
	return &Bus{client: cli, prefix: cfg.Prefix, eventTTL: cfg.EventTTL}
}

// Publish writes evt to a unique short-lived key under the prefix. Unlike
// the memory peer this is a real network round-trip (Grant + Put), so the
// span it starts is the one genuinely worth timing in a trace backend.
func (b *Bus) Publish(ctx context.Context, evt cluster.Event) error {
	ctx, span := tracing.StartSpan(ctx, "cluster.bus.publish")
	defer span.End()
	span.SetAttributes(
		attribute.String("cluster.bus.backend", "etcd"),
		attribute.String("cluster.bus.kind", string(evt.Kind)),
	)

	body, err := json.Marshal(evt)
	if err != nil {
		err = fmt.Errorf("cluster/etcd: marshal event: %w", err)
		tracing.SetError(span, err)
		return err
	}
	lease, err := b.client.Grant(ctx, int64(b.eventTTL.Seconds()))
	if err != nil {
		err = fmt.Errorf("cluster/etcd: grant lease: %w", err)
		tracing.SetError(span, err)
		return err
	}
	key, err := b.eventKey()
	if err != nil {
		tracing.SetError(span, err)
		return err
	}
	if _, err := b.client.Put(ctx, key, string(body), clientv3.WithLease(lease.ID)); err != nil {
		err = fmt.Errorf("cluster/etcd: put event: %w", err)
		tracing.SetError(span, err)
		return err
	}
	return nil
}

// Subscribe runs a prefix WATCH and emits one Event per published PUT.
func (b *Bus) Subscribe(ctx context.Context) (<-chan cluster.Event, error) {
	_, span := tracing.StartSpan(ctx, "cluster.bus.subscribe")
	defer span.End()
	span.SetAttributes(attribute.String("cluster.bus.backend", "etcd"))

	out := make(chan cluster.Event, 16)
	wch := b.client.Watch(ctx, b.prefix, clientv3.WithPrefix())
	go func() {
		defer close(out)
		for resp := range wch {
			if err := resp.Err(); err != nil {
				return
			}
			for _, ev := range resp.Events {
				evt, ok := decodeEvent(ev)
				if !ok {
					continue
				}
				select {
				case out <- evt:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

// Close releases the etcd connection. Idempotent.
func (b *Bus) Close() error {
	var err error
	b.closeOnce.Do(func() { err = b.client.Close() })
	return err
}

// eventKey builds a collision-resistant, time-ordered key under the
// prefix. The nanosecond prefix keeps keys roughly chronological; the
// random suffix prevents collisions between same-instant publishes.
func (b *Bus) eventKey() (string, error) {
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("cluster/etcd: key entropy: %w", err)
	}
	return path.Join(b.prefix, fmt.Sprintf("%d-%s", time.Now().UnixNano(), hex.EncodeToString(buf[:]))), nil
}

// decodeEvent translates an etcd watch event into a cluster.Event. Only
// PUTs carry a payload; the lease-expiry DELETE (and any undecodable
// value) is reported as not-ok so the caller skips it.
func decodeEvent(ev *clientv3.Event) (cluster.Event, bool) {
	if ev.Type != mvccpb.PUT || ev.Kv == nil {
		return cluster.Event{}, false
	}
	var evt cluster.Event
	if err := json.Unmarshal(ev.Kv.Value, &evt); err != nil {
		return cluster.Event{}, false
	}
	return evt, true
}
