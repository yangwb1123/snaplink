// Package etcd implements signingkeys.Registry against etcd v3, giving the
// leaderless signing-key aggregation genuine cross-process reach (the memory
// peer only fans announcements within one process).
//
// Each replica's announcement becomes a single key under <Prefix>/<ReplicaID>,
// carrying the JSON-encoded signingkeys.Announcement (PUBLIC keys only — no
// private material ever touches the wire). Lifecycle is bound to an etcd lease
// granted from the announcement's LeaseSeconds (or DefaultLeaseTTL); a
// background KeepAlive renews that lease for as long as the replica is alive,
// so a live replica's keys never expire out from under its peers — mirroring
// the lease + KeepAlive pattern registry/etcd uses to keep a service alive.
// When the replica process dies its KeepAlive stops, the lease expires, and
// etcd reaps the key: the resulting DELETE becomes an EventKeysRemoved so
// every peer drops the departed replica's keys.
//
// This backend is PURE TRANSPORT: it marshals and ships core.JWK announcements
// and never inspects, validates, or otherwise touches key material. All key
// validation (on-curve, modulus, exponent, alg-match) happens in the Server's
// adoptPeerKey decode gates after an announcement is delivered — the registry
// only moves bytes. Re-Publish replaces a replica's prior announcement
// wholesale under a fresh lease, so a rotation is reflected by the new
// announcement and the old lease is revoked.
package etcd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"sync"
	"time"

	mvccpb "go.etcd.io/etcd/api/v3/mvccpb"
	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/snaplink/sso/signingkeys"
)

// Defaults applied when a corresponding Config field (or the announcement's
// LeaseSeconds) is zero.
const (
	DefaultPrefix      = "/snaplink/signingkeys"
	DefaultDialTimeout = 5 * time.Second
	// DefaultLeaseTTL bounds how long a replica's published announcement
	// survives without renewal. A live replica's lease is kept alive by a
	// background KeepAlive, so this only governs how fast a crashed replica's
	// keys drop from peers' verify-sets. Matches the announcer's default
	// (sso.DefaultSigningKeyLeaseTTL) so config and backend agree.
	DefaultLeaseTTL = 5 * time.Minute
)

// Config configures the etcd Registry. The fields mirror cluster/etcd and
// registry/etcd for operator familiarity.
type Config struct {
	Endpoints   []string      // etcd cluster endpoints, e.g. ["localhost:2379"]
	Prefix      string        // key namespace; defaults to DefaultPrefix
	DialTimeout time.Duration // connect timeout; defaults to DefaultDialTimeout
	LeaseTTL    time.Duration // fallback lease when an announcement's LeaseSeconds is 0
	Username    string
	Password    string
}

// Registry is the etcd-backed signingkeys.Registry. The caller owns the
// lifecycle — call Close to release the connection and revoke the outstanding
// announcement lease.
type Registry struct {
	client     *clientv3.Client
	prefix     string
	defaultTTL time.Duration

	mu     sync.Mutex
	lease  clientv3.LeaseID   // this replica's current announcement lease (0 = none)
	cancel context.CancelFunc // cancels the current KeepAlive (nil = none)
	closed bool

	closeOnce sync.Once
}

var _ signingkeys.Registry = (*Registry)(nil)

// New connects to etcd and returns a Registry.
func New(cfg Config) (*Registry, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("signingkeys/etcd: at least one endpoint required")
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = DefaultDialTimeout
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: cfg.DialTimeout,
		Username:    cfg.Username,
		Password:    cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("signingkeys/etcd: dial: %w", err)
	}
	return NewWithClient(cli, cfg), nil
}

// NewWithClient wraps an existing etcd client (shared-connection deployments,
// tests). Ownership of the client transfers to the Registry — Close closes it.
func NewWithClient(cli *clientv3.Client, cfg Config) *Registry {
	prefix := cfg.Prefix
	if prefix == "" {
		prefix = DefaultPrefix
	}
	ttl := cfg.LeaseTTL
	if ttl <= 0 {
		ttl = DefaultLeaseTTL
	}
	return &Registry{client: cli, prefix: prefix, defaultTTL: ttl}
}

// Publish writes ann under <prefix>/<ReplicaID> with a fresh lease and keeps
// that lease alive for the life of the process. A re-Publish (startup, then
// each rotation) replaces the prior announcement wholesale: it cancels the old
// KeepAlive and revokes the old lease, then puts the new announcement under a
// new lease — so a rotated kid propagates and a retired kid drops from peers.
func (r *Registry) Publish(ctx context.Context, ann signingkeys.Announcement) error {
	if ann.ReplicaID == "" {
		return errors.New("signingkeys/etcd: announcement replica_id required")
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return errors.New("signingkeys/etcd: registry closed")
	}
	r.mu.Unlock()

	body, err := encodeAnnouncement(ann)
	if err != nil {
		return fmt.Errorf("signingkeys/etcd: marshal announcement: %w", err)
	}

	ttlSec := r.leaseSeconds(ann.LeaseSeconds)
	lease, err := r.client.Grant(ctx, ttlSec)
	if err != nil {
		return fmt.Errorf("signingkeys/etcd: grant lease: %w", err)
	}
	if _, err := r.client.Put(ctx, r.replicaKey(ann.ReplicaID), string(body),
		clientv3.WithLease(lease.ID)); err != nil {
		return fmt.Errorf("signingkeys/etcd: put announcement: %w", err)
	}

	// KeepAlive runs off a background context so it outlives the (request-
	// scoped) ctx of this Publish — the announcement must stay live until the
	// next Publish or Close, not just until ctx returns.
	keepCtx, cancel := context.WithCancel(context.Background())
	keepAlive, err := r.client.KeepAlive(keepCtx, lease.ID)
	if err != nil {
		cancel()
		return fmt.Errorf("signingkeys/etcd: keepalive: %w", err)
	}
	go drainKeepAlive(keepAlive)

	r.mu.Lock()
	oldCancel, oldLease := r.cancel, r.lease
	r.cancel, r.lease = cancel, lease.ID
	r.mu.Unlock()

	// Tear down the prior announcement's KeepAlive + lease so the old key
	// doesn't linger under its own lease alongside the new one.
	if oldCancel != nil {
		oldCancel()
	}
	if oldLease != 0 {
		_, _ = r.client.Revoke(ctx, oldLease)
	}
	return nil
}

// List returns every currently live replica's announcement (the prefix
// snapshot), skipping any value that fails to decode rather than failing the
// whole call — one corrupt entry must not blind a replica to its peers.
func (r *Registry) List(ctx context.Context) ([]signingkeys.Announcement, error) {
	resp, err := r.client.Get(ctx, r.namespace(), clientv3.WithPrefix())
	if err != nil {
		return nil, fmt.Errorf("signingkeys/etcd: get: %w", err)
	}
	out := make([]signingkeys.Announcement, 0, resp.Count)
	for _, kv := range resp.Kvs {
		ann, ok := decodeAnnouncement(kv.Value)
		if !ok {
			continue
		}
		out = append(out, ann)
	}
	return out, nil
}

// Subscribe runs a prefix WATCH and emits one Event per change. A PUT becomes
// EventKeysUpserted carrying the decoded announcement; a DELETE (key removed
// or lease expired) becomes EventKeysRemoved carrying only the ReplicaID
// derived from the key path (a DELETE carries no value, and the Server's
// dropAllAdopted needs only the ReplicaID). The channel closes on ctx cancel,
// Close, or a fatal watch error.
func (r *Registry) Subscribe(ctx context.Context) (<-chan signingkeys.Event, error) {
	out := make(chan signingkeys.Event, 16)
	wch := r.client.Watch(ctx, r.namespace(), clientv3.WithPrefix())
	go func() {
		defer close(out)
		for resp := range wch {
			if err := resp.Err(); err != nil {
				return
			}
			for _, ev := range resp.Events {
				evt, ok := decodeWatchEvent(r.prefix, ev)
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

// Close revokes this replica's announcement lease, stops its KeepAlive, and
// closes the etcd client. Idempotent.
func (r *Registry) Close() error {
	var err error
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		cancel, lease := r.cancel, r.lease
		r.cancel, r.lease = nil, 0
		r.mu.Unlock()

		if cancel != nil {
			cancel()
		}
		if lease != 0 {
			revokeCtx, c := context.WithTimeout(context.Background(), 2*time.Second)
			_, _ = r.client.Revoke(revokeCtx, lease)
			c()
		}
		err = r.client.Close()
	})
	return err
}

// leaseSeconds resolves an announcement's requested LeaseSeconds against the
// configured default, with a floor of 1s (etcd rejects a non-positive TTL).
func (r *Registry) leaseSeconds(reqSeconds int64) int64 {
	if reqSeconds > 0 {
		return reqSeconds
	}
	if s := int64(r.defaultTTL.Seconds()); s > 0 {
		return s
	}
	return 1
}

// replicaKey is the etcd key for one replica's announcement.
func (r *Registry) replicaKey(replicaID string) string {
	return path.Join(r.prefix, replicaID)
}

// namespace is the prefix that contains every replica's announcement.
// The trailing slash makes WithPrefix() match exactly this namespace.
func (r *Registry) namespace() string {
	return r.prefix + "/"
}

// encodeAnnouncement JSON-marshals an announcement for the wire. Pure so it is
// unit-testable without etcd.
func encodeAnnouncement(ann signingkeys.Announcement) ([]byte, error) {
	return json.Marshal(ann)
}

// decodeAnnouncement JSON-unmarshals a wire value into an announcement,
// reporting ok=false for an undecodable value so callers skip it. Pure.
func decodeAnnouncement(value []byte) (signingkeys.Announcement, bool) {
	var ann signingkeys.Announcement
	if err := json.Unmarshal(value, &ann); err != nil {
		return signingkeys.Announcement{}, false
	}
	return ann, true
}

// replicaIDFromKey extracts the replica id from a full etcd key under prefix.
// The id is the path segment after "<prefix>/"; trimming the prefix and any
// leading slash and taking the base segment yields it. Pure.
func replicaIDFromKey(prefix, key string) string {
	trimmed := strings.TrimPrefix(key, prefix)
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed == "" {
		return ""
	}
	return path.Base(trimmed)
}

// decodeWatchEvent maps one etcd watch event to a signingkeys.Event. A PUT
// decodes to EventKeysUpserted (skipped if the value is garbage); a DELETE
// (key removed or lease expired) maps to EventKeysRemoved with the ReplicaID
// derived from the key path, since a DELETE carries no value. Any other event
// type, or a PUT with a nil/undecodable value, is reported not-ok so the
// caller skips it. Pure (no etcd I/O, no crypto) so it is unit-testable.
func decodeWatchEvent(prefix string, ev *clientv3.Event) (signingkeys.Event, bool) {
	if ev == nil || ev.Kv == nil {
		return signingkeys.Event{}, false
	}
	switch ev.Type {
	case mvccpb.PUT:
		ann, ok := decodeAnnouncement(ev.Kv.Value)
		if !ok {
			return signingkeys.Event{}, false
		}
		return signingkeys.Event{Type: signingkeys.EventKeysUpserted, Announcement: ann}, true
	case mvccpb.DELETE:
		replicaID := replicaIDFromKey(prefix, string(ev.Kv.Key))
		if replicaID == "" {
			return signingkeys.Event{}, false
		}
		return signingkeys.Event{
			Type:         signingkeys.EventKeysRemoved,
			Announcement: signingkeys.Announcement{ReplicaID: replicaID},
		}, true
	default:
		return signingkeys.Event{}, false
	}
}

// drainKeepAlive consumes the KeepAlive response channel so the etcd client
// doesn't block on backpressure. We don't care about the values; we only need
// the channel drained for KeepAlive to keep renewing the lease.
func drainKeepAlive(ch <-chan *clientv3.LeaseKeepAliveResponse) {
	for range ch { //nolint:revive
	}
}
