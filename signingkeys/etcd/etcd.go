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
	"errors"
	"fmt"
	"path"
	"sync"
	"time"

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

// Backoff bounds for the supervised KeepAlive re-grant loop. Mirrors the
// signing-key aggregation backoff in signing_key_aggregation.go: deterministic
// jitter (attempt-indexed, no rand) keeps the loop allocation-free while still
// spreading retries across a fleet that all lost the lease at the same instant.
const (
	signingKeyLeaseBackoffInitial = 1 * time.Second
	signingKeyLeaseBackoffMax     = 30 * time.Second
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

	mu         sync.Mutex
	lease      clientv3.LeaseID   // this replica's current announcement lease (0 = none)
	cancel     context.CancelFunc // cancels the current supervised keepalive loop (nil = none)
	bgCtx      context.Context    // background context for the supervised loop
	lastAnn    signingkeys.Announcement
	degraded   bool
	degradedAt time.Time
	closed     bool

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
