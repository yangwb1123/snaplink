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

// Publish writes ann under <prefix>/<ReplicaID> with a fresh lease and launches
// a supervised keep-alive goroutine. A re-Publish (startup, then each rotation)
// replaces the prior announcement wholesale: it cancels the old supervised loop
// and revokes the old lease, then puts the new announcement under a new lease —
// so a rotated kid propagates and a retired kid drops from peers.
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

	// The supervised loop runs off a background context so it outlives the
	// (request-scoped) ctx of this Publish — the announcement must stay live
	// until the next Publish or Close, not just until ctx returns. Cancelling
	// the prior loop's context stops its KeepAlive before we revoke the old lease.
	keepCtx, cancel := context.WithCancel(context.Background())
	keepAlive, err := r.client.KeepAlive(keepCtx, lease.ID)
	if err != nil {
		cancel()
		return fmt.Errorf("signingkeys/etcd: keepalive: %w", err)
	}

	r.mu.Lock()
	oldCancel, oldLease := r.cancel, r.lease
	r.cancel = cancel
	r.bgCtx = keepCtx
	r.lease = lease.ID
	r.lastAnn = ann
	r.mu.Unlock()

	go r.supervisedKeepAlive(keepCtx, keepAlive, ann, ttlSec, string(body))

	// Tear down the prior announcement's supervised loop + lease so the old key
	// doesn't linger under its own lease alongside the new one.
	if oldCancel != nil {
		oldCancel()
	}
	if oldLease != 0 {
		_, _ = r.client.Revoke(ctx, oldLease)
	}
	return nil
}

// supervisedKeepAlive drains the KeepAlive channel. If the channel closes while
// the background context is still live (lease expired due to leader churn,
// network partition, etc.), it marks degraded and re-grants a new lease with
// exponential backoff — persisting the last known announcement so peers never
// see a silent gap. A ctx cancellation (from Close or a new Publish) exits
// cleanly without marking degraded.
func (r *Registry) supervisedKeepAlive(
	ctx context.Context,
	ch <-chan *clientv3.LeaseKeepAliveResponse,
	ann signingkeys.Announcement,
	ttlSec int64,
	body string,
) {
	for range ch { //nolint:revive
	}

	// Channel closed. If ctx is done this is a clean shutdown (Close or
	// re-Publish cancelled us) — exit without degrading so a graceful drain
	// never trips /readyz or forces a re-grant cycle.
	if ctx.Err() != nil {
		return
	}

	// The channel closed with a live context: the lease expired (etcd leader
	// churn, network partition, or a long GC pause). Mark degraded and
	// re-grant with backoff so peers see the keys again as soon as possible.
	r.markDegraded()

	attempt := 0
	for {
		attempt++
		d := signingKeyLeaseBackoff(attempt)

		t := time.NewTimer(d)
		select {
		case <-ctx.Done():
			t.Stop()
			// Clean ctx cancel during backoff — not a failure, stay degraded
			// flag is moot since the loop is gone.
			return
		case <-t.C:
		}

		// Retrieve the current announcement under the lock in case a concurrent
		// re-Publish swapped it before we could re-grant. If ctx is now
		// cancelled the newer Publish already owns the lease — stop.
		if ctx.Err() != nil {
			return
		}
		r.mu.Lock()
		currentAnn := r.lastAnn
		r.mu.Unlock()

		newLease, err := r.client.Grant(ctx, ttlSec)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}

		annBody, encErr := encodeAnnouncement(currentAnn)
		if encErr != nil {
			// The announcement hasn't changed structurally since we encoded it
			// once before — marshal failure here would be a panic-level bug, but
			// we stay live by falling back to the original body so the lease
			// entry is never empty.
			annBody = []byte(body)
		}

		if _, err := r.client.Put(ctx, r.replicaKey(currentAnn.ReplicaID), string(annBody),
			clientv3.WithLease(newLease.ID)); err != nil {
			if ctx.Err() != nil {
				return
			}
			_, _ = r.client.Revoke(ctx, newLease.ID)
			continue
		}

		newKA, err := r.client.KeepAlive(ctx, newLease.ID)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			_, _ = r.client.Revoke(ctx, newLease.ID)
			continue
		}

		// We have a live lease again. Update the registry's tracked lease under
		// the lock — but only if our background context is still the active one
		// (a concurrent Publish may have already replaced it, in which case that
		// Publish owns the new lease and we should stop).
		r.mu.Lock()
		ctxStillActive := r.bgCtx == ctx
		if ctxStillActive {
			r.lease = newLease.ID
		}
		r.mu.Unlock()

		if !ctxStillActive {
			// A concurrent Publish replaced us. Revoke our new lease to avoid
			// leaving a ghost announcement alongside the newer one, then exit.
			_, _ = r.client.Revoke(context.Background(), newLease.ID)
			return
		}

		r.clearDegraded()
		// Hand off to a fresh supervised loop for the new lease. Tail-call via
		// goroutine to avoid unbounded stack growth across many re-grant cycles.
		go r.supervisedKeepAlive(ctx, newKA, currentAnn, ttlSec, string(annBody))
		return
	}
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

// ReadyzCheck returns an error if the Registry is degraded — i.e. the
// KeepAlive channel closed while the process context was still live and the
// supervised re-grant loop has not yet recovered. In that window this replica's
// signing keys are absent from peers' JWKS, so tokens it signs will fail
// verification on peers. cmd may register this as a /readyz ReadyCheck when
// the etcd registry backend is wired so the load-balancer can pull the
// replica while it re-grants its lease.
func (r *Registry) ReadyzCheck() error {
	r.mu.Lock()
	deg := r.degraded
	r.mu.Unlock()
	if deg {
		return errors.New("signingkeys/etcd: keepalive degraded (re-granting lease)")
	}
	return nil
}

// markDegraded transitions the Registry into the degraded state. Idempotent:
// a second call while already degraded is a no-op so a flapping lease only
// stamps one transition time.
func (r *Registry) markDegraded() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.degraded {
		r.degraded = true
		r.degradedAt = time.Now()
	}
}

// clearDegraded transitions the Registry back to healthy.
func (r *Registry) clearDegraded() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.degraded = false
	r.degradedAt = time.Time{}
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

// signingKeyLeaseBackoff returns the re-grant delay for the given 1-based
// attempt: exponential from the initial up to the cap, plus a deterministic
// per-attempt step (no rand) so a fleet that all lost the lease at the same
// instant de-synchronizes its retries. The jitter term is a small bounded
// step (attempt * 100ms, capped at initial/4) — wide enough to spread a
// fleet, narrow enough to stay within [base, base+initial/4].
func signingKeyLeaseBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	d := signingKeyLeaseBackoffInitial
	for i := 1; i < attempt && d < signingKeyLeaseBackoffMax; i++ {
		d *= 2
	}
	if d > signingKeyLeaseBackoffMax {
		d = signingKeyLeaseBackoffMax
	}
	// Deterministic jitter: a per-attempt step bounded to a quarter of the
	// initial window, so even at the cap the spread is modest and bounded.
	jitter := time.Duration(attempt) * 100 * time.Millisecond
	if max := signingKeyLeaseBackoffInitial / 4; jitter > max {
		jitter = max
	}
	return d + jitter
}
