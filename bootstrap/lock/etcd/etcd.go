// Package etcd is the etcd v3-backed distributed lock for
// bootstrap.Runner. It serializes init across replicas via Lease + Txn:
//
//   - TryAcquire grants a Lease (TTL bound by caller) and atomically
//     creates the key only if it doesn't exist (CreateRevision == 0).
//     If the Txn fails the key was held — return ErrLocked.
//   - Renew extends the lease via etcd KeepAlive. Failures (lease
//     revoked, network partition) surface as ErrLockLost.
//   - Release deletes the key bound to the lease and revokes the lease,
//     making the slot immediately available to peers.
//   - FencingToken returns the etcd LeaseID — etcd assigns these
//     monotonically per cluster, so a FencedTracker can reject stale
//     writes from a holder whose lease was revoked.
package etcd

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/bootstrap/lock"
	clientv3 "go.etcd.io/etcd/client/v3"
)

// Defaults applied when a corresponding Config field is zero.
const (
	DefaultDialTimeout = 5 * time.Second
)

// Config configures the etcd Lock.
type Config struct {
	Endpoints   []string      // etcd cluster endpoints, e.g. ["localhost:2379"]
	DialTimeout time.Duration // connect timeout; defaults to DefaultDialTimeout
	Username    string
	Password    string
}

// Lock is the etcd-backed distributed lock.
type Lock struct {
	client *clientv3.Client
	owns   bool // close client on Lock.Close iff we created it
}

// New constructs a Lock by dialing the etcd cluster described by cfg.
// The Client is owned by the Lock and closed by Close.
func New(cfg Config) (*Lock, error) {
	if len(cfg.Endpoints) == 0 {
		return nil, errors.New("bootstrap/lock/etcd: endpoints required")
	}
	dial := cfg.DialTimeout
	if dial == 0 {
		dial = DefaultDialTimeout
	}
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   cfg.Endpoints,
		DialTimeout: dial,
		Username:    cfg.Username,
		Password:    cfg.Password,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrap/lock/etcd: dial: %w", err)
	}
	return &Lock{client: cli, owns: true}, nil
}

// FromClient adopts an externally-managed etcd client. Caller retains
// ownership; Close is a no-op.
func FromClient(c *clientv3.Client) *Lock {
	return &Lock{client: c, owns: false}
}

// Close releases the etcd client if Lock owns it. Safe to call multiple
// times; outstanding Handles MUST be Released first or they'll error
// on Renew.
func (l *Lock) Close() error {
	if l.owns && l.client != nil {
		err := l.client.Close()
		l.client = nil
		return err
	}
	return nil
}

// TryAcquire grants a Lease and CAS-creates key. ttl is rounded up to a
// whole second (etcd Lease minimum granularity). Returns ErrLocked if
// the key is held.
func (l *Lock) TryAcquire(ctx context.Context, key string, ttl time.Duration) (lock.Handle, error) {
	if key == "" {
		return nil, errors.New("bootstrap/lock/etcd: key required")
	}
	if ttl <= 0 {
		return nil, errors.New("bootstrap/lock/etcd: ttl must be > 0")
	}
	seconds := max(int64(ttl.Seconds()), 1)
	leaseResp, err := l.client.Grant(ctx, seconds)
	if err != nil {
		return nil, fmt.Errorf("bootstrap/lock/etcd: grant: %w", err)
	}
	// CAS: take the key only if it does not exist.
	txn := l.client.Txn(ctx).
		If(clientv3.Compare(clientv3.CreateRevision(key), "=", 0)).
		Then(clientv3.OpPut(key, fmt.Sprintf("lease=%d", leaseResp.ID), clientv3.WithLease(leaseResp.ID)))
	tr, err := txn.Commit()
	if err != nil {
		_, _ = l.client.Revoke(ctx, leaseResp.ID)
		return nil, fmt.Errorf("bootstrap/lock/etcd: txn: %w", err)
	}
	if !tr.Succeeded {
		_, _ = l.client.Revoke(ctx, leaseResp.ID)
		return nil, lock.ErrLocked
	}
	return &handle{
		client:  l.client,
		key:     key,
		leaseID: leaseResp.ID,
		ttl:     time.Duration(seconds) * time.Second,
	}, nil
}

type handle struct {
	client  *clientv3.Client
	key     string
	leaseID clientv3.LeaseID
	ttl     time.Duration

	closed atomic.Bool
	mu     sync.Mutex // serialize Renew/Release
}

// Renew sends a single KeepAliveOnce to etcd. Bootstrap.Runner calls
// this on a heartbeat goroutine; failures are signaled by returning
// ErrLockLost so the Runner cancels in-flight work.
func (h *handle) Renew(ctx context.Context) error {
	if h.closed.Load() {
		return lock.ErrLockLost
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.client.KeepAliveOnce(ctx, h.leaseID)
	if err != nil {
		// rpctypes.ErrLeaseNotFound (lease revoked / expired) maps to lost.
		return fmt.Errorf("%w: %v", lock.ErrLockLost, err)
	}
	return nil
}

// Release revokes the lease which deletes the key with it. Idempotent.
func (h *handle) Release(ctx context.Context) error {
	if !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.client.Revoke(ctx, h.leaseID)
	if err != nil {
		return fmt.Errorf("bootstrap/lock/etcd: revoke: %w", err)
	}
	return nil
}

// FencingToken returns the etcd LeaseID, which is monotonic per cluster.
func (h *handle) FencingToken() uint64 { return uint64(h.leaseID) }

// Compile-time interface assertions.
var (
	_ lock.Lock   = (*Lock)(nil)
	_ lock.Handle = (*handle)(nil)
)
