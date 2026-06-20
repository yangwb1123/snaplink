// Package lock defines the distributed-init Lock SPI used by
// bootstrap.Runner to serialize first-run init across replicas.
//
// The interface is intentionally tiny: TryAcquire returns a Handle, and
// Handle has Renew + Release + FencingToken. Backends differ in storage
// (process-local, file flock, etcd lease, redis SET-NX, postgres
// advisory) but share these semantics:
//
//   - TryAcquire returns ErrLocked if another holder owns the key.
//     Backends MUST NOT block; the Runner decides whether to retry.
//   - Renew extends the lease. Failure means the lock is GONE — the
//     caller MUST stop work and abandon any pending writes.
//   - Release is idempotent on a Handle that already lost its lease.
//   - FencingToken returns an opaque identifier for the holder of this
//     lease. It is ADVISORY: no in-tree tracker consumes it, and the etcd
//     backend's token (the LeaseID) is NOT monotonic across holders (see
//     the etcd package) — do NOT build a `<`-comparison fence on it.
//     Backends without native fencing return 0.
//
// Split-brain protection — a stop-the-world GC pause inside a Step can
// outlast the lock TTL, letting another node acquire the lock before the
// renewLoop notices — does NOT come from a fencing-token tracker today:
// there is no FencedTracker, and MarkApplied carries no token. It comes
// from two real mechanisms: (1) Renew returning ErrLockLost CANCELS the
// in-flight Step's context, so a holder that lost its lease stops before
// its write lands; and (2) bootstrap Steps are version-gated + idempotent,
// so a late write that still slips through is a no-op (re-seeding the admin
// role/user or re-restoring a snapshot converges to the same state).
// FencingToken is plumbed for a future tracker, but enforcing one would
// require a backend whose token is genuinely monotonic per holder — which
// etcd's LeaseID is not.
package lock

import (
	"context"
	"errors"
	"time"
)

// ErrLocked is returned by TryAcquire when the key is held by another
// holder. Sentinel — match with errors.Is.
var ErrLocked = errors.New("bootstrap/lock: already held")

// ErrLockLost is returned by Renew when the lease is gone (TTL expired,
// network partition outlasted TTL, etcd lease revoked). Renew failures
// MUST cancel in-flight work — the Runner uses this to abort Steps.
var ErrLockLost = errors.New("bootstrap/lock: lease lost")

// Lock is a distributed mutual-exclusion primitive scoped by key.
type Lock interface {
	// TryAcquire requests exclusive ownership of key for ttl. Returns
	// ErrLocked if held; any other error is treated as transport
	// failure by the Runner. Backends MUST NOT block waiting.
	TryAcquire(ctx context.Context, key string, ttl time.Duration) (Handle, error)
}

// Handle is an active lease on a key.
type Handle interface {
	// Renew extends the lease. Returns ErrLockLost if the lease is
	// already gone. Backends without TTL semantics (file/postgres
	// advisory) may return nil unconditionally.
	Renew(ctx context.Context) error

	// Release voluntarily relinquishes the lease. Idempotent; calling
	// after ErrLockLost is allowed and returns nil.
	Release(ctx context.Context) error

	// FencingToken returns an opaque identifier for the holder of THIS
	// lease. ADVISORY only (no in-tree tracker consumes it) and NOT
	// guaranteed monotonic across holders — the etcd backend returns a
	// non-monotonic LeaseID (see package etcd). Returns 0 if the backend
	// doesn't support fencing.
	FencingToken() uint64
}
