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
//   - FencingToken is monotonically increasing for the SAME key across
//     successive holders. Backends without native fencing return 0.
//
// Why fencing tokens matter: a stop-the-world GC pause inside a Step
// can outlast the lock TTL. By the time the renewLoop notices, another
// node may already hold the lock. A FencedTracker rejects MarkApplied
// from a token < its last seen token, preventing the dead holder's
// final write from corrupting state.
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

	// FencingToken returns a monotonically-increasing identifier for
	// the holder of THIS lease on THIS key. Returns 0 if the backend
	// doesn't support fencing.
	FencingToken() uint64
}
