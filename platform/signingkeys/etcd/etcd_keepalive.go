package etcd

import (
	"context"
	"errors"
	"fmt"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/yangwb1123/snaplink/platform/signingkeys"
)

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
	lease, err := r.grantAndPut(ctx, ann, body, ttlSec)
	if err != nil {
		return err
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

	oldCancel, oldLease := r.swapSupervised(cancel, keepCtx, lease.ID, ann)

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

// grantAndPut grants a fresh lease and puts the announcement under it. Split
// from Publish to keep the grant/put error wrapping in one cohesive place.
func (r *Registry) grantAndPut(
	ctx context.Context,
	ann signingkeys.Announcement,
	body []byte,
	ttlSec int64,
) (*clientv3.LeaseGrantResponse, error) {
	lease, err := r.client.Grant(ctx, ttlSec)
	if err != nil {
		return nil, fmt.Errorf("signingkeys/etcd: grant lease: %w", err)
	}
	if _, err := r.client.Put(ctx, r.replicaKey(ann.ReplicaID), string(body),
		clientv3.WithLease(lease.ID)); err != nil {
		return nil, fmt.Errorf("signingkeys/etcd: put announcement: %w", err)
	}
	return lease, nil
}

// swapSupervised installs the new supervised loop's cancel/context/lease/ann
// under the lock and returns the prior cancel + lease so the caller can tear
// them down after launching the new loop. Keeping the swap atomic preserves the
// invariant that bgCtx, cancel, and lease always refer to the same generation.
func (r *Registry) swapSupervised(
	cancel context.CancelFunc,
	keepCtx context.Context,
	lease clientv3.LeaseID,
	ann signingkeys.Announcement,
) (context.CancelFunc, clientv3.LeaseID) {
	r.mu.Lock()
	oldCancel, oldLease := r.cancel, r.lease
	r.cancel = cancel
	r.bgCtx = keepCtx
	r.lease = lease
	r.lastAnn = ann
	r.mu.Unlock()
	return oldCancel, oldLease
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
		if !r.backoffWait(ctx, attempt) {
			// Clean ctx cancel during backoff — not a failure, stay degraded
			// flag is moot since the loop is gone.
			return
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

		done, retry := r.regrantOnce(ctx, currentAnn, ttlSec, body)
		if retry {
			continue
		}
		if done {
			return
		}
	}
}

// backoffWait sleeps for the attempt's backoff delay, returning false if ctx is
// cancelled during the wait (clean shutdown) and true once the timer fires.
func (r *Registry) backoffWait(ctx context.Context, attempt int) bool {
	d := signingKeyLeaseBackoff(attempt)
	t := time.NewTimer(d)
	select {
	case <-ctx.Done():
		t.Stop()
		return false
	case <-t.C:
		return true
	}
}

// regrantOnce performs a single re-grant attempt: grant a new lease, put the
// current announcement, restart KeepAlive, and (if our context is still the
// active generation) hand off to a fresh supervised loop. It returns
// (done, retry): retry=true means the caller should loop again after backoff;
// done=true means the loop should exit (recovered, replaced, or cancelled).
// Splitting this out preserves the exact grant/put/keepalive/handoff ordering
// while keeping supervisedKeepAlive under the complexity budget.
func (r *Registry) regrantOnce(
	ctx context.Context,
	currentAnn signingkeys.Announcement,
	ttlSec int64,
	body string,
) (done bool, retry bool) {
	newLease, err := r.client.Grant(ctx, ttlSec)
	if err != nil {
		if ctx.Err() != nil {
			return true, false
		}
		return false, true
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
			return true, false
		}
		_, _ = r.client.Revoke(ctx, newLease.ID)
		return false, true
	}

	newKA, err := r.client.KeepAlive(ctx, newLease.ID)
	if err != nil {
		if ctx.Err() != nil {
			return true, false
		}
		_, _ = r.client.Revoke(ctx, newLease.ID)
		return false, true
	}

	r.installRegrantedLease(ctx, newLease.ID, newKA, currentAnn, ttlSec, string(annBody))
	return true, false
}

// installRegrantedLease takes ownership of a freshly re-granted live lease: it
// updates the tracked lease under the lock only if our background context is
// still the active generation, clears degraded, and hands off to a fresh
// supervised loop. If a concurrent Publish already replaced this generation it
// revokes the new lease so no ghost announcement lingers. Extracted verbatim
// from regrantOnce's tail to keep that function within the length budget.
func (r *Registry) installRegrantedLease(
	ctx context.Context,
	newLease clientv3.LeaseID,
	newKA <-chan *clientv3.LeaseKeepAliveResponse,
	currentAnn signingkeys.Announcement,
	ttlSec int64,
	annBody string,
) {
	// We have a live lease again. Update the registry's tracked lease under
	// the lock — but only if our background context is still the active one
	// (a concurrent Publish may have already replaced it, in which case that
	// Publish owns the new lease and we should stop).
	r.mu.Lock()
	ctxStillActive := r.bgCtx == ctx
	if ctxStillActive {
		r.lease = newLease
	}
	r.mu.Unlock()

	if !ctxStillActive {
		// A concurrent Publish replaced us. Revoke our new lease to avoid
		// leaving a ghost announcement alongside the newer one, then exit.
		_, _ = r.client.Revoke(context.Background(), newLease)
		return
	}

	r.clearDegraded()
	// Hand off to a fresh supervised loop for the new lease. Tail-call via
	// goroutine to avoid unbounded stack growth across many re-grant cycles.
	go r.supervisedKeepAlive(ctx, newKA, currentAnn, ttlSec, annBody)
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
