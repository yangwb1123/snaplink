package netpolicy

import (
	"context"
	"errors"
	"time"

	"github.com/snaplink/sso/platform/metrics"
)

// Resubscribe backoff bounds. Identical shape to the signing-key aggregation +
// invalidation-bus self-heal loops (root package): on a Watch-channel close
// while ctx is live the loop retries with an exponentially growing,
// deterministically-jittered, capped delay so a flapping policy backend doesn't
// hot-loop, and a fleet that all lost the watch at once de-synchronizes its
// retries without a randomness dependency.
const (
	classifierBackoffInitial = 1 * time.Second
	classifierBackoffMax     = 30 * time.Second
)

// ErrClassifierDegraded is returned by [Classifier.Ready] while the Watch
// subscription is degraded (the Store.Watch channel closed under a live context
// and the loop is between resubscribe attempts). The Classifier is STILL serving
// its last snapshot (Classify never blocks or errors — fail-open), but it has
// STOPPED applying policy edits until it resubscribes, so a just-added/removed
// network class is not reflected here yet. cmd wraps this into a /readyz check.
var ErrClassifierDegraded = errors.New("netpolicy: classifier watch subscription degraded (serving frozen snapshot)")

// Ready reports whether this replica's network-policy Watch subscription is
// healthy. It returns ErrClassifierDegraded while degraded. Safe for concurrent
// use (the flag is atomic). Always nil before Start runs and after a clean
// ctx-cancel shutdown (a graceful drain never trips readiness).
func (c *Classifier) Ready() error {
	if c.degraded.Load() {
		return ErrClassifierDegraded
	}
	return nil
}

// run is the self-healing Watch consumer. It drains the current subscription,
// and on a channel close distinguishes a clean ctx-cancel (exit normally, NOT
// degraded) from a live-context Watch drop (mark degraded, back off, resubscribe
// AND re-List so any change missed during the gap is caught). Closes done
// exactly once, only when ctx is cancelled. Mirrors runInvalidationBus.
func (c *Classifier) run(ctx context.Context, s Store, done chan struct{}, ch <-chan Event) {
	defer close(done)
	attempt := 0
	for {
		for evt := range ch {
			c.apply(evt)
		}
		// The channel closed. If ctx is done this is a clean shutdown — the
		// memory + etcd Store peers both close the stream BECAUSE ctx was
		// cancelled. Exit without marking degraded so a graceful drain never
		// trips /readyz.
		if ctx.Err() != nil {
			return
		}

		// A close with a live context is the silent-failure mode this loop
		// exists to defend against: mark degraded ONCE per transition (gauge +
		// counter + flag + log), then back off and resubscribe.
		c.setDegraded()

		attempt++
		if !sleepCtx(ctx, c.backoff(attempt)) {
			return // ctx cancelled during backoff — clean exit.
		}

		next, action := c.resubscribe(ctx, s, attempt)
		switch action {
		case selfHealExit:
			return
		case selfHealRetry:
			continue
		}
		// Recovered: clear degraded (gauge -> 1, flag -> false, reconnected
		// counter) and resume draining the fresh stream with a reset backoff.
		c.setHealthy()
		ch = next
		attempt = 0
	}
}

// selfHealAction is the outcome of a single resubscribe-and-reload attempt,
// telling the run loop whether to exit cleanly, retry after backoff, or resume
// on the freshly returned channel.
type selfHealAction int

const (
	selfHealRecovered selfHealAction = iota // resubscribed AND re-Listed; resume on the new channel.
	selfHealExit                            // ctx cancelled mid-attempt; exit cleanly.
	selfHealRetry                           // attempt failed under a live ctx; stay degraded and retry.
)

// resubscribe re-establishes the Watch stream and re-Lists so any edit missed
// during the degraded gap is caught. It returns the fresh channel only on
// selfHealRecovered; on selfHealExit/selfHealRetry the channel is nil. Extracted
// verbatim from run's resubscribe block — same ctx checks, logs, and ordering
// (re-List BEFORE clearing degraded). Called only from the single Watch-consumer
// goroutine.
func (c *Classifier) resubscribe(ctx context.Context, s Store, attempt int) (<-chan Event, selfHealAction) {
	next, err := s.Watch(ctx)
	if err != nil {
		// Resubscribe failed (backend still down). Stay degraded and retry
		// after a longer backoff. A permanent-close error at shutdown is
		// benign — the next ctx check or backoff observes the cancel.
		if ctx.Err() != nil {
			return nil, selfHealExit
		}
		if c.logger != nil {
			c.logger.Error("netpolicy classifier rewatch failed, will retry", "attempt", attempt, "error", err)
		}
		return nil, selfHealRetry
	}
	// Re-List on the fresh subscription BEFORE clearing degraded: Watch is
	// edge-triggered and the Store contract says slow consumers may miss
	// events, so a change applied during the gap would otherwise be lost.
	// A failed re-List leaves the (stale) snapshot in place and keeps the
	// loop degraded — better a known-stale read than a silently-wrong one.
	if err := c.Reload(ctx, s); err != nil {
		if ctx.Err() != nil {
			return nil, selfHealExit
		}
		if c.logger != nil {
			c.logger.Error("netpolicy classifier reload after rewatch failed, will retry", "attempt", attempt, "error", err)
		}
		return nil, selfHealRetry
	}
	return next, selfHealRecovered
}

// setDegraded flips the Classifier into the degraded state ONCE per transition:
// it no-ops if already degraded (so a flapping backend emits one gauge write +
// one counter tick + one log per outage, not per retry). Called only from the
// single Watch-consumer goroutine, so the read-then-set is race-free w.r.t.
// itself; the flag is atomic only for the concurrent Ready() reader. Mirrors
// setInvalidationBusDegraded.
func (c *Classifier) setDegraded() {
	if c.degraded.Swap(true) {
		return // already degraded — don't re-emit.
	}
	if c.logger != nil {
		c.logger.Error("netpolicy classifier watch closed while running; serving frozen snapshot, resubscribing")
	}
	if c.metrics != nil {
		c.metrics.NetPolicyClassifierUp.Set(0)
		c.metrics.NetPolicyClassifierReconnectsTotal.WithLabelValues(metrics.NetPolicyClassifierReasonDegraded).Inc()
	}
}

// setHealthy clears the degraded state. On the initial subscribe it just stamps
// the gauge to 1 (Swap returns false). On RECOVERY from a degraded state it
// additionally emits the reconnected counter tick + a log line. Symmetric with
// setDegraded; one transition, one event. Mirrors setInvalidationBusHealthy.
func (c *Classifier) setHealthy() {
	wasDegraded := c.degraded.Swap(false)
	if c.metrics != nil {
		c.metrics.NetPolicyClassifierUp.Set(1)
	}
	if wasDegraded {
		if c.logger != nil {
			c.logger.Info("netpolicy classifier watch recovered; resumed applying policy updates")
		}
		if c.metrics != nil {
			c.metrics.NetPolicyClassifierReconnectsTotal.WithLabelValues(metrics.NetPolicyClassifierReasonReconnected).Inc()
		}
	}
}

// backoff returns the resubscribe delay for the given 1-based attempt:
// exponential from the initial up to the cap, plus a deterministic per-attempt
// jitter (no rand). The base is the production const unless backoffBase was set
// (test seam). Identical in shape to invalidationBusBackoff.
func (c *Classifier) backoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	base := classifierBackoffInitial
	if c.backoffBase > 0 {
		base = c.backoffBase
	}
	max := classifierBackoffMax
	if base > max {
		max = base
	}
	d := base
	for i := 1; i < attempt && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	// Deterministic jitter keyed off the attempt number so two replicas on
	// different attempt counts don't retry in lockstep. attempt%5 spans 0..4/5
	// of a quarter-window — enough spread without a randomness dependency.
	jitter := (d / 4) * time.Duration(attempt%5) / 5
	return d + jitter
}

// sleepCtx waits for d or ctx cancellation, returning true if the full delay
// elapsed and false if ctx was cancelled first. Lets the backoff abort promptly
// on shutdown.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}
