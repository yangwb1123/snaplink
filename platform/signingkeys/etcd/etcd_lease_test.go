package etcd

// Behavioral tests for the supervised KeepAlive self-heal path. No live etcd
// server is required — the test harness drives the pure-logic pieces directly.
//
// What is exercised:
//   - signingKeyLeaseBackoff: growth curve, deterministic jitter, cap
//   - Registry.markDegraded / clearDegraded / ReadyzCheck state machine
//   - supervisedKeepAlive exits cleanly when ctx is cancelled (no degradation)
//   - supervisedKeepAlive marks degraded when channel closes with live ctx

import (
	"context"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/snaplink/sso/platform/signingkeys"
)

// TestSigningKeyLeaseBackoff verifies the growth + jitter + cap properties
// without any etcd I/O.
func TestSigningKeyLeaseBackoff(t *testing.T) {
	// Attempt 1 must be at least the initial constant.
	d1 := signingKeyLeaseBackoff(1)
	if d1 < signingKeyLeaseBackoffInitial {
		t.Errorf("attempt 1: got %v, want >= %v", d1, signingKeyLeaseBackoffInitial)
	}

	// Values must be non-decreasing up to the cap.
	prev := signingKeyLeaseBackoff(1)
	for attempt := 2; attempt <= 8; attempt++ {
		cur := signingKeyLeaseBackoff(attempt)
		if cur < prev {
			t.Errorf("attempt %d: %v < prev %v (should be non-decreasing)", attempt, cur, prev)
		}
		prev = cur
	}

	// Must never exceed cap + max jitter. The jitter ceiling is
	// signingKeyLeaseBackoffInitial/4, so the hard ceiling is cap + initial/4.
	maxAllowed := signingKeyLeaseBackoffMax + signingKeyLeaseBackoffInitial/4
	for _, attempt := range []int{10, 20, 100} {
		d := signingKeyLeaseBackoff(attempt)
		if d > maxAllowed {
			t.Errorf("attempt %d: %v exceeds ceiling %v", attempt, d, maxAllowed)
		}
	}

	// Large attempts must be capped.
	d100 := signingKeyLeaseBackoff(100)
	if d100 > maxAllowed {
		t.Errorf("attempt 100: %v not capped at %v", d100, maxAllowed)
	}

	// Attempt 0 must be treated the same as attempt 1 (floor guard).
	d0 := signingKeyLeaseBackoff(0)
	if d0 < signingKeyLeaseBackoffInitial {
		t.Errorf("attempt 0: got %v, want >= initial", d0)
	}
}

// TestBackoffDeterminism checks that the same attempt always returns the same
// duration — no hidden randomness.
func TestBackoffDeterminism(t *testing.T) {
	for _, attempt := range []int{1, 3, 5, 7, 10} {
		a := signingKeyLeaseBackoff(attempt)
		b := signingKeyLeaseBackoff(attempt)
		if a != b {
			t.Errorf("attempt %d: non-deterministic (%v != %v)", attempt, a, b)
		}
	}
}

// TestReadyzCheck_DegradedAndRecovered exercises the degrade/clear state
// machine in isolation, without any etcd I/O.
func TestReadyzCheck_DegradedAndRecovered(t *testing.T) {
	r := NewWithClient(nil, Config{})

	// Healthy by default.
	if err := r.ReadyzCheck(); err != nil {
		t.Fatalf("expected healthy initially, got: %v", err)
	}

	// markDegraded flips the check to failing.
	r.markDegraded()
	if err := r.ReadyzCheck(); err == nil {
		t.Fatal("expected error after markDegraded")
	}

	// markDegraded is idempotent — the degradedAt timestamp must not advance.
	before := r.degradedAt
	r.markDegraded()
	if r.degradedAt != before {
		t.Error("markDegraded must be idempotent (should not update degradedAt on second call)")
	}

	// clearDegraded restores health.
	r.clearDegraded()
	if err := r.ReadyzCheck(); err != nil {
		t.Fatalf("expected healthy after clearDegraded, got: %v", err)
	}
}

// TestSupervisedKeepAlive_CleanExitOnCtxCancel verifies that cancelling the
// background context (as Close and re-Publish do) causes supervisedKeepAlive
// to exit without marking the registry degraded.
func TestSupervisedKeepAlive_CleanExitOnCtxCancel(t *testing.T) {
	r := NewWithClient(nil, Config{})

	ctx, cancel := context.WithCancel(context.Background())

	// A channel that we close ourselves after ctx is cancelled — simulating the
	// etcd client closing the KeepAlive channel when its context is done.
	ch := make(chan *clientv3.LeaseKeepAliveResponse)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.supervisedKeepAlive(ctx, ch, signingkeys.Announcement{ReplicaID: "r1"}, 30, "{}")
	}()

	// Cancel the context first, then close the channel — the goroutine should
	// detect ctx.Err() != nil and exit cleanly.
	cancel()
	close(ch)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisedKeepAlive did not exit after ctx cancel")
	}

	// Must NOT have marked degraded — this was a clean shutdown path.
	if err := r.ReadyzCheck(); err != nil {
		t.Errorf("registry should not be degraded after clean ctx cancel, got: %v", err)
	}
}

// TestSupervisedKeepAlive_MarksDegradedOnUnexpectedClose verifies that a
// channel close with a still-live context (e.g. lease expired under network
// partition) marks the registry degraded. We use a cancelled context as the
// escape hatch so the re-grant loop does not need a real etcd client.
func TestSupervisedKeepAlive_MarksDegradedOnUnexpectedClose(t *testing.T) {
	r := NewWithClient(nil, Config{})

	// A context we cancel only AFTER the channel closes — so the goroutine
	// enters the degraded + retry path, then the backoff sees ctx.Done and exits.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch := make(chan *clientv3.LeaseKeepAliveResponse)

	done := make(chan struct{})
	go func() {
		defer close(done)
		r.supervisedKeepAlive(ctx, ch, signingkeys.Announcement{ReplicaID: "r1"}, 30, "{}")
	}()

	// Close the channel while ctx is still live — this is the network-partition
	// / lease-expired path. The goroutine will mark degraded, then attempt
	// backoff. Cancel the context to let it exit cleanly.
	close(ch)

	// Give the goroutine a moment to call markDegraded before we cancel.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("supervisedKeepAlive did not exit after ctx cancel during backoff")
	}

	// Must have marked degraded on the unexpected channel close.
	if err := r.ReadyzCheck(); err == nil {
		t.Error("expected registry to be degraded after unexpected channel close")
	}
}
