package netpolicy_test

// Self-healing tests for the network-policy Classifier's Watch consumer. They
// run as an EXTERNAL test (package netpolicy_test) so they can import the real
// netpolicy/memory backend without the import cycle an in-package test would hit
// (netpolicy/memory imports netpolicy). The unexported degraded flag + backoff
// seam are reached through export_test.go — mirroring how the root package's
// sibling invalidation-bus + signing-key aggregation self-heal tests reach their
// internals.
//
// The headline property: when the Store.Watch channel closes while the run
// context is still live (etcd watch compaction / leader change / network blip),
// the Classifier flips degraded (Ready errors, sso_netpolicy_classifier_up=0),
// keeps serving its frozen snapshot, then resubscribes + re-Lists and recovers —
// and a clean ctx-cancel exits WITHOUT degrading.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/platform/netpolicy/memory"
)

// flakyStore wraps the real in-process memory Store so a test can force the
// CURRENT Watch subscriber's channel closed mid-life (simulating an etcd watch
// death / network blip) while Apply + a subsequent Watch keep working — exactly
// the silent-failure mode the self-healing loop defends against. No production
// API changes: it composes the real Apply/List/Get/Delete/Close and only
// intercepts Watch to relay the inner stream onto a test-owned channel it can
// force-close independently. Mirrors flakyBus in invalidation_bus_selfheal_test.go.
type flakyStore struct {
	inner *memory.Store

	mu      sync.Mutex
	watchN  int                                    // count of Watch calls (for assertions)
	current chan netpolicy.Event                   // channel handed to the most recent subscriber
	relay   map[chan netpolicy.Event]chan struct{} // stop chan per relay goroutine
}

func newFlakyStore() *flakyStore {
	return &flakyStore{
		inner: memory.New(),
		relay: make(map[chan netpolicy.Event]chan struct{}),
	}
}

func (f *flakyStore) Get(ctx context.Context, name string) (*netpolicy.Policy, error) {
	return f.inner.Get(ctx, name)
}
func (f *flakyStore) List(ctx context.Context) ([]*netpolicy.Policy, error) {
	return f.inner.List(ctx)
}
func (f *flakyStore) Apply(ctx context.Context, p *netpolicy.Policy) (*netpolicy.Policy, error) {
	return f.inner.Apply(ctx, p)
}
func (f *flakyStore) Delete(ctx context.Context, name string) error {
	return f.inner.Delete(ctx, name)
}
func (f *flakyStore) Close() error { return f.inner.Close() }

// Watch opens a real inner subscription and relays it onto a test-owned channel
// we can force-close independently. The relay goroutine stops when the inner
// channel closes, when forceClose fires, or when ctx is cancelled.
func (f *flakyStore) Watch(ctx context.Context) (<-chan netpolicy.Event, error) {
	src, err := f.inner.Watch(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan netpolicy.Event, 16)
	stop := make(chan struct{})

	f.mu.Lock()
	f.watchN++
	f.current = out
	f.relay[out] = stop
	f.mu.Unlock()

	go func() {
		defer func() {
			// Close the test-owned channel exactly once on any exit path.
			f.mu.Lock()
			if _, live := f.relay[out]; live {
				delete(f.relay, out)
				close(out)
			}
			f.mu.Unlock()
		}()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				return
			case evt, ok := <-src:
				if !ok {
					return
				}
				select {
				case out <- evt:
				default:
				}
			}
		}
	}()
	return out, nil
}

// forceClose closes the channel currently handed to the subscriber loop,
// simulating a watch death. Apply + the next Watch stay healthy.
func (f *flakyStore) forceClose() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil {
		if stop, ok := f.relay[f.current]; ok {
			close(stop)
		}
	}
}

func (f *flakyStore) watchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.watchN
}

var _ netpolicy.Store = (*flakyStore)(nil)

// clsWaitFor polls cond until it returns true or the deadline elapses.
func clsWaitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// clsSeriesValue reads a single metric series by name + an exact label match
// (nil match = the no-label series) off the metrics Registry via Gather, with no
// testutil/dto dependency. Returns 0 when no matching series exists. Mirrors
// busSeriesValue in invalidation_bus_selfheal_test.go.
func clsSeriesValue(t *testing.T, m *metrics.Metrics, name string, labels map[string]string) float64 {
	t.Helper()
	mfs, err := m.Registry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, metric := range mf.GetMetric() {
			match := true
			for k, v := range labels {
				found := false
				for _, lp := range metric.GetLabel() {
					if lp.GetName() == k && lp.GetValue() == v {
						found = true
						break
					}
				}
				if !found {
					match = false
					break
				}
			}
			if !match {
				continue
			}
			if c := metric.GetCounter(); c != nil {
				return c.GetValue()
			}
			if g := metric.GetGauge(); g != nil {
				return g.GetValue()
			}
		}
	}
	return 0
}

// applyAndExpect publishes a policy via Apply and waits for the consumer loop to
// reflect it in Classify — proving an Event is flowing end-to-end through the
// (current) subscription.
func applyAndExpect(t *testing.T, c *netpolicy.Classifier, s netpolicy.Store, name, cidr, addr string) {
	t.Helper()
	if _, err := s.Apply(context.Background(), &netpolicy.Policy{Name: name, CIDRs: []string{cidr}}); err != nil {
		t.Fatalf("apply %s: %v", name, err)
	}
	if !clsWaitFor(2*time.Second, func() bool {
		p := c.Classify(addr, "")
		return p != nil && p.Name == name
	}) {
		t.Fatalf("policy %s never applied via watch (Classify miss)", name)
	}
}

// newClassifierTest builds a Classifier wired with metrics + a tiny resubscribe
// backoff so the self-heal happens fast. 60ms keeps the degraded window wide
// enough to observe synchronously (mirrors the bus test's rationale) while
// staying well under the recovery timeouts.
func newClassifierTest(m *metrics.Metrics) *netpolicy.Classifier {
	c := netpolicy.NewClassifier(netpolicy.WithClassifierMetrics(m))
	c.SetBackoffBase(60 * time.Millisecond)
	return c
}

// TestClassifier_SelfHealsOnWatchClose is the headline robustness property: when
// the Watch channel closes while the run context is still live, the Classifier
// (a) flips degraded — Ready errors and sso_netpolicy_classifier_up reads 0 —
// while STILL serving its frozen snapshot, then (b) resubscribes + re-Lists and
// clears degraded — Ready ok, up back to 1, a new Event flows again — and (c)
// the reconnect counter shows one degraded + one reconnected tick per transition.
func TestClassifier_SelfHealsOnWatchClose(t *testing.T) {
	t.Parallel()
	store := newFlakyStore()
	defer func() { _ = store.Close() }()

	m := metrics.New()
	c := newClassifierTest(m)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := c.Start(ctx, store)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Healthy from the first subscribe; an Event flows.
	if err := c.Ready(); err != nil {
		t.Fatalf("expected ready after initial subscribe, got: %v", err)
	}
	if got := clsSeriesValue(t, m, metrics.NameNetPolicyClassifierUp, nil); got != 1 {
		t.Fatalf("classifier_up=%v after initial subscribe, want 1", got)
	}
	applyAndExpect(t, c, store, "intranet", "10.0.0.0/8", "10.0.0.1")

	// Kill the live subscription: the loop must flip degraded.
	store.forceClose()
	if !clsWaitFor(2*time.Second, func() bool { return c.Degraded() }) {
		t.Fatal("loop never went degraded after watch close")
	}
	// While degraded: Ready errors + gauge 0 — but the frozen snapshot is still
	// served (fail-open: the request path never breaks while the loop heals).
	if err := c.Ready(); err == nil {
		t.Fatal("Ready must error while degraded")
	}
	if got := clsSeriesValue(t, m, metrics.NameNetPolicyClassifierUp, nil); got != 0 {
		t.Fatalf("classifier_up=%v while degraded, want 0", got)
	}
	if p := c.Classify("10.0.0.1", ""); p == nil || p.Name != "intranet" {
		t.Fatalf("frozen snapshot not served while degraded: %v", p)
	}

	// A policy applied WHILE degraded is not yet visible (the watch is dead) but
	// MUST be picked up by the recovery re-List — proving the gap is closed.
	if _, err := store.Apply(context.Background(), &netpolicy.Policy{Name: "dmz", CIDRs: []string{"172.16.0.0/12"}}); err != nil {
		t.Fatalf("apply during degraded: %v", err)
	}

	// The loop resubscribes on its own (backoff is tiny): degraded clears.
	if !clsWaitFor(3*time.Second, func() bool {
		return !c.Degraded() && store.watchCount() >= 2
	}) {
		t.Fatalf("loop never recovered (degraded=%v watches=%d)",
			c.Degraded(), store.watchCount())
	}
	if err := c.Ready(); err != nil {
		t.Fatalf("Ready must recover after resubscribe, got: %v", err)
	}
	if !clsWaitFor(time.Second, func() bool {
		return clsSeriesValue(t, m, metrics.NameNetPolicyClassifierUp, nil) == 1
	}) {
		t.Fatalf("classifier_up=%v after recovery, want 1",
			clsSeriesValue(t, m, metrics.NameNetPolicyClassifierUp, nil))
	}

	// The re-List on recovery caught the policy applied during the gap.
	if !clsWaitFor(2*time.Second, func() bool {
		p := c.Classify("172.16.0.1", "")
		return p != nil && p.Name == "dmz"
	}) {
		t.Fatal("recovery re-List did not catch the policy applied while degraded")
	}

	// An Event published AFTER recovery must be applied on the fresh
	// subscription (proves the resubscribe keeps draining).
	applyAndExpect(t, c, store, "public", "192.168.0.0/16", "192.168.0.1")

	// Exactly one degraded + one reconnected tick for the single transition (the
	// degraded flag de-dupes per transition, not per retry).
	if got := clsSeriesValue(t, m, metrics.NameNetPolicyClassifierReconnectsTotal,
		map[string]string{metrics.LabelReason: metrics.NetPolicyClassifierReasonDegraded}); got != 1 {
		t.Fatalf("reconnects_total{reason=degraded}=%v, want 1", got)
	}
	if got := clsSeriesValue(t, m, metrics.NameNetPolicyClassifierReconnectsTotal,
		map[string]string{metrics.LabelReason: metrics.NetPolicyClassifierReasonReconnected}); got != 1 {
		t.Fatalf("reconnects_total{reason=reconnected}=%v, want 1", got)
	}

	// Clean ctx-cancel must close done and must NOT flip degraded.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}
	if c.Degraded() {
		t.Fatal("clean ctx-cancel after recovery must leave the loop non-degraded")
	}
}

// TestClassifier_CleanCancelNotDegraded locks the other half of the distinction:
// a graceful shutdown (ctx cancel) closes the subscription too, but the loop must
// exit WITHOUT going degraded — a drain must never trip /readyz. Uses the real
// memory Store directly (no flaky wrapper) since we only cancel ctx.
func TestClassifier_CleanCancelNotDegraded(t *testing.T) {
	t.Parallel()
	store := memory.New()
	defer func() { _ = store.Close() }()

	m := metrics.New()
	c := newClassifierTest(m)

	ctx, cancel := context.WithCancel(context.Background())
	done, err := c.Start(ctx, store)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}

	if c.Degraded() {
		t.Fatal("clean ctx-cancel must not mark the loop degraded")
	}
	if err := c.Ready(); err != nil {
		t.Fatalf("Ready after clean cancel must be nil, got: %v", err)
	}
}

// TestClassifier_ReadyBeforeStart proves Ready is safe (and non-degraded) before
// Start ever runs — the readiness probe can be registered unconditionally.
func TestClassifier_ReadyBeforeStart(t *testing.T) {
	t.Parallel()
	c := netpolicy.NewClassifier()
	if err := c.Ready(); err != nil {
		t.Fatalf("Ready before Start must be nil, got: %v", err)
	}
}
