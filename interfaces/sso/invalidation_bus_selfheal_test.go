package sso

// Self-healing tests for the cross-replica invalidation-bus subscriber. These
// live in package sso (NOT sso_test) so they can read the unexported degraded
// flag + set the test-only backoff base directly + prime the suspension cache —
// mirroring export_test.go's seams for the sibling signing-key aggregation loop,
// whose self-heal tests these are modeled on (signing_key_aggregation_selfheal_test.go).
//
// The headline property: when the bus Subscribe channel closes while the run
// context is still live (etcd watch death / leader change / network blip), the
// replica flips degraded (readiness errors, sso_invalidation_bus_up=0), then
// resubscribes and recovers — and a clean ctx-cancel exits WITHOUT degrading.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/cluster"
	clustermemory "github.com/yangwb1123/snaplink/platform/cluster/memory"
	"github.com/yangwb1123/snaplink/platform/metrics"
)

// flakyBus wraps the real in-process memory cluster.Bus so a test can force the
// CURRENT subscriber's channel closed mid-life (simulating an etcd watch death /
// network blip) while Publish + a subsequent Subscribe keep working — exactly
// the silent-failure mode the self-healing loop defends against. No production
// API changes: it composes the real Publish/Close and only intercepts Subscribe
// to relay the inner stream onto a test-owned channel it can force-close
// independently. Mirrors flakyRegistry in signing_key_aggregation_selfheal_test.go.
type flakyBus struct {
	inner *clustermemory.Bus

	mu      sync.Mutex
	subN    int                                  // count of Subscribe calls (for assertions)
	current chan cluster.Event                   // channel handed to the most recent subscriber
	relay   map[chan cluster.Event]chan struct{} // stop chan per relay goroutine
}

func newFlakyBus() *flakyBus {
	return &flakyBus{
		inner: clustermemory.New(),
		relay: make(map[chan cluster.Event]chan struct{}),
	}
}

func (f *flakyBus) Publish(ctx context.Context, evt cluster.Event) error {
	return f.inner.Publish(ctx, evt)
}

func (f *flakyBus) Close() error { return f.inner.Close() }

// Subscribe opens a real inner subscription and relays it onto a test-owned
// channel we can force-close independently. The relay goroutine stops when the
// inner channel closes, when forceClose fires, or when ctx is cancelled.
func (f *flakyBus) Subscribe(ctx context.Context) (<-chan cluster.Event, error) {
	src, err := f.inner.Subscribe(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan cluster.Event, 16)
	stop := make(chan struct{})

	f.mu.Lock()
	f.subN++
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
// simulating a watch death. Publish + the next Subscribe stay healthy.
func (f *flakyBus) forceClose() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil {
		if stop, ok := f.relay[f.current]; ok {
			close(stop)
		}
	}
}

func (f *flakyBus) subscribeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subN
}

var _ cluster.Bus = (*flakyBus)(nil)

// busWaitFor polls cond until it returns true or the deadline elapses. A local
// helper so this package-sso test file doesn't collide with the package-sso_test
// waitFor.
func busWaitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// busSeriesValue reads a single metric series by name + an exact label match
// (nil match = the no-label series) off the metrics Registry via Gather, with
// no testutil/dto dependency (keeps go.mod untouched). Returns 0 when no
// matching series exists. Mirrors seriesValue in the aggregation self-heal test.
func busSeriesValue(t *testing.T, m *metrics.Metrics, name string, labels map[string]string) float64 {
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

// busCountEvents returns how many events of type et the sink holds.
func busCountEvents(t *testing.T, sink *audit.MemorySink, et audit.EventType) int {
	t.Helper()
	evts, err := sink.Query(context.Background(), audit.Query{Type: et, Limit: 1000})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return len(evts)
}

// newBusTestServer builds a Server wired with the flaky bus + a tenant
// suspension cache (the observable side-effect of applyInvalidation in this
// build) + metrics + auditor, and shrinks the resubscribe backoff so the
// self-heal happens fast. 60ms keeps the degraded window wide enough to observe
// synchronously (mirrors the aggregation test's rationale) while staying well
// under the recovery timeouts.
func newBusTestServer(t *testing.T, bus cluster.Bus) (*Server, *metrics.Metrics, *audit.MemorySink) {
	t.Helper()
	m := metrics.New()
	sink := audit.NewMemorySink(0)
	rec := audit.New(sink)
	srv := NewServer(
		WithInvalidationBus(bus),
		WithTenantSuspensionCheck(time.Hour), // creates tenantSuspensionCache
		WithMetrics(m),
		WithAuditRecorder(rec),
	)
	srv.invalidationBusBackoffBase = 60 * time.Millisecond
	return srv, m, sink
}

// primeAndExpectInvalidated puts a suspended entry for tenantID, publishes a
// KindTenantSuspension Event, and waits for the subscriber loop to invalidate
// it — proving an Event is flowing end-to-end through the (current) subscription.
func primeAndExpectInvalidated(t *testing.T, srv *Server, bus cluster.Bus, tenantID string) {
	t.Helper()
	srv.tenantSuspensionCache.put(tenantID, true)
	if _, fresh := srv.tenantSuspensionCache.get(tenantID); !fresh {
		t.Fatalf("precondition: cache entry for %s should be fresh after put", tenantID)
	}
	if err := bus.Publish(context.Background(), cluster.Event{Kind: cluster.KindTenantSuspension, Key: tenantID}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !busWaitFor(2*time.Second, func() bool {
		_, fresh := srv.tenantSuspensionCache.get(tenantID)
		return !fresh // invalidated
	}) {
		t.Fatalf("invalidation Event never applied for tenant %s", tenantID)
	}
}

// TestInvalidationBus_SelfHealsOnChannelClose is the headline robustness
// property: when the bus Subscribe channel closes while the run context is still
// live, the replica (a) flips degraded — readiness errors and
// sso_invalidation_bus_up reads 0 — then (b) resubscribes and clears degraded —
// readiness ok, up back to 1, an Event flows again — and (c) emits exactly ONE
// degraded audit event + reconnect tick per transition (and one recovered).
func TestInvalidationBus_SelfHealsOnChannelClose(t *testing.T) {
	t.Parallel()
	bus := newFlakyBus()
	defer func() { _ = bus.Close() }()

	srv, m, sink := newBusTestServer(t, bus)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := srv.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Healthy from the first subscribe; an Event flows.
	if err := srv.InvalidationBusReady(); err != nil {
		t.Fatalf("expected ready after initial subscribe, got: %v", err)
	}
	if got := busSeriesValue(t, m, metrics.NameInvalidationBusUp, nil); got != 1 {
		t.Fatalf("invalidation_bus_up=%v after initial subscribe, want 1", got)
	}
	primeAndExpectInvalidated(t, srv, bus, "tenant-initial")

	// Kill the live subscription: the loop must flip degraded.
	bus.forceClose()
	if !busWaitFor(2*time.Second, func() bool {
		return srv.invalidationBusDegraded.Load()
	}) {
		t.Fatal("loop never went degraded after channel close")
	}
	// While degraded: readiness errors + gauge 0.
	if err := srv.InvalidationBusReady(); err == nil {
		t.Fatal("readiness must error while degraded")
	}
	if got := busSeriesValue(t, m, metrics.NameInvalidationBusUp, nil); got != 0 {
		t.Fatalf("invalidation_bus_up=%v while degraded, want 0", got)
	}

	// The loop resubscribes on its own (backoff is tiny): degraded clears.
	if !busWaitFor(3*time.Second, func() bool {
		return !srv.invalidationBusDegraded.Load() && bus.subscribeCount() >= 2
	}) {
		t.Fatalf("loop never recovered (degraded=%v subs=%d)",
			srv.invalidationBusDegraded.Load(), bus.subscribeCount())
	}
	if err := srv.InvalidationBusReady(); err != nil {
		t.Fatalf("readiness must recover after resubscribe, got: %v", err)
	}
	if !busWaitFor(time.Second, func() bool {
		return busSeriesValue(t, m, metrics.NameInvalidationBusUp, nil) == 1
	}) {
		t.Fatalf("invalidation_bus_up=%v after recovery, want 1",
			busSeriesValue(t, m, metrics.NameInvalidationBusUp, nil))
	}

	// An Event published AFTER recovery must be applied on the fresh
	// subscription (proves the resubscribe keeps draining).
	primeAndExpectInvalidated(t, srv, bus, "tenant-after-recovery")

	// Exactly one degraded + one recovered audit event for the single
	// transition (the degraded flag de-dupes per transition, not per retry),
	// and the reconnect counter shows one of each reason.
	if n := busCountEvents(t, sink, eventInvalidationBusDegraded); n != 1 {
		t.Fatalf("degraded audit events=%d, want exactly 1", n)
	}
	if n := busCountEvents(t, sink, eventInvalidationBusRecovered); n != 1 {
		t.Fatalf("recovered audit events=%d, want exactly 1", n)
	}
	if got := busSeriesValue(t, m, metrics.NameInvalidationBusReconnectsTotal,
		map[string]string{metrics.LabelReason: metrics.InvalidationBusReasonDegraded}); got != 1 {
		t.Fatalf("reconnects_total{reason=degraded}=%v, want 1", got)
	}
	if got := busSeriesValue(t, m, metrics.NameInvalidationBusReconnectsTotal,
		map[string]string{metrics.LabelReason: metrics.InvalidationBusReasonReconnected}); got != 1 {
		t.Fatalf("reconnects_total{reason=reconnected}=%v, want 1", got)
	}

	// Clean ctx-cancel must close done and must NOT flip degraded.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}
	if srv.invalidationBusDegraded.Load() {
		t.Fatal("clean ctx-cancel after recovery must leave the loop non-degraded")
	}
}

// TestInvalidationBus_CleanCancelNotDegraded locks the other half of the
// distinction: a graceful shutdown (ctx cancel) closes the subscription too,
// but the loop must exit WITHOUT going degraded — a drain must never trip
// /readyz or emit a degraded audit event. Mirrors
// TestSigningKeyAggregation_CleanCancelNotDegraded.
func TestInvalidationBus_CleanCancelNotDegraded(t *testing.T) {
	t.Parallel()
	bus := clustermemory.New()
	defer func() { _ = bus.Close() }()

	srv, _, sink := newBusTestServer(t, bus)

	ctx, cancel := context.WithCancel(context.Background())
	done, err := srv.StartInvalidationBus(ctx)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}

	if srv.invalidationBusDegraded.Load() {
		t.Fatal("clean ctx-cancel must not mark the loop degraded")
	}
	if n := busCountEvents(t, sink, eventInvalidationBusDegraded); n != 0 {
		t.Fatalf("clean cancel emitted %d degraded audit events, want 0", n)
	}
}

// TestInvalidationBus_NilBusNoGoroutine proves the zero-regression contract:
// with no bus wired StartInvalidationBus returns an already-closed channel + nil
// error, and readiness is never degraded (the loop never ran).
func TestInvalidationBus_NilBusNoGoroutine(t *testing.T) {
	t.Parallel()
	srv := NewServer()
	done, err := srv.StartInvalidationBus(context.Background())
	if err != nil {
		t.Fatalf("nil-bus start returned error: %v", err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("nil-bus start did not return an already-closed channel")
	}
	if err := srv.InvalidationBusReady(); err != nil {
		t.Fatalf("nil-bus readiness must be nil, got: %v", err)
	}
}
