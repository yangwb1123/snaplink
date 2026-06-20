package sso_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/signingkeys"
	signingkeysmemory "github.com/snaplink/sso/platform/signingkeys/memory"
	"github.com/snaplink/sso/shared/core"
)

// gaugeValue reads a no-label gauge/counter's current value from the metrics
// registry via Gather (no testutil dependency, so no go.mod churn). Returns 0
// when the metric has not been written yet (no series).
func gaugeValue(t *testing.T, m *metrics.Metrics, name string) float64 {
	t.Helper()
	return seriesValue(t, m, name, nil)
}

// seriesValue reads a single metric series by name + an exact label match
// (nil match = the no-label series). Returns 0 when no matching series exists.
// Walks the gathered MetricFamily directly (as the existing async-sink test
// does) so it names no prometheus dto type — keeping client_model indirect and
// go.mod untouched.
func seriesValue(t *testing.T, m *metrics.Metrics, name string, labels map[string]string) float64 {
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

// flakyRegistry wraps the real in-process memory registry so a test can force
// the CURRENT subscriber's channel closed mid-life (simulating an etcd watch
// death / network blip) while List + Publish + a subsequent Subscribe keep
// working — exactly the silent-failure mode the self-healing loop defends
// against. No production API changes: it composes the real Publish/List/Close
// and only intercepts Subscribe to retain a handle on the channel it hands the
// loop.
type flakyRegistry struct {
	inner *signingkeysmemory.Registry

	mu      sync.Mutex
	subN    int                               // count of Subscribe calls (for assertions)
	current chan signingkeys.Event            // channel handed to the most recent subscriber
	relay   map[chan signingkeys.Event]func() // stop func per relay goroutine
}

func newFlakyRegistry() *flakyRegistry {
	return &flakyRegistry{
		inner: signingkeysmemory.New(),
		relay: make(map[chan signingkeys.Event]func()),
	}
}

func (f *flakyRegistry) Publish(ctx context.Context, ann signingkeys.Announcement) error {
	return f.inner.Publish(ctx, ann)
}

func (f *flakyRegistry) List(ctx context.Context) ([]signingkeys.Announcement, error) {
	return f.inner.List(ctx)
}

func (f *flakyRegistry) Close() error { return f.inner.Close() }

// Subscribe opens a real inner subscription and relays it onto a test-owned
// channel we can force-close independently. The relay goroutine stops when the
// inner channel closes, when forceClose fires, or when ctx is cancelled.
func (f *flakyRegistry) Subscribe(ctx context.Context) (<-chan signingkeys.Event, error) {
	src, err := f.inner.Subscribe(ctx)
	if err != nil {
		return nil, err
	}
	out := make(chan signingkeys.Event, 16)
	stop := make(chan struct{})

	f.mu.Lock()
	f.subN++
	f.current = out
	f.relay[out] = func() { close(stop) }
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
// simulating a watch death. List/Publish/next Subscribe stay healthy.
func (f *flakyRegistry) forceClose() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.current != nil {
		if stop, ok := f.relay[f.current]; ok {
			stop()
		}
	}
}

func (f *flakyRegistry) subscribeCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.subN
}

var _ signingkeys.Registry = (*flakyRegistry)(nil)

// TestSigningKeyAggregation_SelfHealsOnChannelClose is the headline robustness
// property: when the registry's Subscribe channel closes while the run context
// is still live, the replica (a) flips degraded — readiness errors and
// sso_signing_key_aggregation_up reads 0 — then (b) resubscribes and clears
// degraded — readiness ok, up back to 1 — and (c) emits exactly ONE degraded
// audit event per transition (and one recovered).
func TestSigningKeyAggregation_SelfHealsOnChannelClose(t *testing.T) {
	reg := newFlakyRegistry()
	defer func() { _ = reg.Close() }()

	m := metrics.New()
	sink := audit.NewMemorySink(0)
	rec := audit.New(sink)

	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithSharedSigningKeyRegistry(reg),
		sso.WithSigningKeyReplicaID("replica-local"),
		sso.WithMetrics(m),
		sso.WithAuditRecorder(rec),
	)
	// Shrink the backoff so the resubscribe happens fast, but keep the
	// degraded window WIDE ENOUGH to be observable by the synchronous
	// degraded-state assertions below: with a 5ms backoff the loop can
	// resubscribe (clearing degraded + flipping the gauge back to 1)
	// between waitFor() detecting degraded and the immediate gauge==0
	// check, a latent timing race that surfaces under -cpu=1 / loaded CI.
	// 60ms is still well under the recovery timeouts (2-3s), so the
	// self-heal assertions stay fast.
	srv.SetSigningKeyAggBackoffBaseForTest(60 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done, err := srv.StartSigningKeyAggregation(ctx)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	// Healthy from the first subscribe.
	if err := srv.SigningKeyAggregationReady(); err != nil {
		t.Fatalf("expected ready after initial subscribe, got: %v", err)
	}
	if got := gaugeValue(t, m, metrics.NameSigningKeyAggregationUp); got != 1 {
		t.Fatalf("aggregation_up=%v after initial subscribe, want 1", got)
	}

	// Kill the live subscription: the loop must flip degraded.
	reg.forceClose()
	if !waitFor(2*time.Second, func() bool {
		return srv.SigningKeyAggDegradedForTest()
	}) {
		t.Fatal("loop never went degraded after channel close")
	}
	// While degraded: readiness errors + gauge 0.
	if err := srv.SigningKeyAggregationReady(); err == nil {
		t.Fatal("readiness must error while degraded")
	}
	if got := gaugeValue(t, m, metrics.NameSigningKeyAggregationUp); got != 0 {
		t.Fatalf("aggregation_up=%v while degraded, want 0", got)
	}

	// The loop resubscribes on its own (backoff is tiny): degraded clears.
	if !waitFor(3*time.Second, func() bool {
		return !srv.SigningKeyAggDegradedForTest() && reg.subscribeCount() >= 2
	}) {
		t.Fatalf("loop never recovered (degraded=%v subs=%d)",
			srv.SigningKeyAggDegradedForTest(), reg.subscribeCount())
	}
	if err := srv.SigningKeyAggregationReady(); err != nil {
		t.Fatalf("readiness must recover after resubscribe, got: %v", err)
	}
	if !waitFor(time.Second, func() bool {
		return gaugeValue(t, m, metrics.NameSigningKeyAggregationUp) == 1
	}) {
		t.Fatalf("aggregation_up=%v after recovery, want 1", gaugeValue(t, m, metrics.NameSigningKeyAggregationUp))
	}

	// Exactly one degraded + one recovered audit event for the single
	// transition (the degraded flag de-dupes per transition, not per retry).
	if n := countEvents(t, sink, audit.EventSigningKeyAggregationDegraded); n != 1 {
		t.Fatalf("degraded audit events=%d, want exactly 1", n)
	}
	if n := countEvents(t, sink, audit.EventSigningKeyAggregationRecovered); n != 1 {
		t.Fatalf("recovered audit events=%d, want exactly 1", n)
	}

	// A peer published AFTER recovery must be adopted on the fresh
	// subscription (proves the resubscribe re-seeds + keeps draining).
	peer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://peer.example"))
	peerJWK := jwkForAlg(t, peer)
	if err := reg.Publish(ctx, signingkeys.Announcement{ReplicaID: "replica-peer", Keys: []core.JWK{peerJWK}}); err != nil {
		t.Fatalf("peer publish: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		return jwksHasKidSrv(serverJWKS(t, srv), peer.KeyID())
	}) {
		t.Fatalf("recovered loop did not adopt peer kid %s", peer.KeyID())
	}

	// Clean ctx-cancel must close done and must NOT mark degraded.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}
}

// TestSigningKeyAggregation_CleanCancelNotDegraded locks the other half of the
// distinction: a graceful shutdown (ctx cancel) closes the subscription too,
// but the loop must exit WITHOUT going degraded — a drain must never trip
// /readyz or emit a degraded audit event.
func TestSigningKeyAggregation_CleanCancelNotDegraded(t *testing.T) {
	reg := signingkeysmemory.New()
	defer func() { _ = reg.Close() }()

	sink := audit.NewMemorySink(0)
	rec := audit.New(sink)
	m := metrics.New()

	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://sso.example"))
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, iss),
		sso.WithSharedSigningKeyRegistry(reg),
		sso.WithSigningKeyReplicaID("replica-local"),
		sso.WithMetrics(m),
		sso.WithAuditRecorder(rec),
	)

	ctx, cancel := context.WithCancel(context.Background())
	done, err := srv.StartSigningKeyAggregation(ctx)
	if err != nil {
		t.Fatalf("start: %v", err)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}

	if srv.SigningKeyAggDegradedForTest() {
		t.Fatal("clean ctx-cancel must not mark the loop degraded")
	}
	if n := countEvents(t, sink, audit.EventSigningKeyAggregationDegraded); n != 0 {
		t.Fatalf("clean cancel emitted %d degraded audit events, want 0", n)
	}
}

// countEvents returns how many events of type et the sink holds.
func countEvents(t *testing.T, sink *audit.MemorySink, et audit.EventType) int {
	t.Helper()
	evts, err := sink.Query(context.Background(), audit.Query{Type: et, Limit: 1000})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	return len(evts)
}

// adoptionErrorTotal reads the bounded adoption-error counter for one reason.
func adoptionErrorTotal(t *testing.T, m *metrics.Metrics, reason string) float64 {
	t.Helper()
	return seriesValue(t, m, metrics.NameSigningKeyAdoptionErrorsTotal, map[string]string{metrics.LabelReason: reason})
}

// TestSigningKeyAggregation_AdoptionErrorMetrics proves the two adoption
// failure modes increment sso_signing_key_adoption_errors_total under the
// right bounded reason: a malformed peer JWK bumps {reason=decode}, and a
// peer key whose kid collides with the local signing key (decodes fine, issuer
// rejects AdoptVerifyKey) bumps {reason=adopt}. Both stay fail-open (the key is
// skipped, nothing else changes).
func TestSigningKeyAggregation_AdoptionErrorMetrics(t *testing.T) {
	m := metrics.New()
	localIss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("https://sso.example"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	srv := sso.NewServer(
		sso.WithTokenIssuer(sso.TokenStrategyJWT, localIss),
		sso.WithMetrics(m),
	)
	srv.SetReplicaIDForTest("replica-local")

	// decode path: a real Ed25519 JWK with a corrupted X coordinate.
	peer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("https://peer.example"))
	badDecode := jwkForAlg(t, peer)
	badDecode.Kid = "bad-decode-kid"
	badDecode.X = "!!!notbase64!!!"
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-decode", Keys: []core.JWK{badDecode}},
	})
	if got := adoptionErrorTotal(t, m, metrics.AdoptionReasonDecode); got != 1 {
		t.Fatalf("decode adoption errors=%v, want 1", got)
	}

	// adopt path: a valid peer JWK whose kid collides with the LOCAL signing
	// key. It decodes, but AdoptVerifyKey rejects the collision.
	collide := jwkForAlg(t, peer)
	collide.Kid = localIss.KeyID() // collide with the local signing kid
	srv.ApplySigningKeyEventForTest(signingkeys.Event{
		Type:         signingkeys.EventKeysUpserted,
		Announcement: signingkeys.Announcement{ReplicaID: "peer-adopt", Keys: []core.JWK{collide}},
	})
	if got := adoptionErrorTotal(t, m, metrics.AdoptionReasonAdopt); got != 1 {
		t.Fatalf("adopt adoption errors=%v, want 1", got)
	}
	// The decode counter must not have moved on the adopt-failure path.
	if got := adoptionErrorTotal(t, m, metrics.AdoptionReasonDecode); got != 1 {
		t.Fatalf("decode counter changed on the adopt path: %v, want 1", got)
	}
}
