package sso_test

// Re-seed-on-recovery tests for the invalidation-bus self-heal loop. The
// channel-close/degraded/recover mechanics are covered by the package-sso
// tests in invalidation_bus_selfheal_test.go; these lock the CONVERGENCE half
// — state changed through the durable stores while the subscription was dead
// is re-applied before readiness goes green. They live in package sso_test
// (like the signing-key aggregation self-heal tests) because they wire the
// REAL defaultimpl Ed25519 issuer + RevocationStore, and defaultimpl imports
// interfaces/sso — a package-sso test importing it would be an import cycle.
// Unexported knobs are reached through export_test.go seams.

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/metrics"
)

// countEventsWithMeta returns how many events of type et carry
// Metadata[key] == val.
func countEventsWithMeta(t *testing.T, sink *audit.MemorySink, et audit.EventType, key, val string) int {
	t.Helper()
	evts, err := sink.Query(context.Background(), audit.Query{Type: et, Limit: 1000})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	n := 0
	for _, e := range evts {
		if e.Metadata[key] == val {
			n++
		}
	}
	return n
}

// reseedPrimeAndExpectInvalidated puts a suspended entry for tenantID,
// publishes a KindTenantSuspension Event, and waits for the subscriber loop to
// invalidate it — proving an Event flows end-to-end through the (current)
// subscription. The sso_test twin of primeAndExpectInvalidated, built on the
// export seams.
func reseedPrimeAndExpectInvalidated(t *testing.T, srv *sso.Server, bus cluster.Bus, tenantID string) {
	t.Helper()
	srv.PutTenantSuspensionForTest(tenantID, true)
	if !srv.TenantSuspensionFreshForTest(tenantID) {
		t.Fatalf("precondition: cache entry for %s should be fresh after put", tenantID)
	}
	if err := bus.Publish(context.Background(), cluster.Event{Kind: cluster.KindTenantSuspension, Key: tenantID}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		return !srv.TenantSuspensionFreshForTest(tenantID) // invalidated
	}) {
		t.Fatalf("invalidation Event never applied for tenant %s", tenantID)
	}
}

// newReseedTestServer builds a Server wired with the flaky bus + a REAL
// Ed25519 issuer backed by the given durable RevocationStore (the exact
// SeedRevocations seam boot uses via serverbuildsign.seedRevocations) + the
// suspension cache + metrics + auditor. The 300ms backoff base keeps the
// degraded window wide enough that the mid-outage durable-store writes these
// tests perform can never race the loop's own recovery (the writes are
// microseconds; the first resubscribe attempt is 300ms out), while recovery
// still lands well inside the wait budgets.
func newReseedTestServer(t *testing.T, bus cluster.Bus, store defaultimpl.RevocationStore) (*sso.Server, *defaultimpl.Ed25519JWTIssuer, *audit.MemorySink) {
	t.Helper()
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519RevocationStore(store))
	sink := audit.NewMemorySink(0)
	srv := sso.NewServer(
		sso.WithInvalidationBus(bus),
		sso.WithTenantSuspensionCheck(time.Hour), // creates the suspension cache
		sso.WithTokenIssuer("jwt", iss),
		sso.WithMetrics(metrics.New()),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	srv.SetInvalidationBusBackoffBaseForTest(300 * time.Millisecond)
	return srv, iss, sink
}

// TestInvalidationBus_ReseedsOnRecovery is the convergence property: state
// changed through the DURABLE stores while the subscription was dead (whose
// broadcast this replica therefore missed) is re-applied on recovery — the
// revocation deny-set is re-seeded from the RevocationStore and the stale
// suspension-cache entry is flushed so the next check re-fetches — and the
// single recovered audit event carries the re_seeded=true marker.
func TestInvalidationBus_ReseedsOnRecovery(t *testing.T) {
	t.Parallel()
	bus := sso.NewFlakyBusForTest()
	defer func() { _ = bus.Close() }()

	revStore := defaultimpl.NewMemoryRevocationStore()
	srv, iss, sink := newReseedTestServer(t, bus, revStore)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := srv.StartInvalidationBus(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "user-1", ClientID: "client-1"}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("precondition: fresh token must validate, got: %v", err)
	}

	// Kill the live subscription.
	bus.ForceCloseForTest()
	if !waitFor(2*time.Second, func() bool { return srv.InvalidationBusDegradedForTest() }) {
		t.Fatal("loop never went degraded after channel close")
	}

	// While degraded: a PEER replica revokes the token — its bus broadcast is
	// lost on this replica, but the shared durable-store write is not — and a
	// tenant suspension flips while our cache still holds the stale entry the
	// lost KindTenantSuspension event would have invalidated.
	if err := revStore.Revoke(context.Background(), tok.AccessToken, sso.JWTExpUnsafeForTest(tok.AccessToken)); err != nil {
		t.Fatalf("durable store revoke: %v", err)
	}
	srv.PutTenantSuspensionForTest("tenant-stale", false)

	// The local deny-set never saw the revocation: the token still validates
	// here — exactly the gap re-seed-on-recovery closes.
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err != nil {
		t.Fatalf("mid-outage validate must still pass (deny-set not re-seeded yet), got: %v", err)
	}

	// The loop resubscribes, re-seeds, and clears degraded on its own.
	if !waitFor(5*time.Second, func() bool {
		return !srv.InvalidationBusDegradedForTest() && bus.SubscribeCountForTest() >= 2
	}) {
		t.Fatalf("loop never recovered (degraded=%v subs=%d)",
			srv.InvalidationBusDegradedForTest(), bus.SubscribeCountForTest())
	}

	// The missed revocation is re-applied from the durable store.
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("revocation missed during the outage must be re-applied on recovery")
	}
	// The stale suspension entry is flushed, so the next check re-fetches from
	// the authoritative tenant store instead of honoring the stale value.
	if srv.TenantSuspensionFreshForTest("tenant-stale") {
		t.Fatal("stale suspension-cache entry must be flushed on recovery")
	}
	// Fresh events still flow end-to-end on the new subscription.
	reseedPrimeAndExpectInvalidated(t, srv, bus, "tenant-after-reseed")

	// Exactly one recovered event, and it carries the re-seeded marker.
	if n := countEvents(t, sink, sso.EventInvalidationBusRecoveredForTest); n != 1 {
		t.Fatalf("recovered audit events=%d, want exactly 1", n)
	}
	if n := countEventsWithMeta(t, sink, sso.EventInvalidationBusRecoveredForTest, sso.InvalidationBusMetaReseededForTest, "true"); n != 1 {
		t.Fatalf("recovered events with %s=true: %d, want exactly 1", sso.InvalidationBusMetaReseededForTest, n)
	}
}

// failingRevocationStore wraps the real memory RevocationStore but fails Load
// while failing is set — injecting a durable-store outage at the same
// boundary flakyBus injects the bus outage (a purpose-built failure wrapper
// around the real impl, not a mock). Revoke/Prune pass through so the "peer
// revokes during the outage" write still lands.
type failingRevocationStore struct {
	inner   *defaultimpl.MemoryRevocationStore
	failing atomic.Bool
}

func (f *failingRevocationStore) Revoke(ctx context.Context, token string, expUnix int64) error {
	return f.inner.Revoke(ctx, token, expUnix)
}

func (f *failingRevocationStore) Load(ctx context.Context) (map[string]int64, error) {
	if f.failing.Load() {
		return nil, errors.New("revocation store unavailable")
	}
	return f.inner.Load(ctx)
}

func (f *failingRevocationStore) Prune(ctx context.Context, nowUnix int64) error {
	return f.inner.Prune(ctx, nowUnix)
}

var _ defaultimpl.RevocationStore = (*failingRevocationStore)(nil)

// TestInvalidationBus_StaysDegradedUntilReseedSucceeds locks the fail-safe
// half: when the resubscribe SUCCEEDS but the re-seed fails, readiness must
// stay not-ready (never green on a partial re-seed), each failed attempt is
// audited with reason=reseed_failed, and once the seeder heals the loop
// re-seeds, clears degraded, and the missed revocation is applied.
func TestInvalidationBus_StaysDegradedUntilReseedSucceeds(t *testing.T) {
	t.Parallel()
	bus := sso.NewFlakyBusForTest()
	defer func() { _ = bus.Close() }()

	revStore := &failingRevocationStore{inner: defaultimpl.NewMemoryRevocationStore()}
	srv, iss, sink := newReseedTestServer(t, bus, revStore)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := srv.StartInvalidationBus(ctx); err != nil {
		t.Fatalf("start: %v", err)
	}

	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "user-2", ClientID: "client-2"}, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Seeder outage begins BEFORE the watch dies so the very first recovery
	// attempt hits it.
	revStore.failing.Store(true)
	bus.ForceCloseForTest()
	if !waitFor(2*time.Second, func() bool { return srv.InvalidationBusDegradedForTest() }) {
		t.Fatal("loop never went degraded after channel close")
	}
	// A peer's revoke lands in the durable store during the outage.
	if err := revStore.Revoke(context.Background(), tok.AccessToken, sso.JWTExpUnsafeForTest(tok.AccessToken)); err != nil {
		t.Fatalf("durable store revoke: %v", err)
	}

	// The resubscribe itself succeeds (subscribe count grows) yet degraded
	// persists and each failed re-seed is audited with its distinct reason.
	if !waitFor(5*time.Second, func() bool {
		return bus.SubscribeCountForTest() >= 2 &&
			countEventsWithMeta(t, sink, sso.EventInvalidationBusDegradedForTest, "reason", sso.InvalidationBusReseedFailedReasonForTest) >= 1
	}) {
		t.Fatalf("no reseed_failed degraded audit after resubscribe (subs=%d)", bus.SubscribeCountForTest())
	}
	if !srv.InvalidationBusDegradedForTest() {
		t.Fatal("degraded must persist while the re-seed keeps failing")
	}
	if err := srv.InvalidationBusReady(); err == nil {
		t.Fatal("readiness must stay not-ready until the re-seed succeeds")
	}

	// Seeder heals: the next backoff cycle re-seeds and clears degraded.
	revStore.failing.Store(false)
	if !waitFor(10*time.Second, func() bool { return !srv.InvalidationBusDegradedForTest() }) {
		t.Fatal("loop never recovered after the seeder healed")
	}
	if err := srv.InvalidationBusReady(); err != nil {
		t.Fatalf("readiness must clear after a successful re-seed, got: %v", err)
	}
	// The revocation missed during the outage is applied by the healed re-seed.
	if _, err := iss.Validate(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("missed revocation must be re-applied once the re-seed succeeds")
	}
	// Recovered exactly once, marked re-seeded. Polled: the loop flips the
	// degraded flag first and records the recovered audit event just after,
	// so a raw read here can race the Record by a few microseconds.
	if !waitFor(2*time.Second, func() bool {
		return countEventsWithMeta(t, sink, sso.EventInvalidationBusRecoveredForTest, sso.InvalidationBusMetaReseededForTest, "true") == 1
	}) {
		t.Fatalf("recovered re_seeded=true events=%d, want exactly 1",
			countEventsWithMeta(t, sink, sso.EventInvalidationBusRecoveredForTest, sso.InvalidationBusMetaReseededForTest, "true"))
	}
}
