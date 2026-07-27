package sso

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/platform/cluster"
	clustermemory "github.com/yangwb1123/snaplink/platform/cluster/memory"
)

// These are direct-call unit tests for the data-residency enforcement
// engine. checkTenantResidency is unexported and NOT yet wired into any
// handler (the middleware + login gate land in a follow-up commit), so the
// only way to exercise it is from within package sso against a constructed
// *Server. The suspension check is the structural template; these mirror it
// where applicable (memory tenant store, fail-open outage, cache amortization,
// invalidation forces refetch).

const (
	trTenantID = "tenant-tr"
)

// newResidencyServer builds a Server with a memory tenant store seeded with
// one tenant and the residency check enabled. enabled=false skips the option
// entirely so the nil-default byte-identical path is exercised.
func newResidencyServer(t *testing.T, enabled bool, seed *tenant.Tenant) *Server {
	t.Helper()
	tstore := tenantmemory.New()
	if seed != nil {
		if err := tstore.PutTenant(context.Background(), seed); err != nil {
			t.Fatalf("PutTenant: %v", err)
		}
	}
	opts := []Option{WithTenantStore(tstore)}
	if enabled {
		opts = append(opts, WithTenantResidencyCheck(time.Minute))
	}
	return NewServer(opts...)
}

func constrainedTenant() *tenant.Tenant {
	return &tenant.Tenant{
		ID: trTenantID, Slug: "tr", Name: "tr", Status: tenant.StatusActive,
		HomeRegion:     "eu-west-1",
		AllowedRegions: []string{"eu-west-1", "eu-central-1"},
	}
}

// TestResidency_NotEnabledIsByteIdentical proves a server that never calls
// WithTenantResidencyCheck never enforces — checkTenantResidency returns nil
// even for a fully-constrained tenant served from a disallowed region. This
// is the nil-default byte-identical guarantee.
func TestResidency_NotEnabledIsByteIdentical(t *testing.T) {
	t.Parallel()
	srv := newResidencyServer(t, false, constrainedTenant())
	if srv.tenantResidencyCache != nil {
		t.Fatal("residency cache allocated without WithTenantResidencyCheck")
	}
	for _, isWrite := range []bool{false, true} {
		if err := srv.checkTenantResidency(context.Background(), trTenantID, "us-east-1", isWrite); err != nil {
			t.Fatalf("not-enabled check (isWrite=%v) = %v want nil", isWrite, err)
		}
	}
}

// TestResidency_EmptyServingRegionUnconstrained: no resolved serving region
// means unconstrained (region is a routing signal; absence = anywhere).
func TestResidency_EmptyServingRegionUnconstrained(t *testing.T) {
	t.Parallel()
	srv := newResidencyServer(t, true, constrainedTenant())
	if err := srv.checkTenantResidency(context.Background(), trTenantID, "", false); err != nil {
		t.Fatalf("empty serving region = %v want nil", err)
	}
}

// TestResidency_EmptyTenantUnconstrained: no tenant binding → nothing to gate.
func TestResidency_EmptyTenantUnconstrained(t *testing.T) {
	t.Parallel()
	srv := newResidencyServer(t, true, constrainedTenant())
	if err := srv.checkTenantResidency(context.Background(), "", "us-east-1", false); err != nil {
		t.Fatalf("empty tenant = %v want nil", err)
	}
}

// TestResidency_UnconstrainedTenant: a tenant with no HomeRegion accepts any
// serving region for reads and writes.
func TestResidency_UnconstrainedTenant(t *testing.T) {
	t.Parallel()
	srv := newResidencyServer(t, true, &tenant.Tenant{
		ID: trTenantID, Slug: "tr", Status: tenant.StatusActive,
		// HomeRegion empty, AllowedRegions nil, EnforceWrites false.
	})
	for _, isWrite := range []bool{false, true} {
		if err := srv.checkTenantResidency(context.Background(), trTenantID, "us-east-1", isWrite); err != nil {
			t.Fatalf("unconstrained tenant (isWrite=%v) = %v want nil", isWrite, err)
		}
	}
}

// TestResidency_HomeRegionAlwaysAllowed: serving from the home region is
// allowed for both reads and writes regardless of EnforceWrites.
func TestResidency_HomeRegionAlwaysAllowed(t *testing.T) {
	t.Parallel()
	seed := constrainedTenant()
	seed.EnforceWrites = true
	srv := newResidencyServer(t, true, seed)
	for _, isWrite := range []bool{false, true} {
		if err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-west-1", isWrite); err != nil {
			t.Fatalf("home region (isWrite=%v) = %v want nil", isWrite, err)
		}
	}
}

// TestResidency_RegionNotAllowed: a serving region outside AllowedRegions is
// rejected with ErrRegionNotAllowed for both reads and writes.
func TestResidency_RegionNotAllowed(t *testing.T) {
	t.Parallel()
	srv := newResidencyServer(t, true, constrainedTenant())
	for _, isWrite := range []bool{false, true} {
		err := srv.checkTenantResidency(context.Background(), trTenantID, "us-east-1", isWrite)
		if !errors.Is(err, region.ErrRegionNotAllowed) {
			t.Fatalf("disallowed region (isWrite=%v) = %v want ErrRegionNotAllowed", isWrite, err)
		}
	}
}

// TestResidency_AllowedNonHomeWriteMatrix exercises the isWrite x EnforceWrites
// matrix for a serving region that IS in AllowedRegions but is NOT the home
// region:
//   - read (any EnforceWrites)            → nil
//   - write + EnforceWrites=false         → nil (advisory, fail-open default)
//   - write + EnforceWrites=true          → ErrResidencyViolation
func TestResidency_AllowedNonHomeWriteMatrix(t *testing.T) {
	t.Parallel()
	const serving region.ID = "eu-central-1" // in AllowedRegions, != HomeRegion

	t.Run("read does not enforce", func(t *testing.T) {
		seed := constrainedTenant()
		seed.EnforceWrites = true
		srv := newResidencyServer(t, true, seed)
		if err := srv.checkTenantResidency(context.Background(), trTenantID, serving, false); err != nil {
			t.Fatalf("allowed-non-home read = %v want nil", err)
		}
	})

	t.Run("write without EnforceWrites is advisory", func(t *testing.T) {
		seed := constrainedTenant()
		seed.EnforceWrites = false
		srv := newResidencyServer(t, true, seed)
		if err := srv.checkTenantResidency(context.Background(), trTenantID, serving, true); err != nil {
			t.Fatalf("allowed-non-home write (EnforceWrites=false) = %v want nil", err)
		}
	})

	t.Run("write with EnforceWrites is a violation", func(t *testing.T) {
		seed := constrainedTenant()
		seed.EnforceWrites = true
		srv := newResidencyServer(t, true, seed)
		err := srv.checkTenantResidency(context.Background(), trTenantID, serving, true)
		if !errors.Is(err, region.ErrResidencyViolation) {
			t.Fatalf("allowed-non-home write (EnforceWrites=true) = %v want ErrResidencyViolation", err)
		}
	})
}

// TestResidency_EnforceWritesNoAllowedList: when AllowedRegions is empty the
// region is unconstrained for reads, but a write under EnforceWrites still
// can't leave HomeRegion. (HomeRegion set, AllowedRegions empty.)
func TestResidency_EnforceWritesNoAllowedList(t *testing.T) {
	t.Parallel()
	srv := newResidencyServer(t, true, &tenant.Tenant{
		ID: trTenantID, Slug: "tr", Status: tenant.StatusActive,
		HomeRegion:    "eu-west-1",
		EnforceWrites: true,
	})
	// Read from a non-home region with no AllowedRegions list → nil.
	if err := srv.checkTenantResidency(context.Background(), trTenantID, "us-east-1", false); err != nil {
		t.Fatalf("read with empty allowed list = %v want nil", err)
	}
	// Write from a non-home region under EnforceWrites → violation.
	err := srv.checkTenantResidency(context.Background(), trTenantID, "us-east-1", true)
	if !errors.Is(err, region.ErrResidencyViolation) {
		t.Fatalf("write with empty allowed list + EnforceWrites = %v want ErrResidencyViolation", err)
	}
}

// capturingLogger records the count of Error calls so the fail-open path can
// assert it logged the outage.
type capturingLogger struct{ errors atomic.Int64 }

func (l *capturingLogger) Info(string, ...any)  {}
func (l *capturingLogger) Debug(string, ...any) {}
func (l *capturingLogger) Error(string, ...any) { l.errors.Add(1) }

// erroringTenantStore returns an error on every GetTenant (fault injection,
// not a mock — there is no in-memory "always errors" peer). It satisfies the
// full tenant.Store so it can be wired via WithTenantStore.
type erroringTenantStore struct{}

func (*erroringTenantStore) GetTenant(context.Context, string) (*tenant.Tenant, error) {
	return nil, errors.New("tenant store down")
}
func (*erroringTenantStore) ListTenants(context.Context) ([]*tenant.Tenant, error) { return nil, nil }
func (*erroringTenantStore) PutTenant(context.Context, *tenant.Tenant) error       { return nil }
func (*erroringTenantStore) DeleteTenant(context.Context, string) error            { return nil }
func (*erroringTenantStore) GetDomain(context.Context, string) (*tenant.Domain, error) {
	return nil, tenant.ErrDomainNotFound
}
func (*erroringTenantStore) ListDomains(context.Context) ([]*tenant.Domain, error) { return nil, nil }
func (*erroringTenantStore) ListDomainsByTenant(context.Context, string) ([]*tenant.Domain, error) {
	return nil, nil
}
func (*erroringTenantStore) PutDomain(context.Context, *tenant.Domain) error { return nil }
func (*erroringTenantStore) DeleteDomain(context.Context, string) error      { return nil }
func (*erroringTenantStore) Close() error                                    { return nil }

// TestResidency_StoreOutageFailsOpen proves a tenant-store outage allows the
// request (residency is an AP/governance control, not a security CP
// invariant) AND logs the failure.
func TestResidency_StoreOutageFailsOpen(t *testing.T) {
	t.Parallel()
	logger := &capturingLogger{}
	srv := NewServer(
		WithLogger(logger),
		WithTenantStore(&erroringTenantStore{}),
		WithTenantResidencyCheck(time.Minute),
	)
	// A write into a non-home region: would be a violation if the policy
	// resolved, but the store is down, so it fails open.
	if err := srv.checkTenantResidency(context.Background(), trTenantID, "us-east-1", true); err != nil {
		t.Fatalf("store outage = %v want nil (fail-open)", err)
	}
	if n := logger.errors.Load(); n != 1 {
		t.Fatalf("fail-open did not log: error calls = %d want 1", n)
	}
}

// countingResidencyStore counts GetTenant calls to assert cache behavior.
type countingResidencyStore struct {
	inner *tenantmemory.Store
	calls atomic.Int64
}

func (c *countingResidencyStore) GetTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	c.calls.Add(1)
	return c.inner.GetTenant(ctx, id)
}
func (c *countingResidencyStore) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	return c.inner.ListTenants(ctx)
}
func (c *countingResidencyStore) PutTenant(ctx context.Context, t *tenant.Tenant) error {
	return c.inner.PutTenant(ctx, t)
}
func (c *countingResidencyStore) DeleteTenant(ctx context.Context, id string) error {
	return c.inner.DeleteTenant(ctx, id)
}
func (c *countingResidencyStore) GetDomain(ctx context.Context, h string) (*tenant.Domain, error) {
	return c.inner.GetDomain(ctx, h)
}
func (c *countingResidencyStore) ListDomains(ctx context.Context) ([]*tenant.Domain, error) {
	return c.inner.ListDomains(ctx)
}
func (c *countingResidencyStore) ListDomainsByTenant(ctx context.Context, id string) ([]*tenant.Domain, error) {
	return c.inner.ListDomainsByTenant(ctx, id)
}
func (c *countingResidencyStore) PutDomain(ctx context.Context, d *tenant.Domain) error {
	return c.inner.PutDomain(ctx, d)
}
func (c *countingResidencyStore) DeleteDomain(ctx context.Context, h string) error {
	return c.inner.DeleteDomain(ctx, h)
}
func (c *countingResidencyStore) Close() error { return c.inner.Close() }

func newCountingResidencyServer(t *testing.T, seed *tenant.Tenant) (*Server, *countingResidencyStore) {
	t.Helper()
	inner := tenantmemory.New()
	if err := inner.PutTenant(context.Background(), seed); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	counter := &countingResidencyStore{inner: inner}
	srv := NewServer(
		WithTenantStore(counter),
		WithTenantResidencyCheck(time.Hour),
	)
	return srv, counter
}

// TestResidency_CacheAmortizesLookups: after the first resolution every
// subsequent check hits the cache, so the tenant store is read exactly once.
func TestResidency_CacheAmortizesLookups(t *testing.T) {
	t.Parallel()
	srv, counter := newCountingResidencyServer(t, constrainedTenant())
	for i := 0; i < 20; i++ {
		if err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-west-1", false); err != nil {
			t.Fatalf("check[%d]: %v", i, err)
		}
	}
	if n := counter.calls.Load(); n != 1 {
		t.Fatalf("tenant store calls = %d want 1 (cache hit on every subsequent check)", n)
	}
}

// TestResidency_InvalidateForcesRefetch: InvalidateTenantResidencyCache drops
// the cached policy so the next check re-reads the store.
func TestResidency_InvalidateForcesRefetch(t *testing.T) {
	t.Parallel()
	srv, counter := newCountingResidencyServer(t, constrainedTenant())

	if err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-west-1", false); err != nil {
		t.Fatalf("first check: %v", err)
	}
	if n := counter.calls.Load(); n != 1 {
		t.Fatalf("first-check calls = %d want 1", n)
	}
	srv.InvalidateTenantResidencyCache(trTenantID)
	if err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-west-1", false); err != nil {
		t.Fatalf("post-invalidate check: %v", err)
	}
	if n := counter.calls.Load(); n != 2 {
		t.Fatalf("post-invalidate calls = %d want 2 (cache cleared)", n)
	}
}

// TestResidency_InvalidateNilSafe: calling Invalidate on a server with no
// residency cache (and no bus) is a no-op, not a panic.
func TestResidency_InvalidateNilSafe(t *testing.T) {
	t.Parallel()
	srv := NewServer()
	srv.InvalidateTenantResidencyCache(trTenantID) // must not panic
}

// TestResidency_ApplyInvalidationDropsCache proves a received
// KindTenantResidency bus Event clears this replica's cached policy (the
// cross-replica convergence path). It drives applyInvalidation directly,
// the same way StartInvalidationBus would on a real Subscribe.
func TestResidency_ApplyInvalidationDropsCache(t *testing.T) {
	t.Parallel()
	srv, counter := newCountingResidencyServer(t, constrainedTenant())

	if err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-west-1", false); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	if n := counter.calls.Load(); n != 1 {
		t.Fatalf("seed calls = %d want 1", n)
	}
	// A peer published a residency change; the subscriber loop hands it here.
	srv.applyInvalidation(context.Background(), cluster.Event{Kind: cluster.KindTenantResidency, Key: trTenantID})
	if err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-west-1", false); err != nil {
		t.Fatalf("post-apply check: %v", err)
	}
	if n := counter.calls.Load(); n != 2 {
		t.Fatalf("post-apply calls = %d want 2 (cache cleared by bus event)", n)
	}

	// A DIFFERENT tenant's invalidation must NOT evict our entry — proves the
	// per-key delete is not a wildcard clear (would otherwise silently break
	// cross-replica convergence into a global cache flush).
	srv.applyInvalidation(context.Background(), cluster.Event{Kind: cluster.KindTenantResidency, Key: "some-other-tenant"})
	if _, ok := srv.tenantResidencyCache.get(trTenantID); !ok {
		t.Fatal("unrelated tenant invalidation evicted a different tenant's cache entry")
	}
}

// TestResidency_InvalidatePublishesToBus proves InvalidateTenantResidencyCache
// fans the change out to peers over the wired bus as a KindTenantResidency
// Event (the cross-replica side of invalidation).
func TestResidency_InvalidatePublishesToBus(t *testing.T) {
	t.Parallel()
	bus := clustermemory.New()
	sub, err := bus.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	srv := NewServer(
		WithTenantStore(tenantmemory.New()),
		WithTenantResidencyCheck(time.Minute),
		WithInvalidationBus(bus),
	)
	srv.InvalidateTenantResidencyCache(trTenantID)

	select {
	case evt := <-sub:
		if evt.Kind != cluster.KindTenantResidency {
			t.Fatalf("published kind = %q want %q", evt.Kind, cluster.KindTenantResidency)
		}
		if evt.Key != trTenantID {
			t.Fatalf("published key = %q want %q", evt.Key, trTenantID)
		}
	case <-time.After(time.Second):
		t.Fatal("no invalidation event published to bus")
	}
}

// TestResidency_PolicyEditPropagatesAfterInvalidate proves the cache serves
// the updated policy after a residency edit + invalidation: a tenant initially
// served fine from eu-central-1 is later restricted to eu-west-1 only, and the
// next check after invalidation rejects.
func TestResidency_PolicyEditPropagatesAfterInvalidate(t *testing.T) {
	t.Parallel()
	inner := tenantmemory.New()
	_ = inner.PutTenant(context.Background(), constrainedTenant()) // allows eu-central-1
	srv := NewServer(
		WithTenantStore(inner),
		WithTenantResidencyCheck(time.Hour),
	)
	if err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-central-1", false); err != nil {
		t.Fatalf("pre-edit check = %v want nil", err)
	}
	// Tighten the policy: only the home region is now allowed.
	_ = inner.PutTenant(context.Background(), &tenant.Tenant{
		ID: trTenantID, Slug: "tr", Status: tenant.StatusActive,
		HomeRegion:     "eu-west-1",
		AllowedRegions: []string{"eu-west-1"},
	})
	srv.InvalidateTenantResidencyCache(trTenantID)
	err := srv.checkTenantResidency(context.Background(), trTenantID, "eu-central-1", false)
	if !errors.Is(err, region.ErrRegionNotAllowed) {
		t.Fatalf("post-edit check = %v want ErrRegionNotAllowed", err)
	}
}
