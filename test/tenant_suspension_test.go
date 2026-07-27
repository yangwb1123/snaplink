package ssotest

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	tsUserID   = "u-ts"
	tsClientID = "ts-client"
	tsSecret   = "ts-secret"
	tsTenantID = "tenant-ts"
)

func newTenantSuspensionHarness(t *testing.T, ttl time.Duration) (*sso.Server, sso.TokenIssuer, *tenantmemory.Store, sso.ClientStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClientID, Secret: tsSecret, Active: true,
		TokenStrategy: "jwt",
		TenantID:      tsTenantID,
	})
	tstore := tenantmemory.New()
	_ = tstore.PutTenant(context.Background(), &tenant.Tenant{
		ID: tsTenantID, Slug: "ts", Name: "ts", Status: tenant.StatusActive,
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantStore(tstore),
		sso.WithTenantSuspensionCheck(ttl),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	return srv, issuer, tstore, clients
}

func mintTSToken(t *testing.T, issuer sso.TokenIssuer) string {
	t.Helper()
	tok, err := issuer.Issue(context.Background(), &sso.Subject{
		ID:       tsUserID,
		ClientID: tsClientID,
	}, []string{"read"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	return tok.AccessToken
}

func TestTenantSuspension_ActiveTenantValidates(t *testing.T) {
	srv, issuer, _, _ := newTenantSuspensionHarness(t, time.Second)
	tok := mintTSToken(t, issuer)
	if _, err := srv.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("ValidateToken on active tenant: %v", err)
	}
}

func TestTenantSuspension_SuspendedTenantRejectsToken(t *testing.T) {
	// Mint while active, flip to suspended, validate.
	srv, issuer, tstore, _ := newTenantSuspensionHarness(t, 0) // ttl=0 → default
	tok := mintTSToken(t, issuer)
	if _, err := srv.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("pre-suspension validate: %v", err)
	}
	srv.InvalidateTenantSuspensionCache(tsTenantID) // drop the active-state cache
	_ = tstore.PutTenant(context.Background(), &tenant.Tenant{
		ID: tsTenantID, Slug: "ts", Name: "ts", Status: tenant.StatusSuspended,
	})
	_, err := srv.ValidateToken(context.Background(), tok)
	if !errors.Is(err, sso.ErrTenantSuspended) {
		t.Fatalf("post-suspension err = %v want ErrTenantSuspended", err)
	}
}

func TestTenantSuspension_NoOpWithoutTenantStore(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClientID, Secret: tsSecret, Active: true,
		TokenStrategy: "jwt",
		TenantID:      tsTenantID, // bound to a tenant the server can't resolve
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	// No WithTenantStore + WithTenantSuspensionCheck enabled → still no-op.
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantSuspensionCheck(time.Second),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	tok := mintTSToken(t, issuer)
	if _, err := srv.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("validate (no tenant store): %v", err)
	}
}

func TestTenantSuspension_NoOpForClientWithoutTenant(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClientID, Secret: tsSecret, Active: true,
		TokenStrategy: "jwt",
		// TenantID intentionally empty.
	})
	tstore := tenantmemory.New()
	_ = tstore.PutTenant(context.Background(), &tenant.Tenant{
		ID: tsTenantID, Slug: "ts", Status: tenant.StatusSuspended,
	})
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantStore(tstore),
		sso.WithTenantSuspensionCheck(time.Second),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	tok := mintTSToken(t, issuer)
	if _, err := srv.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("validate (unbound client): %v", err)
	}
}

// countingTenantStore wraps a memory store to verify cache hits skip
// the tenant.Store lookup.
type countingTenantStore struct {
	inner *tenantmemory.Store
	calls atomic.Int64
}

func (c *countingTenantStore) GetTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	c.calls.Add(1)
	return c.inner.GetTenant(ctx, id)
}
func (c *countingTenantStore) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	return c.inner.ListTenants(ctx)
}
func (c *countingTenantStore) PutTenant(ctx context.Context, t *tenant.Tenant) error {
	return c.inner.PutTenant(ctx, t)
}
func (c *countingTenantStore) DeleteTenant(ctx context.Context, id string) error {
	return c.inner.DeleteTenant(ctx, id)
}
func (c *countingTenantStore) GetDomain(ctx context.Context, h string) (*tenant.Domain, error) {
	return c.inner.GetDomain(ctx, h)
}
func (c *countingTenantStore) ListDomains(ctx context.Context) ([]*tenant.Domain, error) {
	return c.inner.ListDomains(ctx)
}
func (c *countingTenantStore) ListDomainsByTenant(ctx context.Context, id string) ([]*tenant.Domain, error) {
	return c.inner.ListDomainsByTenant(ctx, id)
}
func (c *countingTenantStore) PutDomain(ctx context.Context, d *tenant.Domain) error {
	return c.inner.PutDomain(ctx, d)
}
func (c *countingTenantStore) DeleteDomain(ctx context.Context, h string) error {
	return c.inner.DeleteDomain(ctx, h)
}
func (c *countingTenantStore) Close() error { return c.inner.Close() }

func TestTenantSuspension_CacheAmortizesLookups(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClientID, Secret: tsSecret, Active: true,
		TokenStrategy: "jwt",
		TenantID:      tsTenantID,
	})
	inner := tenantmemory.New()
	_ = inner.PutTenant(context.Background(), &tenant.Tenant{
		ID: tsTenantID, Slug: "ts", Status: tenant.StatusActive,
	})
	counter := &countingTenantStore{inner: inner}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantStore(counter),
		sso.WithTenantSuspensionCheck(time.Minute), // long TTL
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	tok := mintTSToken(t, issuer)

	for i := 0; i < 20; i++ {
		if _, err := srv.ValidateToken(context.Background(), tok); err != nil {
			t.Fatalf("validate[%d]: %v", i, err)
		}
	}
	if n := counter.calls.Load(); n != 1 {
		t.Fatalf("tenant store calls = %d want 1 (cache hit on every subsequent validate)", n)
	}
}

func TestTenantSuspension_CacheExpiryRefetches(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClientID, Secret: tsSecret, Active: true,
		TokenStrategy: "jwt",
		TenantID:      tsTenantID,
	})
	inner := tenantmemory.New()
	_ = inner.PutTenant(context.Background(), &tenant.Tenant{
		ID: tsTenantID, Slug: "ts", Status: tenant.StatusActive,
	})
	counter := &countingTenantStore{inner: inner}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantStore(counter),
		sso.WithTenantSuspensionCheck(50*time.Millisecond),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	tok := mintTSToken(t, issuer)
	_, _ = srv.ValidateToken(context.Background(), tok)
	_, _ = srv.ValidateToken(context.Background(), tok)
	if n := counter.calls.Load(); n != 1 {
		t.Fatalf("after-burst calls = %d want 1", n)
	}
	time.Sleep(80 * time.Millisecond)
	_, _ = srv.ValidateToken(context.Background(), tok)
	if n := counter.calls.Load(); n != 2 {
		t.Fatalf("post-expiry calls = %d want 2 (cache refetch)", n)
	}
}

func TestTenantSuspension_InvalidateForcesRefetch(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClientID, Secret: tsSecret, Active: true,
		TokenStrategy: "jwt",
		TenantID:      tsTenantID,
	})
	inner := tenantmemory.New()
	_ = inner.PutTenant(context.Background(), &tenant.Tenant{
		ID: tsTenantID, Slug: "ts", Status: tenant.StatusActive,
	})
	counter := &countingTenantStore{inner: inner}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantStore(counter),
		sso.WithTenantSuspensionCheck(time.Hour),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	tok := mintTSToken(t, issuer)
	_, _ = srv.ValidateToken(context.Background(), tok)
	if n := counter.calls.Load(); n != 1 {
		t.Fatalf("first-validate calls = %d want 1", n)
	}
	srv.InvalidateTenantSuspensionCache(tsTenantID)
	_, _ = srv.ValidateToken(context.Background(), tok)
	if n := counter.calls.Load(); n != 2 {
		t.Fatalf("post-invalidate calls = %d want 2 (cache cleared)", n)
	}
}

func TestTenantSuspension_StoreOutageFailsOpen(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: tsUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: tsClientID, Secret: tsSecret, Active: true,
		TokenStrategy: "jwt",
		TenantID:      tsTenantID,
	})
	// brokenTenantStore returns an error on every GetTenant.
	tstore := &brokenTenantStore{}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTenantStore(tstore),
		sso.WithTenantSuspensionCheck(time.Second),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	tok := mintTSToken(t, issuer)
	if _, err := srv.ValidateToken(context.Background(), tok); err != nil {
		t.Fatalf("validate during store outage = %v want nil (fail-open)", err)
	}
}

type brokenTenantStore struct{}

func (*brokenTenantStore) GetTenant(context.Context, string) (*tenant.Tenant, error) {
	return nil, errors.New("tenant store down")
}
func (*brokenTenantStore) ListTenants(context.Context) ([]*tenant.Tenant, error) { return nil, nil }
func (*brokenTenantStore) PutTenant(context.Context, *tenant.Tenant) error       { return nil }
func (*brokenTenantStore) DeleteTenant(context.Context, string) error            { return nil }
func (*brokenTenantStore) GetDomain(context.Context, string) (*tenant.Domain, error) {
	return nil, tenant.ErrDomainNotFound
}
func (*brokenTenantStore) ListDomains(context.Context) ([]*tenant.Domain, error) { return nil, nil }
func (*brokenTenantStore) ListDomainsByTenant(context.Context, string) ([]*tenant.Domain, error) {
	return nil, nil
}
func (*brokenTenantStore) PutDomain(context.Context, *tenant.Domain) error { return nil }
func (*brokenTenantStore) DeleteDomain(context.Context, string) error      { return nil }
func (*brokenTenantStore) Close() error                                    { return nil }
