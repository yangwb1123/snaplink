package sso

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/shared/core"
)

// server_login_resolve_test.go direct-call-tests resolveHomeRealm's
// interaction with the connections.Store domain-verification contract
// (connections.WithDomainVerificationRequired / config
// connections.domain_verification) and its own cross-tenant guard.
//
// Domain-ownership enforcement is NOT reimplemented in resolveHomeRealm: it is
// delegated entirely to connections.Resolve -> Store.ByDomain, which only
// returns a match once the specific domain's claim is promoted to routing
// owner (domains/connections/memory_domain_verification.go
// reconcileClaimsLocked / promoteDomainLocked; domains/connections/sqlite
// mirrors this via promoteDomainTx). These tests prove that delegation
// composes correctly through resolveHomeRealm for both the strict (opted-in)
// and legacy (default, byte-identical) store modes, and alongside the
// pre-existing cross-tenant guard.

// rhrCtx builds a bare HandlerContext for a direct resolveHomeRealm call —
// no router/middleware chain is needed since resolveHomeRealm only reads
// ctx.Request() and (via tenant.FromHandlerContext) ctx.Get.
func rhrCtx(t *testing.T) core.HandlerContext {
	t.Helper()
	r := httptest.NewRequest("GET", "/auth/login", nil)
	return core.NewContext(httptest.NewRecorder(), r)
}

// rhrUpsertConnection seeds store with a single enabled OIDC connection
// claiming domain, owned by tenantID. Shared by every test below so each one
// only varies the store's enforcement mode / verification state.
func rhrUpsertConnection(t *testing.T, store connections.Store, id, tenantID, domain string) {
	t.Helper()
	if err := store.Upsert(context.Background(), &connections.Connection{
		ID: id, TenantID: tenantID, Type: connections.TypeOIDC,
		DisplayName: "Acme SSO", Domains: []string{domain}, Enabled: true,
	}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
}

// TestResolveHomeRealm_VerifiedDomainMatches proves the existing happy path is
// preserved: once a connection's domain claim is actually verified (DNS-TXT
// proof — here the operator-trusted VerifyDomain primitive stands in for a
// passed challenge), resolveHomeRealm routes to it.
func TestResolveHomeRealm_VerifiedDomainMatches(t *testing.T) {
	t.Parallel()
	store := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))
	rhrUpsertConnection(t, store, "acme", "tenant-a", "acme.com")
	if err := store.VerifyDomain(context.Background(), "acme", "acme.com"); err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}

	s := NewServer(WithConnectionStore(store))
	conn, ok := s.resolveHomeRealm(rhrCtx(t), "user@acme.com")
	if !ok || conn == nil || conn.ID != "acme" {
		t.Fatalf("resolveHomeRealm = %v, %v; want acme, true", conn, ok)
	}
}

// TestResolveHomeRealm_UnverifiedDomainRejectedWhenEnforcementOptedIn is the
// anti-hijack regression test: with
// connections.WithDomainVerificationRequired(true) (config
// connections.domain_verification.enabled) wired, a connection that merely
// lists a domain in Domains — without ever proving DNS control — must NOT be
// resolved. An admin typo, a stale config, or a domain the org no longer
// controls must not silently route real users to the wrong upstream IdP.
func TestResolveHomeRealm_UnverifiedDomainRejectedWhenEnforcementOptedIn(t *testing.T) {
	t.Parallel()
	store := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))
	rhrUpsertConnection(t, store, "acme", "tenant-a", "acme.com")
	// Deliberately never call VerifyDomain / VerifyDomainOwnership: the claim
	// stays DomainPending and is never promoted to routing owner.

	s := NewServer(WithConnectionStore(store))
	conn, ok := s.resolveHomeRealm(rhrCtx(t), "user@acme.com")
	if ok || conn != nil {
		t.Fatalf("resolveHomeRealm = %v, %v; want nil, false (unverified domain must not route)", conn, ok)
	}
}

// TestResolveHomeRealm_UnverifiedDomainAcceptedByDefault proves the rollout is
// byte-identical: a store built WITHOUT WithDomainVerificationRequired (the
// zero value, and every deployment that has never adopted domain
// verification) keeps the historical last-write-wins routing — a declared
// domain matches immediately, with no explicit verification step ever taken.
func TestResolveHomeRealm_UnverifiedDomainAcceptedByDefault(t *testing.T) {
	t.Parallel()
	store := connections.NewMemoryStore() // no options: legacy/default behavior
	rhrUpsertConnection(t, store, "acme", "tenant-a", "acme.com")
	// Deliberately never call VerifyDomain / VerifyDomainOwnership.

	s := NewServer(WithConnectionStore(store))
	conn, ok := s.resolveHomeRealm(rhrCtx(t), "user@acme.com")
	if !ok || conn == nil || conn.ID != "acme" {
		t.Fatalf("resolveHomeRealm = %v, %v; want acme, true (byte-identical default)", conn, ok)
	}
}

// TestResolveHomeRealm_CrossTenantGuardFiresWithVerifiedDomain proves the
// pre-existing cross-tenant HRD isolation guard still fires even when the
// matched domain IS verified: a genuinely-proven domain claim must still not
// route across a tenant boundary the request itself resolved to.
func TestResolveHomeRealm_CrossTenantGuardFiresWithVerifiedDomain(t *testing.T) {
	t.Parallel()
	store := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))
	rhrUpsertConnection(t, store, "acme", "tenant-a", "acme.com")
	if err := store.VerifyDomain(context.Background(), "acme", "acme.com"); err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}

	s := NewServer(WithConnectionStore(store))
	hctx := rhrCtx(t)
	// The request resolved to a DIFFERENT tenant than the connection's owner.
	hctx.Set(tenant.HandlerContextKey, &tenant.Resolved{Tenant: &tenant.Tenant{ID: "tenant-b"}})

	conn, ok := s.resolveHomeRealm(hctx, "user@acme.com")
	if ok || conn != nil {
		t.Fatalf("resolveHomeRealm = %v, %v; want nil, false (cross-tenant guard must still fire)", conn, ok)
	}
}

// TestResolveHomeRealm_SameTenantWithVerifiedDomainStillMatches is the sanity
// counterpart to the cross-tenant test above: when the request's resolved
// tenant DOES agree with the connection's owner, a verified domain still
// routes (the guard only rejects a disagreement, never requires agreement).
func TestResolveHomeRealm_SameTenantWithVerifiedDomainStillMatches(t *testing.T) {
	t.Parallel()
	store := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))
	rhrUpsertConnection(t, store, "acme", "tenant-a", "acme.com")
	if err := store.VerifyDomain(context.Background(), "acme", "acme.com"); err != nil {
		t.Fatalf("VerifyDomain: %v", err)
	}

	s := NewServer(WithConnectionStore(store))
	hctx := rhrCtx(t)
	hctx.Set(tenant.HandlerContextKey, &tenant.Resolved{Tenant: &tenant.Tenant{ID: "tenant-a"}})

	conn, ok := s.resolveHomeRealm(hctx, "user@acme.com")
	if !ok || conn == nil || conn.ID != "acme" {
		t.Fatalf("resolveHomeRealm = %v, %v; want acme, true", conn, ok)
	}
}
