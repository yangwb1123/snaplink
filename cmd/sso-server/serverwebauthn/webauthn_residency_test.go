package serverwebauthn

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	tenantmemory "github.com/snaplink/sso/domains/tenant/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

// Data-residency enforcement on the WebAuthn LOGIN mint path.
//
// /webauthn/login/finish?client_id= mints tokens exactly like /auth/login,
// but the ceremony is mounted as raw http handlers OUTSIDE the HandlerContext
// residency gate (residencyGateLogin). Before this change a region-constrained
// tenant's user could complete WebAuthn login from a disallowed serving region
// and receive tokens, bypassing residency. issueWebAuthnToken now consults the
// server's context-free ResidencyDecision seam (resolving the serving region
// from the raw request) BEFORE minting, isWrite=true — same verdict the
// in-pipeline login gate renders.
//
// Real *sso.Server + memory tenant store throughout — no mocks (AGENTS.md §8).

// newWebAuthnResidencyDeps builds a *sso.Server with a memory tenant store
// (seeded with seedTenant) + residency enabled, then returns WebAuthnDeps wired
// with the given resolver and the server's ResidencyDecision seam (mirroring
// cmd's conditional wiring). When resolver is nil BOTH residency hooks are left
// nil — the byte-identical "residency not enforced for WebAuthn" path.
func newWebAuthnResidencyDeps(t *testing.T, seedTenant *tenant.Tenant, client *sso.Client, resolver region.Resolver) *WebAuthnDeps {
	t.Helper()
	tstore := tenantmemory.New()
	if seedTenant != nil {
		if err := tstore.PutTenant(context.Background(), seedTenant); err != nil {
			t.Fatalf("PutTenant: %v", err)
		}
	}
	clientStore := defaultimpl.NewMemoryClientStore()
	if err := clientStore.Add(context.Background(), client); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	srv := sso.NewServer(
		sso.WithClientStore(clientStore),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantStore(tstore),
		sso.WithTenantResidencyCheck(time.Minute),
	)
	deps := &WebAuthnDeps{
		ClientStore:  clientStore,
		TokenIssuers: map[string]sso.TokenIssuer{"jwt": issuer},
		DefaultStrat: "jwt",
	}
	// Mirror cmd's conditional wiring: only attach the residency hooks when a
	// region resolver is configured.
	if resolver != nil {
		deps.RegionResolver = resolver
		deps.ResidencyDecision = srv.ResidencyDecision
	}
	return deps
}

// constrainedResidencyTenant: home eu-west-1, allowed {eu-west-1}, no
// EnforceWrites — so a serving region outside the allow-list trips the
// AllowedRegions check (region_not_allowed) for both reads and writes.
func constrainedResidencyTenant() *tenant.Tenant {
	return &tenant.Tenant{
		ID:             "tenant-wa",
		Slug:           "wa",
		Name:           "wa",
		Status:         tenant.StatusActive,
		HomeRegion:     "eu-west-1",
		AllowedRegions: []string{"eu-west-1"},
	}
}

func constrainedResidencyClient() *sso.Client {
	return &sso.Client{
		ID:            "wa-app",
		Active:        true,
		TokenStrategy: "jwt",
		TenantID:      "tenant-wa",
		AllowedScopes: []string{"openid", "profile"},
	}
}

// TestWebAuthnResidency_DisallowedRegionDeniedRegionNotAllowed: a constrained
// tenant served from a region outside AllowedRegions is denied a WebAuthn mint
// with 403 region_not_allowed.
func TestWebAuthnResidency_DisallowedRegionDeniedRegionNotAllowed(t *testing.T) {
	t.Parallel()
	deps := newWebAuthnResidencyDeps(t,
		constrainedResidencyTenant(),
		constrainedResidencyClient(),
		region.ConfigPinnedResolver{Region: "us-east-1"}, // not in AllowedRegions
	)
	req, _ := http.NewRequest("POST", "http://x/", nil)
	_, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if !errors.Is(err, errWebAuthnResidency) {
		t.Fatalf("got %v want errWebAuthnResidency", err)
	}
	status, code := webauthnIssueErrorStatus(err)
	if status != http.StatusForbidden || code != sso.ErrRegionNotAllowed {
		t.Fatalf("mapping = (%d, %q) want (403, %q)", status, code, sso.ErrRegionNotAllowed)
	}
}

// TestWebAuthnResidency_HomeRegionMints: the same constrained tenant served
// from its home region mints normally (no denial).
func TestWebAuthnResidency_HomeRegionMints(t *testing.T) {
	t.Parallel()
	deps := newWebAuthnResidencyDeps(t,
		constrainedResidencyTenant(),
		constrainedResidencyClient(),
		region.ConfigPinnedResolver{Region: "eu-west-1"}, // home
	)
	req, _ := http.NewRequest("POST", "http://x/", nil)
	res, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("issue from home region: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("AccessToken empty (home-region mint should succeed)")
	}
}

// TestWebAuthnResidency_UnwiredIsByteIdentical proves the byte-identical
// guarantee: a fully region-constrained tenant whose deps have NO resolver /
// ResidencyDecision wired (the non-residency deployment) mints normally — the
// residency check is simply not enforced for WebAuthn.
func TestWebAuthnResidency_UnwiredIsByteIdentical(t *testing.T) {
	t.Parallel()
	deps := newWebAuthnResidencyDeps(t,
		constrainedResidencyTenant(),
		constrainedResidencyClient(),
		nil, // no resolver → both residency hooks stay nil
	)
	if deps.RegionResolver != nil || deps.ResidencyDecision != nil {
		t.Fatal("residency hooks must stay nil when no resolver is wired")
	}
	req, _ := http.NewRequest("POST", "http://x/", nil)
	res, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("unwired residency must mint: %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("AccessToken empty (unwired residency must mint)")
	}
}

// TestWebAuthnResidency_EnforceWritesViolation: a tenant with EnforceWrites and
// an allow-list that INCLUDES the serving region (so the AllowedRegions check
// passes) but the serving region is NOT the home region — since the WebAuthn
// mint is a WRITE (isWrite=true), it must trip the EnforceWrites guard with
// 403 residency_violation (distinct from region_not_allowed).
func TestWebAuthnResidency_EnforceWritesViolation(t *testing.T) {
	t.Parallel()
	seed := &tenant.Tenant{
		ID:             "tenant-wa",
		Slug:           "wa",
		Name:           "wa",
		Status:         tenant.StatusActive,
		HomeRegion:     "eu-west-1",
		AllowedRegions: []string{"eu-west-1", "eu-central-1"}, // serving region IS allowed
		EnforceWrites:  true,
	}
	deps := newWebAuthnResidencyDeps(t,
		seed,
		constrainedResidencyClient(),
		region.ConfigPinnedResolver{Region: "eu-central-1"}, // allowed, but != home
	)
	req, _ := http.NewRequest("POST", "http://x/", nil)
	_, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if !errors.Is(err, errWebAuthnResidency) {
		t.Fatalf("got %v want errWebAuthnResidency", err)
	}
	status, code := webauthnIssueErrorStatus(err)
	if status != http.StatusForbidden || code != sso.ErrResidencyViolation {
		t.Fatalf("mapping = (%d, %q) want (403, %q)", status, code, sso.ErrResidencyViolation)
	}
}

// TestWebAuthnResidency_ResolverErrorFailsOpen proves fail-open: a resolver
// that errors yields an empty serving region, which checkTenantResidency treats
// as unconstrained — so the constrained tenant still mints (the region
// middleware's nonfatal contract, mirrored here).
func TestWebAuthnResidency_ResolverErrorFailsOpen(t *testing.T) {
	t.Parallel()
	deps := newWebAuthnResidencyDeps(t,
		constrainedResidencyTenant(),
		constrainedResidencyClient(),
		erroringRegionResolver{},
	)
	req, _ := http.NewRequest("POST", "http://x/", nil)
	res, err := issueWebAuthnToken(req, deps, "wa-app", "alice")
	if err != nil {
		t.Fatalf("resolver error must fail open (mint): %v", err)
	}
	if res.AccessToken == "" {
		t.Fatal("AccessToken empty (resolver error must fail open and mint)")
	}
}

// erroringRegionResolver always errors with an empty region — the fail-open
// probe (an empty serving region is unconstrained, mirroring the region
// middleware's nonfatal contract).
type erroringRegionResolver struct{}

func (erroringRegionResolver) Resolve(*http.Request) (region.ID, error) {
	return "", errors.New("resolver boom")
}
