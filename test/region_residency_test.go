package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/geo"
	geostatic "github.com/snaplink/sso/geo/static"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
)

// These are the live integration tests for the data-residency feature: a
// full *sso.Server over HTTP, the region middleware mounted, and the
// /auth/login residency gate enforcing a tenant's ResidencyPolicy. They are
// the wire-level counterpart to the in-package engine unit tests in
// tenant_residency_test.go (which call checkTenantResidency directly).

const residencyTenantID = "tenant-eu"

// residencyTenant is bound to eu-west-1 and allows ONLY eu-west-1 — any
// other serving region is outside AllowedRegions. EnforceWrites is varied
// per-test by the matrix helpers below.
func residencyTenant(enforceWrites bool, allowed ...string) *tenant.Tenant {
	if len(allowed) == 0 {
		allowed = []string{"eu-west-1"}
	}
	return &tenant.Tenant{
		ID: residencyTenantID, Slug: "eu", Name: "EU", Status: tenant.StatusActive,
		HomeRegion:     "eu-west-1",
		AllowedRegions: allowed,
		EnforceWrites:  enforceWrites,
	}
}

// residencyFixture builds a server with a tenant-bound client. When resolver
// is non-nil the region middleware is mounted and the residency check enabled;
// when nil neither is wired (the inert / byte-identical path). The client is
// bound to residencyTenantID — clientTenantOK passes (no tenant host resolves
// on these requests), so the residency gate is what decides.
func residencyFixture(t *testing.T, resolver region.Resolver, seed *tenant.Tenant) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		TenantID:              residencyTenantID,
		AllowedAuthenticators: []string{stub.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	tstore := tenantmemory.New()
	if seed != nil {
		if err := tstore.PutTenant(context.Background(), seed); err != nil {
			t.Fatalf("PutTenant: %v", err)
		}
	}
	sink := audit.NewMemorySink(20)
	opts := []sso.Option{
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(stub),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithTenantStore(tstore),
		sso.WithAuditRecorder(audit.New(sink)),
	}
	if resolver != nil {
		opts = append(opts,
			sso.WithRegionMiddleware(resolver, region.MiddlewareOptions{}),
			sso.WithTenantResidencyCheck(0),
		)
	}
	srv := sso.NewServer(opts...)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sink
}

// doResidencyLogin posts a login and returns status + decoded body.
func doResidencyLogin(t *testing.T, ts *httptest.Server) (int, map[string]any) {
	t.Helper()
	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("decode: %v body=%s", err, raw)
		}
	}
	return resp.StatusCode, out
}

// TestResidency_DisallowedRegion_LoginRejectedWithIss proves the primary
// control: a login served from a region outside the tenant's AllowedRegions
// is rejected with region_not_allowed, and the RFC 9207 `iss` is PRESENT in
// the error body — proving authzErrorBody (not errorBody) backs the gate.
func TestResidency_DisallowedRegion_LoginRejectedWithIss(t *testing.T) {
	// Pinned to us-east-1, which is NOT in the tenant's allowed set.
	ts, _ := residencyFixture(t, region.ConfigPinnedResolver{Region: "us-east-1"}, residencyTenant(true))

	status, body := doResidencyLogin(t, ts)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body=%v)", status, body)
	}
	if got := body[sso.KeyError]; got != sso.ErrRegionNotAllowed {
		t.Errorf("error = %v, want %q", got, sso.ErrRegionNotAllowed)
	}
	// iss MUST be present — this is the §2 RFC 9207 invariant the residency
	// error response shares with every other /auth/login response.
	if iss, ok := body[sso.KeyIss].(string); !ok || iss == "" {
		t.Errorf("iss missing/empty on residency error body: %v", body)
	}
}

// TestResidency_HomeRegion_LoginSucceedsWithServingRegion proves a server
// pinned to the tenant's home region serves the login normally AND surfaces
// serving_region in the success response.
func TestResidency_HomeRegion_LoginSucceedsWithServingRegion(t *testing.T) {
	ts, _ := residencyFixture(t, region.ConfigPinnedResolver{Region: "eu-west-1"}, residencyTenant(true))

	status, body := doResidencyLogin(t, ts)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%v)", status, body)
	}
	if _, ok := body[sso.KeyAccessToken]; !ok {
		t.Errorf("no access_token on success: %v", body)
	}
	if got := body[sso.KeyServingRegion]; got != "eu-west-1" {
		t.Errorf("serving_region = %v, want eu-west-1", got)
	}
}

// TestResidency_NoRegionWired_LoginSucceeds proves the nil-default
// byte-identical guarantee at the wire level: the SAME constrained tenant +
// client, but with NO WithRegionMiddleware / WithTenantResidencyCheck, logs in
// successfully and carries no serving_region. The middleware isn't installed,
// the gate sees servingRegion=="" and returns nil.
func TestResidency_NoRegionWired_LoginSucceeds(t *testing.T) {
	ts, _ := residencyFixture(t, nil, residencyTenant(true))

	status, body := doResidencyLogin(t, ts)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inert residency) body=%v", status, body)
	}
	if _, ok := body[sso.KeyAccessToken]; !ok {
		t.Errorf("no access_token despite inert residency: %v", body)
	}
	if _, present := body[sso.KeyServingRegion]; present {
		t.Errorf("serving_region present despite no region middleware: %v", body)
	}
}

// TestResidency_EnforceWritesMatrix proves the write-side semantics. The
// tenant ALLOWS eu-central-1 (a non-home allowed region). Served from there:
//   - EnforceWrites=true  → login (a write/mint) → residency_violation.
//   - EnforceWrites=false → login succeeds (the policy is advisory).
func TestResidency_EnforceWritesMatrix(t *testing.T) {
	const servingNonHomeAllowed = "eu-central-1"
	allowed := []string{"eu-west-1", servingNonHomeAllowed}

	t.Run("enforce_writes_true_blocks", func(t *testing.T) {
		ts, _ := residencyFixture(t,
			region.ConfigPinnedResolver{Region: servingNonHomeAllowed},
			residencyTenant(true, allowed...))

		status, body := doResidencyLogin(t, ts)
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 (body=%v)", status, body)
		}
		if got := body[sso.KeyError]; got != sso.ErrResidencyViolation {
			t.Errorf("error = %v, want %q", got, sso.ErrResidencyViolation)
		}
		if iss, ok := body[sso.KeyIss].(string); !ok || iss == "" {
			t.Errorf("iss missing on residency_violation body: %v", body)
		}
	})

	t.Run("enforce_writes_false_allows", func(t *testing.T) {
		ts, _ := residencyFixture(t,
			region.ConfigPinnedResolver{Region: servingNonHomeAllowed},
			residencyTenant(false, allowed...))

		status, body := doResidencyLogin(t, ts)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (advisory) body=%v", status, body)
		}
		if got := body[sso.KeyServingRegion]; got != servingNonHomeAllowed {
			t.Errorf("serving_region = %v, want %s", got, servingNonHomeAllowed)
		}
	})
}

// TestResidency_AuditCarriesServingRegionWithoutClobberingGeo proves the audit
// enrichment: a successful login event carries region.serving in Metadata, and
// the geo.* keys (also wired here) are NOT clobbered.
func TestResidency_AuditCarriesServingRegionWithoutClobberingGeo(t *testing.T) {
	// Build the fixture, then ALSO wire geo so we can prove both namespaces
	// coexist. residencyFixture doesn't take a geo provider, so build inline.
	stub := &stubAuthenticator{
		name:   "stub",
		result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		TenantID:              residencyTenantID,
		AllowedAuthenticators: []string{stub.Name()},
		TokenStrategy:         sso.TokenStrategySession,
	})
	tstore := tenantmemory.New()
	if err := tstore.PutTenant(context.Background(), residencyTenant(true)); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	geoProv := geostatic.New()
	_ = geoProv.Add("10.0.0.0/8", geo.GeoInfo{CountryCode: "US", Region: "US-CA"})
	sink := audit.NewMemorySink(20)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(stub),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithTenantStore(tstore),
		sso.WithGeoProvider(geoProv),
		// Pin to the home region so the login SUCCEEDS (we want a login event).
		sso.WithRegionMiddleware(region.ConfigPinnedResolver{Region: "eu-west-1"}, region.MiddlewareOptions{}),
		sso.WithTenantResidencyCheck(0),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-For", "10.5.6.7")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	events, err := sink.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var login *audit.Event
	for _, e := range events {
		if e.Type == audit.EventLogin {
			login = e
			break
		}
	}
	if login == nil {
		t.Fatalf("no login event recorded; got %d events", len(events))
	}
	if got := login.Metadata["region.serving"]; got != "eu-west-1" {
		t.Errorf("region.serving = %q, want eu-west-1 (full meta=%v)", got, login.Metadata)
	}
	// geo.* must survive alongside region.serving (SetMeta merges, never
	// clobbers — §2 audit-metadata invariant).
	if got := login.Metadata["geo.country_code"]; got != "US" {
		t.Errorf("geo.country_code clobbered: %v", login.Metadata)
	}
	if got := login.Metadata["geo.region"]; got != "US-CA" {
		t.Errorf("geo.region clobbered/conflated with region.serving: %v", login.Metadata)
	}
}
