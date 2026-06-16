package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
)

// These cover the data-residency WRITE-gate on the /token grant endpoint
// (residencyGateTokenGrant). The login flow's mint is gated by
// residencyGateLogin; this closes the grant-side hole so a token mint via any
// /token grant (client_credentials exercised here as the simplest) cannot
// produce fresh credentials for a region-constrained tenant from a disallowed
// serving region. Wire-level counterpart to the engine unit tests in
// tenant_residency_test.go. residencyTenant / residencyTenantID /
// residencyServingHeader are shared with region_residency_test.go (same pkg).

const (
	grantResidencyClient = "grant-app"
	grantResidencySecret = "grant-secret"
)

// grantResidencyFixture builds a server with a confidential client bound to the
// region-constrained residencyTenant. When resolver is non-nil the region
// middleware + residency check are wired; when nil neither is (the inert path).
// The serving region is resolved from residencyServingHeader (Default = the
// tenant's home eu-west-1) so one server can mint from home (no header) or
// replay a grant from a disallowed region (header set).
func grantResidencyFixture(t *testing.T, resolver region.Resolver, seed *tenant.Tenant) *httptest.Server {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: grantResidencyClient, Secret: grantResidencySecret, Active: true,
		TenantID:      residencyTenantID,
		TokenStrategy: "jwt",
	})
	tstore := tenantmemory.New()
	if seed != nil {
		if err := tstore.PutTenant(context.Background(), seed); err != nil {
			t.Fatalf("PutTenant: %v", err)
		}
	}
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	opts := []sso.Option{
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantStore(tstore),
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
	return ts
}

// postClientCredsFromRegion runs a client_credentials token request, optionally
// pinning the serving region via the header (empty → no header → home region).
func postClientCredsFromRegion(t *testing.T, ts *httptest.Server, servingRegion string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {grantResidencyClient},
		"client_secret": {grantResidencySecret},
	}
	req, _ := http.NewRequest("POST", ts.URL+"/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if servingRegion != "" {
		req.Header.Set(residencyServingHeader, servingRegion)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func headerResolverHomeEUWest() region.Resolver {
	return region.HeaderResolver{Header: residencyServingHeader, Default: "eu-west-1"}
}

// TestResidency_TokenGrant_DisallowedRegion_Blocked: a token mint served from a
// region outside the tenant's AllowedRegions is rejected with region_not_allowed
// and leaks no token. This FAILS pre-fix (the grant switch minted before any
// residency gate ran).
func TestResidency_TokenGrant_DisallowedRegion_Blocked(t *testing.T) {
	ts := grantResidencyFixture(t, headerResolverHomeEUWest(), residencyTenant(true))

	status, body := postClientCredsFromRegion(t, ts, "us-east-1")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (grant-side bypass!) body=%v", status, body)
	}
	if got := body[sso.KeyError]; got != sso.ErrRegionNotAllowed {
		t.Errorf("error = %v, want %q", got, sso.ErrRegionNotAllowed)
	}
	if _, ok := body[sso.KeyAccessToken]; ok {
		t.Errorf("blocked grant still minted an access_token: %v", body)
	}
}

// TestResidency_TokenGrant_HomeRegion_Mints: the same grant served from the
// tenant's home region succeeds — the gate doesn't break the happy path.
func TestResidency_TokenGrant_HomeRegion_Mints(t *testing.T) {
	ts := grantResidencyFixture(t, headerResolverHomeEUWest(), residencyTenant(true))

	status, body := postClientCredsFromRegion(t, ts, "") // no header → home eu-west-1
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 body=%v", status, body)
	}
	if _, ok := body[sso.KeyAccessToken].(string); !ok {
		t.Errorf("home-region grant minted no access_token: %v", body)
	}
}

// TestResidency_TokenGrant_EnforceWritesNonHome: served from a non-home but
// ALLOWED region, EnforceWrites makes the mint (a write) a residency_violation,
// while EnforceWrites=false permits it (policy advisory) — mirroring the login
// write-gate matrix on the grant path.
func TestResidency_TokenGrant_EnforceWritesNonHome(t *testing.T) {
	const servingNonHomeAllowed = "eu-central-1"
	allowed := []string{"eu-west-1", servingNonHomeAllowed}

	t.Run("enforce_writes_true_blocks", func(t *testing.T) {
		ts := grantResidencyFixture(t, headerResolverHomeEUWest(), residencyTenant(true, allowed...))
		status, body := postClientCredsFromRegion(t, ts, servingNonHomeAllowed)
		if status != http.StatusForbidden {
			t.Fatalf("status = %d, want 403 body=%v", status, body)
		}
		if got := body[sso.KeyError]; got != sso.ErrResidencyViolation {
			t.Errorf("error = %v, want %q", got, sso.ErrResidencyViolation)
		}
	})

	t.Run("enforce_writes_false_allows", func(t *testing.T) {
		ts := grantResidencyFixture(t, headerResolverHomeEUWest(), residencyTenant(false, allowed...))
		status, body := postClientCredsFromRegion(t, ts, servingNonHomeAllowed)
		if status != http.StatusOK {
			t.Fatalf("status = %d, want 200 (advisory) body=%v", status, body)
		}
		if _, ok := body[sso.KeyAccessToken].(string); !ok {
			t.Errorf("advisory grant minted no access_token: %v", body)
		}
	})
}

// TestResidency_TokenGrant_NoRegionWired_Mints: the byte-identical guarantee —
// the same constrained tenant + client with NO region middleware / residency
// check mints normally (the gate's first guard returns before any work).
func TestResidency_TokenGrant_NoRegionWired_Mints(t *testing.T) {
	ts := grantResidencyFixture(t, nil, residencyTenant(true))

	status, body := postClientCredsFromRegion(t, ts, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (inert residency) body=%v", status, body)
	}
	if _, ok := body[sso.KeyAccessToken].(string); !ok {
		t.Errorf("no access_token despite inert residency: %v", body)
	}
}
