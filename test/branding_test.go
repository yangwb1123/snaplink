package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	sso "github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
)

const brandingHost = "acme.example"

// newBrandingServer wires a server with a tenant store seeded with one branded
// Domain. withTenant=false returns a server WITHOUT a tenant store (to assert
// the route is not mounted).
func newBrandingServer(t *testing.T, withTenant bool) *httptest.Server {
	t.Helper()
	opts := []sso.Option{
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withTenant {
		ts := tenantmemory.New()
		_ = ts.PutTenant(context.Background(), &tenant.Tenant{ID: "acme", Slug: "acme", Name: "Acme", Status: tenant.StatusActive})
		_ = ts.PutDomain(context.Background(), &tenant.Domain{
			Hostname: brandingHost,
			TenantID: "acme",
			Branding: map[string]string{
				"brand_name":    "Acme Corp",
				"primary_color": "#ff5722",
				"logo_url":      "https://cdn.acme.example/logo.png",
			},
		})
		opts = append(opts, sso.WithTenantStore(ts))
	}
	srv := sso.NewServer(opts...)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// getBranding issues GET /branding with an explicit Host header.
func getBranding(t *testing.T, srv *httptest.Server, host string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/branding", nil)
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /branding: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestBranding_ResolvedByHost verifies a branded host returns its Domain.Branding.
func TestBranding_ResolvedByHost(t *testing.T) {
	srv := newBrandingServer(t, true)
	status, body := getBranding(t, srv, brandingHost)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	b, _ := body["branding"].(map[string]any)
	if b == nil {
		t.Fatalf("no branding object: %v", body)
	}
	if b["brand_name"] != "Acme Corp" || b["primary_color"] != "#ff5722" {
		t.Errorf("branding = %v, want Acme Corp / #ff5722", b)
	}
	// iss is present on every response (RFC 9207 + §4 invariant).
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("iss missing from branding response")
	}
}

// TestBranding_UnknownHostReturnsEmpty verifies an unconfigured host returns an
// empty branding object (non-enumerable: same shape as a known host).
func TestBranding_UnknownHostReturnsEmpty(t *testing.T) {
	srv := newBrandingServer(t, true)
	status, body := getBranding(t, srv, "unknown.example")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	b, _ := body["branding"].(map[string]any)
	if len(b) != 0 {
		t.Errorf("branding = %v, want empty for unknown host", b)
	}
}

// TestBranding_NotMountedWithoutTenantStore verifies the route is absent (404)
// when no tenant store is wired — byte-identical to a single-tenant build.
func TestBranding_NotMountedWithoutTenantStore(t *testing.T) {
	srv := newBrandingServer(t, false)
	status, _ := getBranding(t, srv, brandingHost)
	if status != http.StatusNotFound {
		t.Errorf("status=%d, want 404 (route must not be mounted without a tenant store)", status)
	}
}
