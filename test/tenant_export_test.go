package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newTenantExportHarness wires a server with a tenant roster + a seeded
// "acme" client/member, optionally with a domains/tenant Store (for the
// tenant_mismatch case) bound to acmeExportHost.
const acmeExportHost = "acme-export.example"

func newTenantExportHarness(t *testing.T, withTenantStore bool) *httptest.Server {
	t.Helper()
	ctx := context.Background()

	users := defaultimpl.NewMemoryUserProvider()
	if err := users.CreateOrUpdate(ctx, &sso.User{ID: "u-alice", Email: "alice@acme.example"}); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "acme-app", Secret: "s", TenantID: "acme", Active: true})
	members := defaultimpl.NewMemoryTenantUserStore()
	if err := members.Add(ctx, &sso.TenantMembership{TenantID: "acme", UserID: "u-alice", Role: sso.TenantRoleAdmin, CreatedAt: time.Now()}); err != nil {
		t.Fatalf("seed membership: %v", err)
	}

	opts := []sso.Option{
		sso.WithIssuer("https://sso.example"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithTenantUserStore(members),
	}
	if withTenantStore {
		ts := tenantmemory.New()
		if err := ts.PutTenant(ctx, &tenant.Tenant{ID: "acme", Slug: "acme", Name: "Acme", Status: tenant.StatusActive}); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
		if err := ts.PutDomain(ctx, &tenant.Domain{Hostname: acmeExportHost, TenantID: "acme"}); err != nil {
			t.Fatalf("seed domain: %v", err)
		}
		opts = append(opts, sso.WithTenantStore(ts))
	}

	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)
	return hs
}

// postExport issues POST .../export with an optional Host header override.
func postExport(t *testing.T, srv *httptest.Server, path, host string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if host != "" {
		req.Host = host
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func TestTenantExport_NotMountedWithoutTenantUserStore(t *testing.T) {
	hs := httptest.NewServer(sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	).Handler())
	t.Cleanup(hs.Close)

	resp, _ := postExport(t, hs, "/api/v1/admin/tenants/acme/export", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (route not mounted)", resp.StatusCode)
	}
}

func TestTenantExport_HappyPath(t *testing.T) {
	hs := newTenantExportHarness(t, false)

	resp, body := postExport(t, hs, "/api/v1/admin/tenants/acme/export", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Disposition"); got == "" {
		t.Error("expected a Content-Disposition attachment header")
	}
	if body["tenant_id"] != "acme" {
		t.Errorf("tenant_id = %v, want acme", body["tenant_id"])
	}
	clients, _ := body["clients"].([]any)
	if len(clients) != 1 {
		t.Errorf("clients = %v, want exactly acme-app", body["clients"])
	}
	manifest, _ := body["manifest"].(map[string]any)
	if manifest == nil || manifest["checksum"] == "" {
		t.Errorf("manifest/checksum missing: %v", body["manifest"])
	}
}

func TestTenantExport_TenantMismatchIsForbidden(t *testing.T) {
	hs := newTenantExportHarness(t, true)

	// Host resolves to tenant "acme"; requesting a DIFFERENT tenant's export
	// via the path must be rejected before any data is assembled.
	resp, body := postExport(t, hs, "/api/v1/admin/tenants/someone-else/export", acmeExportHost)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, body = %v, want 403 tenant_mismatch", resp.StatusCode, body)
	}
	if body["error"] != "tenant_mismatch" {
		t.Errorf("error = %v, want tenant_mismatch", body["error"])
	}

	// The SAME host requesting its OWN tenant's export is not a mismatch.
	resp2, body2 := postExport(t, hs, "/api/v1/admin/tenants/acme/export", acmeExportHost)
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("own-tenant export status = %d, body = %v", resp2.StatusCode, body2)
	}
}
