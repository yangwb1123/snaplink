package ssotest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	meteringmemory "github.com/snaplink/sso/metering/memory"
)

// TestTenantUsageRoute_ResolvesAtDocumentedPath guards the group-prefix
// double-up regression: the admin tenant-usage endpoint MUST answer at
// /api/v1/admin/tenants/:id/usage. A full-path const on the /api/v1 router
// group registered it at /api/v1/api/v1/admin/... — a 404 at the documented
// path AND outside the AdminMiddleware /api/v1/admin/ gate.
func TestTenantUsageRoute_ResolvesAtDocumentedPath(t *testing.T) {
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithTenantUsageAggregator(meteringmemory.New()),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	resp, err := http.Get(hs.URL + "/api/v1/admin/tenants/t1/usage?period=day")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		t.Fatalf("tenant-usage 404 at documented path — route mis-registered (group double-prefix)")
	}

	// The previously-buggy doubled path MUST NOT resolve.
	resp2, err := http.Get(hs.URL + "/api/v1/api/v1/admin/tenants/t1/usage?period=day")
	if err != nil {
		t.Fatalf("GET doubled: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Errorf("doubled path resolved (status %d), want 404", resp2.StatusCode)
	}
}
