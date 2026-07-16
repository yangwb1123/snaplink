package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/platform/lifecycle/admingovernance"
	"github.com/snaplink/sso/shared/core"
)

// TestIsGatedGRPCMethod_DiscoveryMutations verifies that the discovery write
// mutations (Register, Deregister) require admin auth, while the discovery
// read operations (Discover, Watch) remain open for service-discovery clients
// that do not hold admin tokens. The existing admin/audit/netpolicy prefix
// gates must not regress.
func TestIsGatedGRPCMethod_DiscoveryMutations(t *testing.T) {
	t.Parallel()
	gated := []string{
		// Discovery write mutations — the security fix.
		"/snaplink.discovery.v1.Discovery/Register",
		"/snaplink.discovery.v1.Discovery/Deregister",
		// Admin CRUD services — must remain gated.
		"/snaplink.admin.v1.UserAdminService/Delete",
		"/snaplink.admin.v1.ClientAdminService/Create",
		// Audit service — must remain gated.
		"/snaplink.audit.v1.AuditWriter/StreamEvents",
		// Netpolicy management — must remain gated.
		"/snaplink.netpolicy.v1.PolicyService/Apply",
	}
	for _, m := range gated {
		if !isGatedGRPCMethod(m) {
			t.Errorf("isGatedGRPCMethod(%q) = false, want true", m)
		}
	}

	open := []string{
		// Discovery read operations must remain open for service-mesh clients.
		"/snaplink.discovery.v1.Discovery/Discover",
		"/snaplink.discovery.v1.Discovery/Watch",
	}
	for _, m := range open {
		if isGatedGRPCMethod(m) {
			t.Errorf("isGatedGRPCMethod(%q) = true, want false", m)
		}
	}
}

// --- Admin governance framework: HTTPMiddleware transport-level checks ---
//
// These exercise the real end-to-end HTTP path (httptest.Server + a real
// Middleware), not just the pure domains/admingovernance helpers, so a wiring
// mistake in HTTPMiddleware itself (wrong order, wrong field) would be caught
// here.

// fakeValidator is a minimal TokenValidator test double: every token
// validates to the same fixed claims. Not a mock (no call-count assertions,
// no behavior verification) — a hand-written stub, the same shape as
// bgTestDeps in break_glass_test.go.
type fakeValidator struct{ claims *core.TokenClaims }

func (f fakeValidator) ValidateToken(context.Context, string) (*core.TokenClaims, error) {
	return f.claims, nil
}

// allowAllAuthorizer grants every admin-scope check — the tests below are
// about the governance checks that run BEFORE/AFTER authorization, not about
// authorization itself.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) HasAdminScope(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// newTestMiddleware builds a Middleware with a fixed-subject validator and an
// allow-all authorizer, constructed directly (this test file is `package
// admin`) rather than through NewMiddleware, so no permissions.Provider fake
// is needed.
func newTestMiddleware(subject string) *Middleware {
	return &Middleware{
		validator:    fakeValidator{claims: &core.TokenClaims{Subject: subject}},
		authorizer:   allowAllAuthorizer{},
		methodScopes: defaultMethodScopes(),
	}
}

func TestHTTPMiddleware_WriteQuotaBlocksAfterLimit(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	mw.SetWriteQuota(admingovernance.NewMemoryWriteQuotaStore(), 1, time.Hour, "")
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	post := func() int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("first write = %d; want 200 (within quota)", code)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("second write = %d; want 429 (quota exhausted)", code)
	}

	// A GET (read) never consumes the write-only quota, so it must still
	// succeed even though the write budget is exhausted.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET after write-quota exhaustion = %d; want 200", resp.StatusCode)
	}
}

func TestHTTPMiddleware_DestructiveActionRequiresConfirm(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	mw.SetDestructiveActions(admingovernance.NewDestructiveSet([]admingovernance.DestructiveRule{
		{Method: http.MethodDelete, PathPrefix: "/api/v1/admin/tenants/", Action: "tenant_delete"},
	}))
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/tenants/acme", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE without confirm: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("DELETE without X-Confirm = %d; want 409", resp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/tenants/acme", nil)
	req2.Header.Set("Authorization", "Bearer t")
	req2.Header.Set(HeaderConfirm, "true")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("DELETE with confirm: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("DELETE with X-Confirm=true = %d; want 200", resp2.StatusCode)
	}

	// An unrelated (non-destructive) path must be unaffected.
	req3, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/connections/abc", nil)
	req3.Header.Set("Authorization", "Bearer t")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("DELETE unrelated path: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("DELETE on a non-classified path = %d; want 200 (unaffected)", resp3.StatusCode)
	}
}

func TestHTTPMiddleware_IPAllowlistDenies(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	// httptest's client always connects from 127.0.0.1; a CIDR that excludes
	// it must deny every request regardless of a valid bearer token.
	cfg, err := admingovernance.ParseIPAllowlistConfig([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatalf("ParseIPAllowlistConfig: %v", err)
	}
	mw.SetIPAllowlist(cfg, nil)
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET from a non-allowlisted IP = %d; want 403", resp.StatusCode)
	}
}

func TestHTTPMiddleware_IPAllowlistAllowsMatchingCIDR(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	cfg, err := admingovernance.ParseIPAllowlistConfig([]string{"127.0.0.1/32"}, nil)
	if err != nil {
		t.Fatalf("ParseIPAllowlistConfig: %v", err)
	}
	mw.SetIPAllowlist(cfg, nil)
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET from an allowlisted IP = %d; want 200", resp.StatusCode)
	}
}

// --- Admin-wide rate limit (SetRateLimit / SetRateLimitPolicyStore) ---

func TestHTTPMiddleware_RateLimitBlocksAfterBurst(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	mw.SetRateLimit(1, 1) // burst 1: first request OK, second immediately blocked
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	get := func() (int, string) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}
	if code, _ := get(); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200 (within burst)", code)
	}
	code, retryAfter := get()
	if code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429 (burst exhausted)", code)
	}
	if retryAfter == "" {
		t.Error("expected a non-empty Retry-After header on 429")
	}
}

// TestHTTPMiddleware_RateLimitPolicyStoreHotSwap proves SetRateLimitPolicyStore
// wires a SHARED store: swapping its Policy (as a SIGHUP config reload would)
// takes effect on the admin gate immediately, without reconstructing the
// Middleware.
func TestHTTPMiddleware_RateLimitPolicyStoreHotSwap(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	store := ratelimit.NewPolicyStore(ratelimit.Policy{Default: ratelimit.NewMemoryLimiter(1, 1)})
	mw.SetRateLimitPolicyStore(store)
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	get := func() int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	if code := get(); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200 (within burst=1)", code)
	}
	if code := get(); code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429 (burst=1 exhausted)", code)
	}

	// Hot-swap to a much larger burst — simulating a SIGHUP config reload —
	// without touching mw at all.
	store.Set(ratelimit.Policy{Default: ratelimit.NewMemoryLimiter(1000, 1000)})
	if code := get(); code != http.StatusOK {
		t.Fatalf("request after hot-swap = %d, want 200 (new policy has ample burst)", code)
	}
}

// TestHTTPMiddleware_RateLimitUnwiredIsUnlimited proves neither SetRateLimit
// nor SetRateLimitPolicyStore ever being called is byte-identical to a build
// without the feature.
func TestHTTPMiddleware_RateLimitUnwiredIsUnlimited(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %d = %d, want 200 (unlimited when unwired)", i, resp.StatusCode)
		}
	}
}
