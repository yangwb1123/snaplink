package federation_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/yangwb1123/snaplink/domains/federation"
	"github.com/yangwb1123/snaplink/shared/core"
)

// ---- Resolve endpoint tests ----

type resolveDeps struct {
	resolver *federation.TrustChainResolver
	logged   []string
}

func (d *resolveDeps) FederationResolver() *federation.TrustChainResolver { return d.resolver }
func (d *resolveDeps) LogError(msg string, args ...any) {
	d.logged = append(d.logged, msg)
}

type testCtx struct {
	w       http.ResponseWriter
	r       *http.Request
	status  int
	jsonOut any
}

func (c *testCtx) ResponseWriter() http.ResponseWriter { return c.w }
func (c *testCtx) Request() *http.Request              { return c.r }
func (c *testCtx) Query(name string) string            { return c.r.URL.Query().Get(name) }
func (c *testCtx) JSON(code int, v any) {
	c.status = code
	c.jsonOut = v
	if rw, ok := c.w.(*httptest.ResponseRecorder); ok {
		rw.WriteHeader(code)
	}
}
func (c *testCtx) Param(string) string                     { return "" }
func (c *testCtx) Bind(any) error                          { return nil }
func (c *testCtx) Redirect(int, string)                    {}
func (c *testCtx) Set(string, any)                         {}
func (c *testCtx) Get(string) any                          { return nil }
func (c *testCtx) Abort()                                  {}
func (c *testCtx) Aborted() bool                           { return false }
func (c *testCtx) Written() bool                           { return false }
func (c *testCtx) SetResponseWriter(w http.ResponseWriter) { c.w = w }

func intStr(i int) string { return strconv.Itoa(i) }

func TestHandleFederationResolve_MissingSub(t *testing.T) {
	deps := &resolveDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-resolve", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationResolve(deps, ctx)
	if ctx.status != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusBadRequest)
	}
}

func TestHandleFederationResolve_NilResolver(t *testing.T) {
	deps := &resolveDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-resolve?sub=https://example.com/rp", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationResolve(deps, ctx)
	if ctx.status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusNotFound)
	}
}

func TestHandleFederationResolve_DisabledResolver(t *testing.T) {
	cfg := &federation.Config{AuthorityHints: []string{"https://ta.example.com"}}
	resolver := federation.NewTrustChainResolver(cfg)
	deps := &resolveDeps{resolver: resolver}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-resolve?sub=https://example.com/rp", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationResolve(deps, ctx)
	if ctx.status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusNotFound)
	}
}

func TestHandleFederationResolve_HeaderNoStore(t *testing.T) {
	deps := &resolveDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-resolve", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationResolve(deps, ctx)
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
	if pragma := rec.Header().Get("Pragma"); pragma != "no-cache" {
		t.Errorf("Pragma = %q, want %q", pragma, "no-cache")
	}
}

type mockFetcher struct{}

func (f *mockFetcher) FetchEntityConfiguration(ctx context.Context, entityID string) ([]byte, error) {
	return nil, errors.New("mock: no network")
}
func (f *mockFetcher) FetchSubordinateStatement(ctx context.Context, fetchEndpoint, issuer, subordinate string) ([]byte, error) {
	return nil, errors.New("mock: no network")
}

func TestHandleFederationResolve_WithEnabledResolver_NetworkError(t *testing.T) {
	cfg := &federation.Config{
		TrustAnchors: []federation.TrustAnchor{
			{EntityID: "https://ta.example.com", Keys: []core.JWK{}},
		},
	}
	resolver := federation.NewTrustChainResolver(cfg, federation.WithTrustChainFetcher(&mockFetcher{}))
	deps := &resolveDeps{resolver: resolver}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-resolve?sub=https://example.com/rp", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationResolve(deps, ctx)
	if ctx.status != http.StatusNotFound {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusNotFound)
	}
}

func TestHandleFederationResolve_OracleSafety(t *testing.T) {
	scenarios := []struct {
		name string
		deps federation.ResolveDeps
	}{
		{"nil resolver", &resolveDeps{}},
		{"disabled resolver", &resolveDeps{
			resolver: federation.NewTrustChainResolver(&federation.Config{}),
		}},
		{"network error", &resolveDeps{
			resolver: federation.NewTrustChainResolver(
				&federation.Config{
					TrustAnchors: []federation.TrustAnchor{
						{EntityID: "https://ta.example.com", Keys: []core.JWK{}},
					},
				},
				federation.WithTrustChainFetcher(&mockFetcher{}),
			),
		}},
	}
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-resolve?sub=https://example.com/rp", nil)
			ctx := &testCtx{w: rec, r: req}
			federation.HandleFederationResolve(sc.deps, ctx)
			if ctx.status != http.StatusNotFound {
				t.Errorf("status = %d, want %d (oracle-safe)", ctx.status, http.StatusNotFound)
			}
		})
	}
}

// ---- List endpoint tests ----

type listDeps struct {
	cfg *federation.Config
}

func (d *listDeps) FederationConfig() *federation.Config         { return d.cfg }
func (d *listDeps) ResolveIssuer(ctx core.HandlerContext) string { return "https://server.example.com" }
func (d *listDeps) LogError(msg string, args ...any)             {}

func TestHandleFederationList_NoSubordinates(t *testing.T) {
	cfg := &federation.Config{OrganizationName: "test-org"}
	deps := &listDeps{cfg: cfg}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-list", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationList(deps, ctx)
	if ctx.status != http.StatusOK {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusOK)
	}
	resp, ok := ctx.jsonOut.(federation.ListResponse)
	if !ok {
		t.Fatalf("JSON type: %T", ctx.jsonOut)
	}
	if len(resp.Subordinates) != 0 {
		t.Errorf("expected 0, got %d", len(resp.Subordinates))
	}
}

func TestHandleFederationList_WithSubordinates(t *testing.T) {
	cfg := &federation.Config{
		Subordinates: []federation.SubordinateEntity{
			{EntityID: "https://sub1.example.com"},
			{EntityID: "https://sub2.example.com"},
		},
	}
	deps := &listDeps{cfg: cfg}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-list", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationList(deps, ctx)
	if ctx.status != http.StatusOK {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusOK)
	}
	resp, ok := ctx.jsonOut.(federation.ListResponse)
	if !ok {
		t.Fatalf("JSON type: %T", ctx.jsonOut)
	}
	if len(resp.Subordinates) != 2 {
		t.Errorf("expected 2, got %d", len(resp.Subordinates))
	}
}

func TestHandleFederationList_NilConfig(t *testing.T) {
	deps := &listDeps{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-list", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationList(deps, ctx)
	if ctx.status != http.StatusOK {
		t.Errorf("status = %d, want %d", ctx.status, http.StatusOK)
	}
}

func TestHandleFederationList_CacheHeader(t *testing.T) {
	cfg := &federation.Config{
		Subordinates: []federation.SubordinateEntity{
			{EntityID: "https://sub1.example.com"},
		},
	}
	deps := &listDeps{cfg: cfg}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-federation-list", nil)
	ctx := &testCtx{w: rec, r: req}
	federation.HandleFederationList(deps, ctx)
	if cc := rec.Header().Get("Cache-Control"); cc == "" {
		t.Error("Cache-Control header is empty")
	}
}
