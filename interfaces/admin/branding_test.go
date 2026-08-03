package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

func newBrandingDeps(store *brandingTestStore) *brandingTestDeps {
	return &brandingTestDeps{store: store}
}

type brandingTestDeps struct {
	store *brandingTestStore
}

func (d *brandingTestDeps) TenantStore() tenant.Store { return d.store }
func (d *brandingTestDeps) ErrorBody(code string) map[string]any {
	return map[string]any{"error": code}
}
func (d *brandingTestDeps) ErrorBodyDesc(code, desc string) map[string]any {
	return map[string]any{"error": code, "error_description": desc}
}

// brandingTestStore partially implements tenant.Store for testing.
type brandingTestStore struct {
	tenants  map[string]*tenantTenant
	branding map[string]tenant.Branding
}

type tenantTenant struct {
	ID       string
	Settings map[string]string
}

func newBrandingTestStore() *brandingTestStore {
	return &brandingTestStore{
		tenants: map[string]*tenantTenant{}, branding: map[string]tenant.Branding{},
	}
}

func (s *brandingTestStore) GetBranding(_ context.Context, id string) (tenant.Branding, error) {
	if _, ok := s.tenants[id]; !ok {
		return tenant.Branding{}, tenant.ErrTenantNotFound
	}
	if branding, ok := s.branding[id]; ok {
		return branding, nil
	}
	return tenant.Branding{Values: map[string]string{}, Version: "0"}, nil
}

func (s *brandingTestStore) PutBranding(
	_ context.Context, id string, values map[string]string, expected string,
) (tenant.Branding, error) {
	current, err := s.GetBranding(nil, id)
	if err != nil {
		return tenant.Branding{}, err
	}
	if current.Version != expected {
		return tenant.Branding{}, tenant.ErrBrandingPrecondition
	}
	next := "1"
	if expected == "1" {
		next = "2"
	}
	branding := tenant.Branding{Values: values, Version: next}
	s.branding[id] = branding
	return branding, nil
}

func (s *brandingTestStore) GetTenant(_ context.Context, id string) (*tenant.Tenant, error) {
	t, ok := s.tenants[id]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	return &tenant.Tenant{ID: t.ID, Settings: t.Settings}, nil
}

func (s *brandingTestStore) PutTenant(_ context.Context, t *tenant.Tenant) error {
	s.tenants[t.ID] = &tenantTenant{ID: t.ID, Settings: t.Settings}
	return nil
}
func (s *brandingTestStore) Close() error { return nil }

func (s *brandingTestStore) ListTenants(_ context.Context) ([]*tenant.Tenant, error) { return nil, nil }
func (s *brandingTestStore) DeleteTenant(_ context.Context, id string) error         { return nil }
func (s *brandingTestStore) GetDomain(_ context.Context, hostname string) (*tenant.Domain, error) {
	return nil, nil
}
func (s *brandingTestStore) ListDomains(_ context.Context) ([]*tenant.Domain, error) { return nil, nil }
func (s *brandingTestStore) ListDomainsByTenant(_ context.Context, tenantID string) ([]*tenant.Domain, error) {
	return nil, nil
}
func (s *brandingTestStore) PutDomain(_ context.Context, d *tenant.Domain) error   { return nil }
func (s *brandingTestStore) DeleteDomain(_ context.Context, hostname string) error { return nil }

func brandingCtx(t *testing.T, method, path, body string) *brandingHandlerCtx {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, bytes.NewReader([]byte(body)))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	return &brandingHandlerCtx{rec: httptest.NewRecorder(), req: req}
}

type brandingHandlerCtx struct {
	rec *httptest.ResponseRecorder
	req *http.Request
}

func (c *brandingHandlerCtx) ResponseWriter() http.ResponseWriter     { return c.rec }
func (c *brandingHandlerCtx) Request() *http.Request                  { return c.req }
func (c *brandingHandlerCtx) Set(key string, v any)                   {}
func (c *brandingHandlerCtx) Get(key string) any                      { return nil }
func (c *brandingHandlerCtx) Abort()                                  {}
func (c *brandingHandlerCtx) Aborted() bool                           { return false }
func (c *brandingHandlerCtx) Written() bool                           { return false }
func (c *brandingHandlerCtx) SetResponseWriter(w http.ResponseWriter) {} // tests never swap writers
func (c *brandingHandlerCtx) Redirect(code int, url string)           { http.Redirect(c.rec, c.req, url, code) }
func (c *brandingHandlerCtx) JSON(code int, v any) {
	c.rec.WriteHeader(code)
	json.NewEncoder(c.rec).Encode(v)
}
func (c *brandingHandlerCtx) Bind(v any) error {
	return json.NewDecoder(c.req.Body).Decode(v)
}
func (c *brandingHandlerCtx) Query(key string) string { return c.req.URL.Query().Get(key) }
func (c *brandingHandlerCtx) Param(key string) string { return "" }

func TestAdminGetBranding(t *testing.T) {
	store := newBrandingTestStore()
	store.tenants["tenant-1"] = &tenantTenant{ID: "tenant-1"}
	store.branding["tenant-1"] = tenant.Branding{
		Values: map[string]string{"logo": "https://example.com/logo.png"}, Version: "3",
	}
	deps := newBrandingDeps(store)

	ctx := brandingCtx(t, "GET", "/admin/branding?tenant_id=tenant-1", "")
	HandleAdminGetBranding(deps, ctx)

	if ctx.rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", ctx.rec.Code)
	}
	var result map[string]any
	json.NewDecoder(ctx.rec.Body).Decode(&result)
	if result["tenant_id"] != "tenant-1" {
		t.Errorf("expected tenant-1, got %v", result["tenant_id"])
	}
	if result["version"] != "3" || ctx.rec.Header().Get("ETag") != `"branding-3"` {
		t.Errorf("missing branding version/etag: body=%v headers=%v", result, ctx.rec.Header())
	}
	branding := result["branding"].(map[string]any)
	if branding["logo"] != "https://example.com/logo.png" {
		t.Errorf("expected logo URL, got %v", branding["logo"])
	}
}

func TestAdminGetBranding_NoTenantID(t *testing.T) {
	store := newBrandingTestStore()
	deps := newBrandingDeps(store)
	ctx := brandingCtx(t, "GET", "/admin/branding", "")
	HandleAdminGetBranding(deps, ctx)
	if ctx.rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", ctx.rec.Code)
	}
}

func TestAdminUpdateBranding(t *testing.T) {
	store := newBrandingTestStore()
	store.tenants["tenant-1"] = &tenantTenant{ID: "tenant-1"}
	deps := newBrandingDeps(store)

	body := `{"branding":{"logo":"https://example.com/logo.png","color":"#ff0000"}}`
	ctx := brandingCtx(t, "PUT", "/admin/branding?tenant_id=tenant-1", body)
	ctx.req.Header.Set("If-Match", `"branding-0"`)
	HandleAdminUpdateBranding(deps, ctx)

	if ctx.rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", ctx.rec.Code)
	}

	// Verify persistence
	branding, _ := store.GetBranding(nil, "tenant-1")
	if branding.Values["logo"] != "https://example.com/logo.png" {
		t.Errorf("expected logo to be persisted, got %v", branding.Values["logo"])
	}
}

func TestAdminDeleteBranding(t *testing.T) {
	store := newBrandingTestStore()
	store.tenants["tenant-1"] = &tenantTenant{ID: "tenant-1"}
	store.branding["tenant-1"] = tenant.Branding{
		Values: map[string]string{"logo": "x"}, Version: "1",
	}
	deps := newBrandingDeps(store)

	ctx := brandingCtx(t, "DELETE", "/admin/branding?tenant_id=tenant-1", "")
	ctx.req.Header.Set("If-Match", `"branding-1"`)
	HandleAdminDeleteBranding(deps, ctx)

	if ctx.rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", ctx.rec.Code)
	}

	branding, _ := store.GetBranding(nil, "tenant-1")
	if len(branding.Values) != 0 || branding.Version != "2" {
		t.Errorf("expected versioned empty branding after delete, got %v", branding)
	}
}

func TestAdminUpdateBrandingRejectsStaleVersion(t *testing.T) {
	store := newBrandingTestStore()
	store.tenants["tenant-1"] = &tenantTenant{ID: "tenant-1"}
	store.branding["tenant-1"] = tenant.Branding{Values: map[string]string{}, Version: "1"}
	ctx := brandingCtx(t, "PUT", "/admin/branding?tenant_id=tenant-1", `{"branding":{}}`)
	ctx.req.Header.Set("If-Match", `"branding-0"`)

	HandleAdminUpdateBranding(newBrandingDeps(store), ctx)

	if ctx.rec.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale branding update = %d, want 412", ctx.rec.Code)
	}
}
