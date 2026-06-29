package permissions_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
)

func newRes(id, tenantID, clientID string, t permissions.ResourceType, attrs map[string]string) *permissions.Resource {
	return &permissions.Resource{
		ID: id, TenantID: tenantID, ClientID: clientID,
		Type: t, Name: id,
		RequiresAuth: true,
		Attributes:   attrs,
	}
}

func httpRes(id, tenantID, clientID, method, path string) *permissions.Resource {
	r := newRes(id, tenantID, clientID, permissions.ResourceTypeHTTPAPI, map[string]string{
		"method": method,
		"path":   path,
	})
	r.RequiredPermissions = []string{"user:read"}
	return r
}

// --- Catalog CRUD ---

func TestRegisterResource_RoundTrip(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	if err := p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web-app", "GET", "/users")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := p.GetResource(ctx, "r-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Attributes["path"] != "/users" {
		t.Errorf("attribute round-trip failed: %+v", got.Attributes)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Errorf("timestamps not stamped")
	}
}

func TestRegisterResource_RejectsInvalid(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	r := &permissions.Resource{ID: "r-1", Type: permissions.ResourceTypeHTTPAPI, Name: "x"} // missing attrs
	if err := p.RegisterResource(context.Background(), r); !errors.Is(err, permissions.ErrInvalidResource) {
		t.Errorf("err=%v", err)
	}
}

func TestRegisterResource_TupleConflictRejected(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web-app", "GET", "/users"))
	dup := httpRes("r-2", "t-acme", "web-app", "GET", "/users") // different ID, same name+type+scope
	dup.Name = "r-1"                                            // same Name as r-1
	if err := p.RegisterResource(ctx, dup); !errors.Is(err, permissions.ErrResourceExists) {
		t.Errorf("err=%v want ErrResourceExists", err)
	}
}

func TestRegisterResource_SameIDIdempotent(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web-app", "GET", "/users"))
	updated := httpRes("r-1", "t-acme", "web-app", "GET", "/users")
	updated.Description = "updated"
	if err := p.RegisterResource(ctx, updated); err != nil {
		t.Errorf("idempotent re-register failed: %v", err)
	}
	got, _ := p.GetResource(ctx, "r-1")
	if got.Description != "updated" {
		t.Errorf("update did not take effect")
	}
}

func TestRegisterResource_RetupleClearsStaleIndex(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := httpRes("r-1", "t-acme", "web-app", "GET", "/users")
	r.Name = "list-users"
	_ = p.RegisterResource(ctx, r)

	// Rename: same ID, different Name → tuple changes. The old
	// tuple should not block a future Register at the new name.
	r.Name = "browse-users"
	if err := p.RegisterResource(ctx, r); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// Old tuple should be free now.
	r2 := httpRes("r-2", "t-acme", "web-app", "GET", "/list")
	r2.Name = "list-users"
	if err := p.RegisterResource(ctx, r2); err != nil {
		t.Errorf("old tuple still occupied: %v", err)
	}
}

func TestGetResource_MissingIsErrResourceNotFound(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	if _, err := p.GetResource(context.Background(), "ghost"); !errors.Is(err, permissions.ErrResourceNotFound) {
		t.Errorf("err=%v", err)
	}
}

func TestListResources_FiltersByScope(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-acme-a", "t-acme", "web", "GET", "/a"))
	_ = p.RegisterResource(ctx, httpRes("r-acme-b", "t-acme", "web", "GET", "/b"))
	_ = p.RegisterResource(ctx, httpRes("r-beta", "t-beta", "web", "GET", "/x"))
	_ = p.RegisterResource(ctx, httpRes("r-platform", "", "web", "GET", "/y"))

	acmeWeb, _ := p.ListResources(ctx, "t-acme", "web")
	if len(acmeWeb) != 2 {
		t.Errorf("acme/web len=%d, want 2", len(acmeWeb))
	}
	platform, _ := p.ListResources(ctx, "", "web")
	if len(platform) != 1 || platform[0].ID != "r-platform" {
		t.Errorf("no-tenant bucket = %+v", platform)
	}
}

func TestDeleteResource_ClearsIndex(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := httpRes("r-1", "t-acme", "web-app", "GET", "/users")
	_ = p.RegisterResource(ctx, r)
	if err := p.DeleteResource(ctx, "r-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	// Index cleared → re-register at the same tuple should succeed
	// without ErrResourceExists.
	if err := p.RegisterResource(ctx, httpRes("r-2", "t-acme", "web-app", "GET", "/users")); err != nil {
		t.Errorf("re-register after delete: %v", err)
	}
}

func TestDeleteResource_MissingIsIdempotent(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	if err := p.DeleteResource(context.Background(), "ghost"); err != nil {
		t.Errorf("delete missing: %v", err)
	}
}

// --- ResolveResource matching ---

func TestResolveResource_HTTPExactMatch(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web", "GET", "/api/v1/users"))
	d, err := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/api/v1/users"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !d.Found || d.ResourceID != "r-1" {
		t.Errorf("decision=%+v", d)
	}
	if len(d.RequiredPermissions) != 1 || d.RequiredPermissions[0] != "user:read" {
		t.Errorf("perms=%+v", d.RequiredPermissions)
	}
	if d.RequireMode != permissions.RequireAny {
		t.Errorf("mode=%q want any", d.RequireMode)
	}
}

func TestResolveResource_HTTPMethodMismatch(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web", "GET", "/api/v1/users"))
	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "POST", "path": "/api/v1/users"},
	})
	if d.Found {
		t.Errorf("POST should not match GET-registered resource")
	}
}

func TestResolveResource_HTTPMethodCaseInsensitive(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web", "GET", "/api/v1/users"))
	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "get", "path": "/api/v1/users"}, // lowercase
	})
	if !d.Found {
		t.Errorf("HTTP method match should be case-insensitive")
	}
}

func TestResolveResource_HTTPPathParam(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web", "DELETE", "/api/v1/users/:id"))
	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "DELETE", "path": "/api/v1/users/123"},
	})
	if !d.Found {
		t.Errorf("path :id should match concrete value")
	}
}

func TestResolveResource_HTTPPathLengthMismatch(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web", "GET", "/api/v1/users"))
	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/api/v1/users/123"},
	})
	if d.Found {
		t.Errorf("longer path should not match")
	}
}

func TestResolveResource_TenantIsolation(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-acme", "t-acme", "web", "GET", "/api/v1/users"))
	_ = p.RegisterResource(ctx, httpRes("r-beta", "t-beta", "web", "GET", "/api/v1/users"))

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-beta", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/api/v1/users"},
	})
	if !d.Found || d.ResourceID != "r-beta" {
		t.Errorf("cross-tenant leak: decision=%+v", d)
	}
}

func TestResolveResource_GRPC(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "user-svc", permissions.ResourceTypeGRPCAPI, map[string]string{
		"service": "snaplink.user.v1.UserService", "method": "Delete",
	})
	r.RequiredPermissions = []string{"user:delete"}
	r.RequireMode = permissions.RequireAll
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "user-svc", Type: permissions.ResourceTypeGRPCAPI,
		Match: map[string]string{"service": "snaplink.user.v1.UserService", "method": "Delete"},
	})
	if !d.Found {
		t.Fatalf("not found")
	}
	if d.RequireMode != permissions.RequireAll {
		t.Errorf("RequireMode=%q", d.RequireMode)
	}
}

func TestResolveResource_Page(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypePage, map[string]string{"route": "/admin/users"})
	r.RequiredPermissions = []string{"admin:view"}
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypePage,
		Match: map[string]string{"route": "/admin/users"},
	})
	if !d.Found {
		t.Errorf("page not found")
	}
}

func TestResolveResource_NoMatchReturnsFoundFalse(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	d, err := p.ResolveResource(context.Background(), permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/x"},
	})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if d.Found {
		t.Errorf("decision.Found=true for empty catalog")
	}
}

func TestResolveResource_PublicResourceCarriesRequiresAuthFalse(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := httpRes("r-1", "t-acme", "web", "GET", "/healthz")
	r.RequiresAuth = false
	r.RequiredPermissions = nil
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/healthz"},
	})
	if !d.Found {
		t.Fatalf("not found")
	}
	if d.RequiresAuth {
		t.Errorf("public resource should have RequiresAuth=false")
	}
}

func TestResolveResource_UIElement(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypeUIElement, map[string]string{
		"selector":     "#userTable .delete-btn",
		"page_id":      "page-users",
		"element_kind": "button",
		"behavior":     "hide",
	})
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeUIElement,
		Match: map[string]string{"selector": "#userTable .delete-btn", "page_id": "page-users"},
	})
	if !d.Found {
		t.Errorf("ui_element not found")
	}
}

func TestResolveResource_CustomTypeExactMatch(t *testing.T) {
	t.Parallel()
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", "ws_event", map[string]string{
		"channel": "billing", "event": "invoice.paid",
	})
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: "ws_event",
		Match: map[string]string{"channel": "billing", "event": "invoice.paid"},
	})
	if !d.Found {
		t.Errorf("custom type not found")
	}
}
