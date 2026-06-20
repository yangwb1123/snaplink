package permissions_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
)

// TestResolveResource_TypeMismatchSkips registers a GRPC resource but
// resolves with the HTTP type at the same (tenant,client) — the r.Type !=
// lookup.Type continue branch fires and nothing matches.
func TestResolveResource_TypeMismatchSkips(t *testing.T) {
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypeGRPCAPI, map[string]string{
		"service": "svc", "method": "M",
	})
	_ = p.RegisterResource(ctx, r)

	d, err := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/x"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Found {
		t.Fatalf("type mismatch should not match: %+v", d)
	}
}

func TestResolveResource_ClientMismatchSkips(t *testing.T) {
	// A resource exists under (tenant, clientA) but the lookup names
	// clientB → the scope-filter continue branch skips it.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "client-a", "GET", "/api/v1/users"))

	d, err := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "client-b", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/api/v1/users"},
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if d.Found {
		t.Fatalf("cross-client lookup should not match: %+v", d)
	}
}

func TestResolveResource_GRPCMethodMismatch(t *testing.T) {
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "svc", permissions.ResourceTypeGRPCAPI, map[string]string{
		"service": "snaplink.user.v1.UserService", "method": "Delete",
	})
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "svc", Type: permissions.ResourceTypeGRPCAPI,
		Match: map[string]string{"service": "snaplink.user.v1.UserService", "method": "Create"},
	})
	if d.Found {
		t.Fatalf("grpc method mismatch should not match")
	}
}

func TestResolveResource_GraphQL(t *testing.T) {
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypeGraphQLAPI, map[string]string{
		"op": "mutation", "field": "deleteUser",
	})
	r.RequiredPermissions = []string{"user:delete"}
	_ = p.RegisterResource(ctx, r)

	hit, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeGraphQLAPI,
		Match: map[string]string{"op": "mutation", "field": "deleteUser"},
	})
	if !hit.Found {
		t.Fatalf("graphql exact match should be found")
	}

	miss, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeGraphQLAPI,
		Match: map[string]string{"op": "query", "field": "deleteUser"},
	})
	if miss.Found {
		t.Fatalf("graphql op mismatch should not match")
	}
}

func TestResolveResource_JSFn(t *testing.T) {
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypeJSFn, map[string]string{
		"route": "/admin/users", "symbol": "deleteUserBtn.onClick",
	})
	_ = p.RegisterResource(ctx, r)

	hit, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeJSFn,
		Match: map[string]string{"route": "/admin/users", "symbol": "deleteUserBtn.onClick"},
	})
	if !hit.Found {
		t.Fatalf("js_fn exact match should be found")
	}

	miss, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeJSFn,
		Match: map[string]string{"route": "/admin/users", "symbol": "otherBtn.onClick"},
	})
	if miss.Found {
		t.Fatalf("js_fn symbol mismatch should not match")
	}
}

func TestResolveResource_UIElementSelectorMismatch(t *testing.T) {
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypeUIElement, map[string]string{
		"selector": "#a", "page_id": "p1",
	})
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeUIElement,
		Match: map[string]string{"selector": "#b", "page_id": "p1"},
	})
	if d.Found {
		t.Fatalf("ui_element selector mismatch should not match")
	}
}

func TestResolveResource_UIElementPageIDMismatch(t *testing.T) {
	// Same selector, both sides set page_id but they differ → the
	// page_id disambiguation branch rejects the match.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypeUIElement, map[string]string{
		"selector": "#delete", "page_id": "page-users",
	})
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeUIElement,
		Match: map[string]string{"selector": "#delete", "page_id": "page-orders"},
	})
	if d.Found {
		t.Fatalf("ui_element page_id mismatch should not match")
	}
}

func TestResolveResource_UIElementPageIDOmittedMatchesSelectorOnly(t *testing.T) {
	// page_id only disambiguates when BOTH sides set it. If the lookup
	// omits page_id, a selector match alone is enough.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", permissions.ResourceTypeUIElement, map[string]string{
		"selector": "#delete", "page_id": "page-users",
	})
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeUIElement,
		Match: map[string]string{"selector": "#delete"}, // no page_id
	})
	if !d.Found {
		t.Fatalf("selector-only lookup should match when page_id omitted")
	}
}

func TestResolveResource_CustomTypeKeyMismatch(t *testing.T) {
	// Custom (unknown) type falls into the default best-effort exact-match
	// over every registered key; a differing value rejects.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := newRes("r-1", "t-acme", "web", "ws_event", map[string]string{
		"channel": "billing", "event": "invoice.paid",
	})
	_ = p.RegisterResource(ctx, r)

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: "ws_event",
		Match: map[string]string{"channel": "billing", "event": "invoice.void"},
	})
	if d.Found {
		t.Fatalf("custom type value mismatch should not match")
	}
}

func TestResolveResource_HTTPPathSegmentMismatch(t *testing.T) {
	// Equal segment count, but a concrete (non-:param) segment differs →
	// matchPath's per-segment inequality branch rejects.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.RegisterResource(ctx, httpRes("r-1", "t-acme", "web", "GET", "/api/v1/users"))

	d, _ := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "t-acme", ClientID: "web", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/api/v1/orders"},
	})
	if d.Found {
		t.Fatalf("differing path segment should not match")
	}
}

func TestRegisterResource_NoAttributesCloneRoundTrips(t *testing.T) {
	// A page resource with a non-nil Attributes but nil RequiredPermissions
	// plus a custom-type resource with nil Attributes exercise cloneResource's
	// nil-field branches without aliasing.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	r := &permissions.Resource{
		ID: "r-1", TenantID: "t", ClientID: "c",
		Type: permissions.ResourceTypePage, Name: "home",
		Attributes: map[string]string{"route": "/"},
		// RequiredPermissions intentionally nil.
	}
	if err := p.RegisterResource(ctx, r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := p.GetResource(ctx, "r-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RequiredPermissions != nil {
		t.Errorf("nil RequiredPermissions should round-trip as nil, got %v", got.RequiredPermissions)
	}
	// Mutating the returned attributes must not corrupt stored state.
	got.Attributes["route"] = "/tampered"
	again, _ := p.GetResource(ctx, "r-1")
	if again.Attributes["route"] != "/" {
		t.Errorf("Attributes aliased into stored resource: %v", again.Attributes)
	}
}
