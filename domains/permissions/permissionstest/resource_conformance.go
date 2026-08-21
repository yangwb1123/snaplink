package permissionstest

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// ResourceConformanceSuite locks the optional resource catalog contract for
// every backend that implements permissions.ResourceProvider.
type ResourceConformanceSuite struct {
	Factory func(*testing.T) permissions.ResourceProvider
}

// Run executes catalog CRUD, scope, conflict, and runtime matching checks.
func (s ResourceConformanceSuite) Run(t *testing.T) {
	t.Helper()
	if s.Factory == nil {
		t.Fatal("ResourceConformanceSuite: Factory required")
	}
	cases := []struct {
		name string
		fn   func(*testing.T, permissions.ResourceProvider)
	}{
		{"Register_Roundtrip", testResourceRoundtrip},
		{"Register_InvalidRejected", testResourceInvalidRejected},
		{"Register_TupleConflictRejected", testResourceTupleConflict},
		{"Register_SameIDUpdates", testResourceSameIDUpdate},
		{"List_ScopesEntries", testResourceListScope},
		{"Delete_IsIdempotent", testResourceDelete},
		{"Resolve_HTTPPathAndPolicy", testResourceResolveHTTP},
		{"Resolve_TypeAndScope", testResourceResolveScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.fn(t, s.Factory(t))
		})
	}
}

func testResourceRoundtrip(t *testing.T, p permissions.ResourceProvider) {
	ctx := context.Background()
	want := testHTTPResource("r-1", "tenant-a", "client-a", "/users/:id")
	if err := p.RegisterResource(ctx, want); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	first, err := p.GetResource(ctx, want.ID)
	if err != nil {
		t.Fatalf("GetResource: %v", err)
	}
	got, err := p.GetResource(ctx, want.ID)
	if err != nil {
		t.Fatalf("second GetResource: %v", err)
	}
	if got.Attributes["path"] != "/users/:id" || !got.RequiresAuth {
		t.Fatalf("resource mismatch: %+v", got)
	}
	if got.CreatedAt.IsZero() || got.UpdatedAt.IsZero() {
		t.Fatalf("timestamps were not stamped: %+v", got)
	}
	if !got.CreatedAt.Equal(first.CreatedAt) {
		t.Fatalf("created_at changed between reads: %v vs %v", got.CreatedAt, first.CreatedAt)
	}
}

func testResourceInvalidRejected(t *testing.T, p permissions.ResourceProvider) {
	err := p.RegisterResource(context.Background(), &permissions.Resource{
		ID: "r-1", Type: permissions.ResourceTypeHTTPAPI, Name: "missing-attrs",
	})
	if !errors.Is(err, permissions.ErrInvalidResource) {
		t.Fatalf("err=%v, want ErrInvalidResource", err)
	}
}

func testResourceTupleConflict(t *testing.T, p permissions.ResourceProvider) {
	ctx := context.Background()
	first := testHTTPResource("r-1", "tenant-a", "client-a", "/users")
	second := testHTTPResource("r-2", "tenant-a", "client-a", "/other")
	second.Name = first.Name
	if err := p.RegisterResource(ctx, first); err != nil {
		t.Fatalf("first RegisterResource: %v", err)
	}
	if err := p.RegisterResource(ctx, second); !errors.Is(err, permissions.ErrResourceExists) {
		t.Fatalf("err=%v, want ErrResourceExists", err)
	}
}

func testResourceSameIDUpdate(t *testing.T, p permissions.ResourceProvider) {
	ctx := context.Background()
	r := testHTTPResource("r-1", "tenant-a", "client-a", "/users")
	if err := p.RegisterResource(ctx, r); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	r.Description = "updated"
	if err := p.RegisterResource(ctx, r); err != nil {
		t.Fatalf("update RegisterResource: %v", err)
	}
	got, _ := p.GetResource(ctx, r.ID)
	if got.Description != "updated" || got.CreatedAt.IsZero() {
		t.Fatalf("update not stored: %+v", got)
	}
	if got.UpdatedAt.Before(got.CreatedAt) {
		t.Fatalf("updated_at before created_at: %+v", got)
	}
}

func testResourceListScope(t *testing.T, p permissions.ResourceProvider) {
	ctx := context.Background()
	entries := []*permissions.Resource{
		testHTTPResource("a", "tenant-a", "client-a", "/a"),
		testHTTPResource("b", "tenant-a", "client-a", "/b"),
		testHTTPResource("c", "tenant-b", "client-a", "/c"),
	}
	for _, r := range entries {
		if err := p.RegisterResource(ctx, r); err != nil {
			t.Fatalf("RegisterResource %s: %v", r.ID, err)
		}
	}
	got, err := p.ListResources(ctx, "tenant-a", "client-a")
	if err != nil {
		t.Fatalf("ListResources: %v", err)
	}
	if len(got) != 2 || got[0].ID != "a" || got[1].ID != "b" {
		t.Fatalf("scoped list = %+v", got)
	}
}

func testResourceDelete(t *testing.T, p permissions.ResourceProvider) {
	ctx := context.Background()
	r := testHTTPResource("r-1", "tenant-a", "client-a", "/users")
	if err := p.RegisterResource(ctx, r); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	if err := p.DeleteResource(ctx, r.ID); err != nil {
		t.Fatalf("DeleteResource: %v", err)
	}
	if err := p.DeleteResource(ctx, r.ID); err != nil {
		t.Fatalf("second DeleteResource: %v", err)
	}
	if _, err := p.GetResource(ctx, r.ID); !errors.Is(err, permissions.ErrResourceNotFound) {
		t.Fatalf("GetResource after delete: %v", err)
	}
}

func testResourceResolveHTTP(t *testing.T, p permissions.ResourceProvider) {
	ctx := context.Background()
	r := testHTTPResource("r-1", "tenant-a", "client-a", "/users/:id")
	r.RequiredPermissions = []string{"user:read", "user:write"}
	r.RequireMode = permissions.RequireAll
	if err := p.RegisterResource(ctx, r); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	decision, err := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "tenant-a", ClientID: "client-a", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "get", "path": "/users/42"},
	})
	if err != nil {
		t.Fatalf("ResolveResource: %v", err)
	}
	if !decision.Found || decision.ResourceID != r.ID || decision.RequireMode != permissions.RequireAll {
		t.Fatalf("decision = %+v", decision)
	}
	if len(decision.RequiredPermissions) != 2 {
		t.Fatalf("decision permissions = %v", decision.RequiredPermissions)
	}
}

func testResourceResolveScope(t *testing.T, p permissions.ResourceProvider) {
	ctx := context.Background()
	r := &permissions.Resource{
		ID: "r-1", TenantID: "tenant-a", ClientID: "client-a",
		Type: permissions.ResourceTypeGRPCAPI, Name: "delete",
		Attributes: map[string]string{"service": "users.User", "method": "Delete"},
	}
	if err := p.RegisterResource(ctx, r); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	miss, err := p.ResolveResource(ctx, permissions.ResourceLookup{
		TenantID: "tenant-b", ClientID: "client-a", Type: permissions.ResourceTypeGRPCAPI,
		Match: map[string]string{"service": "users.User", "method": "Delete"},
	})
	if err != nil {
		t.Fatalf("ResolveResource mismatch: %v", err)
	}
	if miss.Found {
		t.Fatalf("cross-tenant resource matched: %+v", miss)
	}
}

func testHTTPResource(id, tenantID, clientID, path string) *permissions.Resource {
	return &permissions.Resource{
		ID: id, TenantID: tenantID, ClientID: clientID,
		Type: permissions.ResourceTypeHTTPAPI, Name: id,
		RequiresAuth: true,
		Attributes:   map[string]string{"method": "GET", "path": path},
	}
}
