package permissions_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

func TestCheckResource_LegacyAndCatalogMissKeepFlatDecision(t *testing.T) {
	p := permissions.NewMemoryProvider()
	perms := []permissions.Permission{{Code: "user:read"}}
	allowed, err := permissions.CheckResource(p, nil, perms, "user:read")
	if err != nil || !allowed {
		t.Fatalf("legacy check = %v, %v", allowed, err)
	}
	allowed, err = permissions.CheckResource(p, &permissions.ResourceLookup{
		TenantID: "tenant-a", ClientID: "client-a", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/missing"},
	}, perms, "user:read")
	if err != nil || !allowed {
		t.Fatalf("catalog miss check = %v, %v", allowed, err)
	}
}

func TestCheckResource_RequireModesAndPublicResources(t *testing.T) {
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	all := &permissions.Resource{
		ID: "all", TenantID: "tenant-a", ClientID: "client-a",
		Type: permissions.ResourceTypeHTTPAPI, Name: "sensitive", RequiresAuth: true,
		Attributes:          map[string]string{"method": "POST", "path": "/sensitive"},
		RequiredPermissions: []string{"billing:write", "audit:read"},
		RequireMode:         permissions.RequireAll,
	}
	if err := p.RegisterResource(ctx, all); err != nil {
		t.Fatalf("Register all: %v", err)
	}
	lookup := &permissions.ResourceLookup{
		TenantID: "tenant-a", ClientID: "client-a", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "POST", "path": "/sensitive"},
	}
	partial := []permissions.Permission{{Code: "billing:write"}}
	allowed, err := permissions.CheckResource(p, lookup, partial, "ignored")
	if err != nil || allowed {
		t.Fatalf("partial all check = %v, %v", allowed, err)
	}
	both := append(partial, permissions.Permission{Code: "audit:read"})
	allowed, err = permissions.CheckResource(p, lookup, both, "ignored")
	if err != nil || !allowed {
		t.Fatalf("complete all check = %v, %v", allowed, err)
	}

	public := *all
	public.ID, public.Name = "public", "public"
	public.RequiresAuth = false
	public.RequiredPermissions = nil
	public.Attributes = map[string]string{"method": "GET", "path": "/public"}
	if err := p.RegisterResource(ctx, &public); err != nil {
		t.Fatalf("Register public: %v", err)
	}
	allowed, err = permissions.CheckResource(p, &permissions.ResourceLookup{
		TenantID: "tenant-a", ClientID: "client-a", Type: permissions.ResourceTypeHTTPAPI,
		Match: map[string]string{"method": "GET", "path": "/public"},
	}, nil, "ignored")
	if err != nil || !allowed {
		t.Fatalf("public check = %v, %v", allowed, err)
	}
}
