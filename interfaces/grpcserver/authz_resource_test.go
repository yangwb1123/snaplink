package grpcserver_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestAuthz_Check_ResourceCatalogRequireAllAndFlatFallback(t *testing.T) {
	t.Parallel()
	prov := permissions.NewMemoryProvider()
	ctx := context.Background()
	if err := prov.AddRole(ctx, "web", permissions.Role{
		Code: "operator", Permissions: []string{"billing:write", "user:read"},
	}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := prov.AssignRoles(ctx, "alice", "web", []string{"operator"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := prov.RegisterResource(ctx, &permissions.Resource{
		ID: "r-sensitive", TenantID: "tenant-a", ClientID: "web",
		Type: permissions.ResourceTypeHTTPAPI, Name: "sensitive", RequiresAuth: true,
		Attributes:          map[string]string{"method": "POST", "path": "/users/:id"},
		RequiredPermissions: []string{"billing:write", "audit:read"}, RequireMode: permissions.RequireAll,
	}); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	conn := startGRPC(t, nil, prov, nil)
	client := authzv1.NewAuthorizerClient(conn)
	request := &authzv1.CheckRequest{
		SubjectId: "alice", ClientId: "web", Permission: "ignored",
		ResourceType: string(permissions.ResourceTypeHTTPAPI), TenantId: "tenant-a",
		Attributes: map[string]string{"method": "POST", "path": "/users/42"},
	}
	resp, err := client.Check(ctx, request)
	if err != nil {
		t.Fatalf("partial Check: %v", err)
	}
	if resp.Allowed {
		t.Fatal("resource require-all allowed with one permission")
	}
	if err := prov.UpdateRole(ctx, "web", permissions.Role{
		Code: "operator", Permissions: []string{"billing:write", "audit:read", "user:read"},
	}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	resp, err = client.Check(ctx, request)
	if err != nil || !resp.Allowed {
		t.Fatalf("complete Check = %+v, %v", resp, err)
	}

	request.Attributes = map[string]string{"method": "POST", "path": "/not-cataloged"}
	request.Permission = "user:read"
	resp, err = client.Check(ctx, request)
	if err != nil || !resp.Allowed {
		t.Fatalf("flat fallback = %+v, %v", resp, err)
	}
}

func TestAuthz_Check_ResourceLookupRequiresCatalogProvider(t *testing.T) {
	t.Parallel()
	conn := startGRPC(t, nil, &erroringProvider{err: nil}, nil)
	client := authzv1.NewAuthorizerClient(conn)
	_, err := client.Check(context.Background(), &authzv1.CheckRequest{
		SubjectId: "alice", Permission: "user:read", ResourceType: "http_api",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition", status.Code(err))
	}
}
