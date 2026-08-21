package grpcserver_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
)

func TestAuthzCheckMatchesExportedPolicyBundle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	roles := []permissions.Role{
		{Code: "operator", Permissions: []string{"billing:write", "audit:read"}},
		{Code: "billing", Permissions: []string{"billing:write"}},
	}
	for _, role := range roles {
		if err := p.AddRole(ctx, "web", role); err != nil {
			t.Fatalf("AddRole %s: %v", role.Code, err)
		}
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"operator"}); err != nil {
		t.Fatalf("AssignRoles alice: %v", err)
	}
	if err := p.AssignRoles(ctx, "bob", "web", []string{"billing"}); err != nil {
		t.Fatalf("AssignRoles bob: %v", err)
	}
	if err := p.RegisterResource(ctx, &permissions.Resource{
		ID: "r-sensitive", TenantID: "tenant-a", ClientID: "web",
		Type: permissions.ResourceTypeHTTPAPI, Name: "sensitive", RequiresAuth: true,
		Attributes:          map[string]string{"method": "POST", "path": "/users"},
		RequiredPermissions: []string{"billing:write", "audit:read"}, RequireMode: permissions.RequireAll,
	}); err != nil {
		t.Fatalf("RegisterResource: %v", err)
	}
	bundle, err := permissions.BuildPolicyBundle(ctx, p, "web")
	if err != nil {
		t.Fatalf("BuildPolicyBundle: %v", err)
	}
	service := grpcserver.NewAuthzService(p)
	fixtures := []struct {
		subject string
		roles   []string
		request *authzv1.CheckRequest
	}{
		{"alice", []string{"operator"}, &authzv1.CheckRequest{
			SubjectId: "alice", ClientId: "web", Permission: "ignored", ResourceType: "http_api",
			TenantId: "tenant-a", Attributes: map[string]string{"method": "POST", "path": "/users"},
		}},
		{"bob", []string{"billing"}, &authzv1.CheckRequest{
			SubjectId: "bob", ClientId: "web", Permission: "ignored", ResourceType: "http_api",
			TenantId: "tenant-a", Attributes: map[string]string{"method": "POST", "path": "/users"},
		}},
		{"bob", []string{"billing"}, &authzv1.CheckRequest{
			SubjectId: "bob", ClientId: "web", Permission: "billing:write", ResourceType: "http_api",
			TenantId: "tenant-a", Attributes: map[string]string{"method": "POST", "path": "/not-cataloged"},
		}},
	}
	for _, fixture := range fixtures {
		live, err := service.Check(ctx, fixture.request)
		if err != nil {
			t.Fatalf("Check %s: %v", fixture.subject, err)
		}
		bundled := bundleAllows(bundle, fixture.roles, fixture.request)
		if live.Allowed != bundled {
			t.Errorf("subject %s: server=%v bundle=%v request=%+v", fixture.subject, live.Allowed, bundled, fixture.request)
		}
	}
}

func bundleAllows(bundle *permissions.PolicyBundle, roleCodes []string, request *authzv1.CheckRequest) bool {
	granted := bundlePermissions(bundle, roleCodes)
	resource := bundleResource(bundle, request)
	if resource == nil {
		return permissions.Matches(granted, request.Permission)
	}
	if !resource.RequiresAuth || len(resource.RequiredPermissions) == 0 {
		return true
	}
	if resource.RequireMode == permissions.RequireAll {
		for _, required := range resource.RequiredPermissions {
			if !permissions.Matches(granted, required) {
				return false
			}
		}
		return true
	}
	for _, required := range resource.RequiredPermissions {
		if permissions.Matches(granted, required) {
			return true
		}
	}
	return false
}

func bundlePermissions(bundle *permissions.PolicyBundle, roleCodes []string) []permissions.Permission {
	wanted := make(map[string]struct{}, len(roleCodes))
	for _, code := range roleCodes {
		wanted[code] = struct{}{}
	}
	var out []permissions.Permission
	for _, role := range bundle.Roles {
		if _, ok := wanted[role.Code]; !ok {
			continue
		}
		for _, code := range role.Permissions {
			out = append(out, permissions.Permission{Code: code})
		}
	}
	return out
}

func bundleResource(bundle *permissions.PolicyBundle, request *authzv1.CheckRequest) *permissions.ResourceBundle {
	for i := range bundle.Resources {
		resource := &bundle.Resources[i]
		if resource.TenantID != request.TenantId || resource.ClientID != request.ClientId ||
			string(resource.Type) != request.ResourceType || !bundleAttributesMatch(resource.Attributes, request.Attributes) {
			continue
		}
		return resource
	}
	return nil
}

func bundleAttributesMatch(want, have map[string]string) bool {
	if len(want) != len(have) {
		return false
	}
	for key, value := range want {
		if have[key] != value {
			return false
		}
	}
	return true
}
