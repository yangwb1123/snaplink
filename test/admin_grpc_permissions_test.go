package ssotest

import (
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
)

func TestAdminGRPC_PermissionCRUD(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewPermissionAdminServiceClient(h.Conn)

	// AddRole
	added, err := svc.AddRole(h.ctx, &adminv1.AddRoleRequest{
		ClientId: "test-client",
		Role: &adminv1.Role{
			Code: "test-role",
			Name: "Test Role",
			Permissions: []string{"test:read", "test:write"},
		},
	})
	if err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if added.GetRole().GetCode() != "test-role" {
		t.Fatalf("got code %q", added.GetRole().GetCode())
	}

	// ListRoles
	list, err := svc.ListRoles(h.ctx, &adminv1.ListRolesRequest{ClientId: "test-client"})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(list.GetRoles()) < 1 {
		t.Fatal("expected at least 1 role")
	}

	// RemoveRole
	_, err = svc.RemoveRole(h.ctx, &adminv1.RemoveRoleRequest{
		ClientId: "test-client",
		RoleCode: "test-role",
	})
	if err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
}

func TestAdminGRPC_PermissionAssignments(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewPermissionAdminServiceClient(h.Conn)

	_, err := svc.AssignRoles(h.ctx, &adminv1.AssignRolesRequest{
		UserId: "alice",
		Roles:  []string{"items-reader"},
	})
	if err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
}
