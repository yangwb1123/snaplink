package grpcadmin

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/codes"
)

// TestPermissionAdminService_NilProviderPreconditionFails proves every RPC
// returns FailedPrecondition rather than panicking when the provider
// dependency is unwired.
func TestPermissionAdminService_NilProviderPreconditionFails(t *testing.T) {
	t.Parallel()
	svc := NewPermissionAdminService(nil, nil, nil)
	ctx := context.Background()

	_, err := svc.ListRoles(ctx, &adminv1.ListRolesRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.AddRole(ctx, &adminv1.AddRoleRequest{Role: &adminv1.Role{Code: "r"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.UpdateRole(ctx, &adminv1.UpdateRoleRequest{Role: &adminv1.Role{Code: "r"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.RemoveRole(ctx, &adminv1.RemoveRoleRequest{RoleCode: "r"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.AssignRoles(ctx, &adminv1.AssignRolesRequest{UserId: "u"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.UnassignRoles(ctx, &adminv1.UnassignRolesRequest{UserId: "u"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.SetMenus(ctx, &adminv1.SetMenusRequest{})
	requireCode(t, err, codes.FailedPrecondition)
}

// TestPermissionAdminService_RoleCRUDAndInvalidateCallback drives AddRole /
// UpdateRole / RemoveRole directly and proves the optional
// invalidateAuthzPolicy hook fires on every role-definition mutation (wired
// to InvalidateAuthzPolicyBundleCache in production).
func TestPermissionAdminService_RoleCRUDAndInvalidateCallback(t *testing.T) {
	t.Parallel()
	prov := permissions.NewMemoryProvider()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	var invalidated []string
	svc := NewPermissionAdminService(prov, rec, func(_ context.Context, clientID string) { invalidated = append(invalidated, clientID) })
	ctx := context.Background()

	_, err := svc.AddRole(ctx, &adminv1.AddRoleRequest{ClientId: "web", Role: &adminv1.Role{
		Code: "editor", Name: "Editor", Permissions: []string{"doc:read", "doc:write"},
	}})
	requireOK(t, err, "AddRole")
	if len(invalidated) != 1 || invalidated[0] != "web" {
		t.Errorf("expected AddRole to invalidate web, got %v", invalidated)
	}

	_, err = svc.AddRole(ctx, &adminv1.AddRoleRequest{ClientId: "web", Role: &adminv1.Role{Code: "editor"}})
	requireCode(t, err, codes.AlreadyExists)

	list, err := svc.ListRoles(ctx, &adminv1.ListRolesRequest{ClientId: "web"})
	requireOK(t, err, "ListRoles")
	if len(list.Roles) != 1 || list.Roles[0].Code != "editor" {
		t.Errorf("ListRoles = %+v", list.Roles)
	}

	_, err = svc.UpdateRole(ctx, &adminv1.UpdateRoleRequest{ClientId: "web", Role: &adminv1.Role{
		Code: "editor", Name: "Senior Editor", Permissions: []string{"doc:read"},
	}})
	requireOK(t, err, "UpdateRole")
	if len(invalidated) != 2 {
		t.Errorf("expected UpdateRole to invalidate again, count=%d", len(invalidated))
	}

	_, err = svc.UpdateRole(ctx, &adminv1.UpdateRoleRequest{ClientId: "web", Role: &adminv1.Role{Code: "missing"}})
	requireCode(t, err, codes.NotFound)

	_, err = svc.RemoveRole(ctx, &adminv1.RemoveRoleRequest{ClientId: "web", RoleCode: "editor"})
	requireOK(t, err, "RemoveRole")
	if len(invalidated) != 3 {
		t.Errorf("expected RemoveRole to invalidate again, count=%d", len(invalidated))
	}

	_, err = svc.RemoveRole(ctx, &adminv1.RemoveRoleRequest{ClientId: "web", RoleCode: "editor"})
	requireCode(t, err, codes.NotFound)

	events, err := sink.Query(ctx, audit.Query{})
	requireOK(t, err, "sink.Query")
	if len(events) != 3 {
		t.Errorf("expected 3 audit events (add/update/remove), got %d", len(events))
	}
}

// TestPermissionAdminService_AssignmentsAndMenus covers the role-assignment
// and menu-tree RPCs, including the nested MenuItem -> Button / Children
// conversion.
func TestPermissionAdminService_AssignmentsAndMenus(t *testing.T) {
	t.Parallel()
	prov := permissions.NewMemoryProvider()
	svc := NewPermissionAdminService(prov, nil, nil)
	ctx := context.Background()

	_, err := svc.AssignRoles(ctx, &adminv1.AssignRolesRequest{ClientId: "web", UserId: "alice", Roles: []string{"editor"}})
	requireOK(t, err, "AssignRoles")

	list, err := svc.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{ClientId: "web"})
	requireOK(t, err, "ListAssignments")
	if len(list.Assignments) != 1 || list.Assignments[0].UserId != "alice" {
		t.Errorf("ListAssignments = %+v", list.Assignments)
	}

	_, err = svc.UnassignRoles(ctx, &adminv1.UnassignRolesRequest{ClientId: "web", UserId: "alice", Roles: []string{"editor"}})
	requireOK(t, err, "UnassignRoles")
	list, _ = svc.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{ClientId: "web"})
	if len(list.Assignments) != 0 {
		t.Errorf("expected no assignments after Unassign, got %+v", list.Assignments)
	}

	_, err = svc.SetMenus(ctx, &adminv1.SetMenusRequest{ClientId: "web", Menus: []*adminv1.MenuItem{
		{
			Id: "dash", Name: "Dashboard", Path: "/", Permission: "dash:view",
			Buttons:  []*adminv1.Button{{Code: "export", Name: "Export", Permission: "dash:export"}},
			Children: []*adminv1.MenuItem{{Id: "sub", Name: "Sub"}},
		},
	}})
	requireOK(t, err, "SetMenus")

	menus, err := prov.GetMenus(ctx, "web")
	requireOK(t, err, "GetMenus")
	if len(menus) != 1 || menus[0].ID != "dash" || len(menus[0].Buttons) != 1 || len(menus[0].Children) != 1 {
		t.Errorf("SetMenus did not round-trip correctly: %+v", menus)
	}

	_, err = svc.AssignRoles(ctx, &adminv1.AssignRolesRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.UnassignRoles(ctx, &adminv1.UnassignRolesRequest{})
	requireCode(t, err, codes.InvalidArgument)
}
