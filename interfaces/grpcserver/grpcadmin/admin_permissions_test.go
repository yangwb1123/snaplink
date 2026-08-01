package grpcadmin

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/platform/audit"
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
	sink := audit.NewMemorySink(10)
	svc := NewPermissionAdminService(prov, audit.New(sink), nil)
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
	events, err := sink.Query(ctx, audit.Query{Limit: 10})
	requireOK(t, err, "sink.Query")
	for _, eventType := range []audit.EventType{audit.EventAdminRoleAssigned, audit.EventAdminRoleUnassigned} {
		found := false
		for _, event := range events {
			if event.Type == eventType && event.Metadata["target_user_id"] == "alice" {
				found = true
			}
		}
		if !found {
			t.Errorf("%s audit event missing target_user_id", eventType)
		}
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

// TestPermissionAdminService_ListRolesPagination proves ListRoles bounds its
// response by page_size (fixed code-ascending sort, since this proto has no
// order_by field), that next_page_token round-trips to the remaining page,
// and that a garbage page_token is rejected. Regression coverage for a List
// RPC that used to ignore page_token/page_size entirely.
func TestPermissionAdminService_ListRolesPagination(t *testing.T) {
	t.Parallel()
	prov := permissions.NewMemoryProvider()
	svc := NewPermissionAdminService(prov, nil, nil)
	ctx := context.Background()
	for _, code := range []string{"alpha", "beta", "gamma"} {
		_, err := svc.AddRole(ctx, &adminv1.AddRoleRequest{ClientId: "web", Role: &adminv1.Role{Code: code}})
		requireOK(t, err, "AddRole "+code)
	}

	page1, err := svc.ListRoles(ctx, &adminv1.ListRolesRequest{ClientId: "web", PageSize: 2})
	requireOK(t, err, "ListRoles page1")
	if len(page1.Roles) != 2 || page1.TotalSize != 3 || page1.NextPageToken == "" {
		t.Fatalf("page1 = len=%d total=%d next=%q", len(page1.Roles), page1.TotalSize, page1.NextPageToken)
	}
	if page1.Roles[0].Code != "alpha" || page1.Roles[1].Code != "beta" {
		t.Errorf("page1 codes = [%s, %s], want [alpha, beta]", page1.Roles[0].Code, page1.Roles[1].Code)
	}

	page2, err := svc.ListRoles(ctx, &adminv1.ListRolesRequest{ClientId: "web", PageSize: 2, PageToken: page1.NextPageToken})
	requireOK(t, err, "ListRoles page2")
	if len(page2.Roles) != 1 || page2.Roles[0].Code != "gamma" || page2.NextPageToken != "" {
		t.Errorf("page2 = %+v, want [gamma] with no further token", page2.Roles)
	}

	_, err = svc.ListRoles(ctx, &adminv1.ListRolesRequest{ClientId: "web", PageToken: "!!!not-valid-base64!!!"})
	requireCode(t, err, codes.InvalidArgument)
}

// TestPermissionAdminService_ListAssignmentsPagination is the same
// regression coverage as ListRolesPagination, for ListAssignments (fixed
// user_id-ascending sort).
func TestPermissionAdminService_ListAssignmentsPagination(t *testing.T) {
	t.Parallel()
	prov := permissions.NewMemoryProvider()
	svc := NewPermissionAdminService(prov, nil, nil)
	ctx := context.Background()
	for _, user := range []string{"alice", "bob", "carol"} {
		_, err := svc.AssignRoles(ctx, &adminv1.AssignRolesRequest{ClientId: "web", UserId: user, Roles: []string{"editor"}})
		requireOK(t, err, "AssignRoles "+user)
	}

	page1, err := svc.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{ClientId: "web", PageSize: 2})
	requireOK(t, err, "ListAssignments page1")
	if len(page1.Assignments) != 2 || page1.TotalSize != 3 || page1.NextPageToken == "" {
		t.Fatalf("page1 = len=%d total=%d next=%q", len(page1.Assignments), page1.TotalSize, page1.NextPageToken)
	}
	if page1.Assignments[0].UserId != "alice" || page1.Assignments[1].UserId != "bob" {
		t.Errorf("page1 user_ids = [%s, %s], want [alice, bob]", page1.Assignments[0].UserId, page1.Assignments[1].UserId)
	}

	page2, err := svc.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{ClientId: "web", PageSize: 2, PageToken: page1.NextPageToken})
	requireOK(t, err, "ListAssignments page2")
	if len(page2.Assignments) != 1 || page2.Assignments[0].UserId != "carol" || page2.NextPageToken != "" {
		t.Errorf("page2 = %+v, want [carol] with no further token", page2.Assignments)
	}

	_, err = svc.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{ClientId: "web", PageToken: "!!!not-valid-base64!!!"})
	requireCode(t, err, codes.InvalidArgument)
}
