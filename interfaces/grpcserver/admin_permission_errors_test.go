package grpcserver_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// erroringPermissionProvider returns the configured error from every method.
type erroringPermissionProvider struct{ err error }

func (e *erroringPermissionProvider) Permissions(context.Context, string, string) ([]permissions.Permission, error) {
	return nil, e.err
}
func (e *erroringPermissionProvider) Roles(context.Context, string, string) ([]permissions.Role, error) {
	return nil, e.err
}
func (e *erroringPermissionProvider) Menus(context.Context, string, string) (permissions.MenuTree, error) {
	return nil, e.err
}
func (e *erroringPermissionProvider) AddRole(context.Context, string, permissions.Role) error {
	return e.err
}
func (e *erroringPermissionProvider) UpdateRole(context.Context, string, permissions.Role) error {
	return e.err
}
func (e *erroringPermissionProvider) RemoveRole(context.Context, string, string) error {
	return e.err
}
func (e *erroringPermissionProvider) ListAllRoles(context.Context, string) ([]permissions.Role, error) {
	return nil, e.err
}
func (e *erroringPermissionProvider) AssignRoles(context.Context, string, string, []string) error {
	return e.err
}
func (e *erroringPermissionProvider) UnassignRoles(context.Context, string, string, []string) error {
	return e.err
}
func (e *erroringPermissionProvider) ListAssignments(context.Context, string) ([]permissions.Assignment, error) {
	return nil, e.err
}
func (e *erroringPermissionProvider) SetMenus(context.Context, string, permissions.MenuTree) error {
	return e.err
}
func (e *erroringPermissionProvider) GetMenus(context.Context, string) (permissions.MenuTree, error) {
	return nil, e.err
}

// ---------- nil provider → FailedPrecondition ----------

func TestPermissionAdmin_NilProvider_FailedPrecondition(t *testing.T) {
	t.Parallel()
	conn := startAdminGRPC(t, nil, nil, nil, nil, nil, nil)
	c := adminv1.NewPermissionAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"ListRoles", func() error { _, e := c.ListRoles(ctx, &adminv1.ListRolesRequest{}); return e }},
		{"AddRole", func() error {
			_, e := c.AddRole(ctx, &adminv1.AddRoleRequest{Role: &adminv1.Role{Code: "x"}})
			return e
		}},
		{"UpdateRole", func() error {
			_, e := c.UpdateRole(ctx, &adminv1.UpdateRoleRequest{Role: &adminv1.Role{Code: "x"}})
			return e
		}},
		{"RemoveRole", func() error {
			_, e := c.RemoveRole(ctx, &adminv1.RemoveRoleRequest{RoleCode: "x"})
			return e
		}},
		{"ListAssignments", func() error {
			_, e := c.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{})
			return e
		}},
		{"AssignRoles", func() error {
			_, e := c.AssignRoles(ctx, &adminv1.AssignRolesRequest{UserId: "u"})
			return e
		}},
		{"UnassignRoles", func() error {
			_, e := c.UnassignRoles(ctx, &adminv1.UnassignRolesRequest{UserId: "u"})
			return e
		}},
		{"SetMenus", func() error { _, e := c.SetMenus(ctx, &adminv1.SetMenusRequest{}); return e }},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", tc.name, got)
		}
	}
}

// ---------- bad args → InvalidArgument ----------

func TestPermissionAdmin_BadArgs_InvalidArgument(t *testing.T) {
	t.Parallel()
	prov := &erroringPermissionProvider{} // non-nil so we get past the FailedPrecondition gate
	conn := startAdminGRPC(t, nil, nil, nil, prov, nil, nil)
	c := adminv1.NewPermissionAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"AddRole-nil-role", func() error {
			_, e := c.AddRole(ctx, &adminv1.AddRoleRequest{})
			return e
		}},
		{"AddRole-empty-code", func() error {
			_, e := c.AddRole(ctx, &adminv1.AddRoleRequest{Role: &adminv1.Role{}})
			return e
		}},
		{"UpdateRole-nil-role", func() error {
			_, e := c.UpdateRole(ctx, &adminv1.UpdateRoleRequest{})
			return e
		}},
		{"UpdateRole-empty-code", func() error {
			_, e := c.UpdateRole(ctx, &adminv1.UpdateRoleRequest{Role: &adminv1.Role{}})
			return e
		}},
		{"RemoveRole-empty-code", func() error {
			_, e := c.RemoveRole(ctx, &adminv1.RemoveRoleRequest{})
			return e
		}},
		{"AssignRoles-empty-user", func() error {
			_, e := c.AssignRoles(ctx, &adminv1.AssignRolesRequest{})
			return e
		}},
		{"UnassignRoles-empty-user", func() error {
			_, e := c.UnassignRoles(ctx, &adminv1.UnassignRolesRequest{})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", tc.name, got)
		}
	}
}

// ---------- provider error → Internal ----------

func TestPermissionAdmin_ProviderError_Internal(t *testing.T) {
	t.Parallel()
	prov := &erroringPermissionProvider{err: errors.New("db unavailable")}
	conn := startAdminGRPC(t, nil, nil, nil, prov, nil, nil)
	c := adminv1.NewPermissionAdminServiceClient(conn)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"ListRoles", func() error { _, e := c.ListRoles(ctx, &adminv1.ListRolesRequest{}); return e }},
		{"AddRole", func() error {
			_, e := c.AddRole(ctx, &adminv1.AddRoleRequest{Role: &adminv1.Role{Code: "x"}})
			return e
		}},
		{"ListAssignments", func() error {
			_, e := c.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{})
			return e
		}},
		{"AssignRoles", func() error {
			_, e := c.AssignRoles(ctx, &adminv1.AssignRolesRequest{UserId: "u"})
			return e
		}},
		{"UnassignRoles", func() error {
			_, e := c.UnassignRoles(ctx, &adminv1.UnassignRolesRequest{UserId: "u"})
			return e
		}},
		{"SetMenus", func() error { _, e := c.SetMenus(ctx, &adminv1.SetMenusRequest{}); return e }},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", tc.name, got)
		}
	}
}

// ---------- sentinel mappings ----------

func TestPermissionAdmin_AddRole_AlreadyExists(t *testing.T) {
	t.Parallel()
	prov := &erroringPermissionProvider{err: permissions.ErrRoleExists}
	conn := startAdminGRPC(t, nil, nil, nil, prov, nil, nil)
	c := adminv1.NewPermissionAdminServiceClient(conn)

	_, err := c.AddRole(context.Background(), &adminv1.AddRoleRequest{
		Role: &adminv1.Role{Code: "dup"},
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", status.Code(err))
	}
}

func TestPermissionAdmin_UpdateRole_NotFound(t *testing.T) {
	t.Parallel()
	prov := &erroringPermissionProvider{err: permissions.ErrRoleNotFound}
	conn := startAdminGRPC(t, nil, nil, nil, prov, nil, nil)
	c := adminv1.NewPermissionAdminServiceClient(conn)

	_, err := c.UpdateRole(context.Background(), &adminv1.UpdateRoleRequest{
		Role: &adminv1.Role{Code: "ghost"},
	})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestPermissionAdmin_RemoveRole_NotFound(t *testing.T) {
	t.Parallel()
	prov := &erroringPermissionProvider{err: permissions.ErrRoleNotFound}
	conn := startAdminGRPC(t, nil, nil, nil, prov, nil, nil)
	c := adminv1.NewPermissionAdminServiceClient(conn)

	_, err := c.RemoveRole(context.Background(), &adminv1.RemoveRoleRequest{RoleCode: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

// ---------- protoToMenuItem nested-tree coverage ----------

func TestPermissionAdmin_SetMenus_NestedTree(t *testing.T) {
	t.Parallel()
	// Exercise protoToMenuItem's Buttons + Children branches by sending
	// a multi-level menu tree through SetMenus and reading it back via
	// the storage layer.
	prov := permissions.NewMemoryProvider()
	conn := startAdminGRPC(t, nil, nil, nil, prov, nil, nil)
	c := adminv1.NewPermissionAdminServiceClient(conn)

	tree := []*adminv1.MenuItem{
		{
			Id: "m-users", Name: "Users", Path: "/users", Permission: "user:read",
			Buttons: []*adminv1.Button{
				{Code: "btn-create", Name: "New", Permission: "user:create"},
				{Code: "btn-delete", Name: "Delete", Permission: "user:delete"},
			},
			Children: []*adminv1.MenuItem{
				{Id: "m-users-list", Name: "All", Path: "/users/list", Permission: "user:read"},
				{Id: "m-users-roles", Name: "Roles", Path: "/users/roles", Permission: "user:role"},
			},
		},
		nil, // nil entries must not panic
	}
	if _, err := c.SetMenus(context.Background(), &adminv1.SetMenusRequest{
		ClientId: "web-app", Menus: tree,
	}); err != nil {
		t.Fatalf("SetMenus: %v", err)
	}

	got, err := prov.GetMenus(context.Background(), "web-app")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	// Nil input items round-trip as zero MenuItem values; the live entry
	// must preserve all of buttons + children.
	if len(got) != 2 {
		t.Fatalf("got %d top-level items, want 2", len(got))
	}
	live := got[0]
	if len(live.Buttons) != 2 || live.Buttons[0].Code != "btn-create" {
		t.Errorf("buttons = %+v", live.Buttons)
	}
	if len(live.Children) != 2 || live.Children[0].ID != "m-users-list" {
		t.Errorf("children = %+v", live.Children)
	}
}
