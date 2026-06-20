package sqlite_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
	permsqlite "github.com/snaplink/sso/domains/permissions/sqlite"
)

func newTestProvider(t *testing.T) *permsqlite.Provider {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "permissions.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	p, err := permsqlite.New(dsn)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

func TestProvider_RoleRoundtrip(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	role := permissions.Role{
		Code:        "admin",
		Name:        "Administrator",
		Description: "all powers",
		Permissions: []string{"user:*", "order:read", "order:write"},
	}
	if err := p.AddRole(ctx, "web-app", role); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	got, err := p.ListAllRoles(ctx, "web-app")
	if err != nil {
		t.Fatalf("ListAllRoles: %v", err)
	}
	if len(got) != 1 || got[0].Code != "admin" || len(got[0].Permissions) != 3 {
		t.Fatalf("ListAllRoles mismatch: %+v", got)
	}
	if got[0].Permissions[0] != "user:*" {
		t.Errorf("permissions[0] = %v, want user:*", got[0].Permissions[0])
	}
}

func TestProvider_AddRoleDuplicateRejected(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	role := permissions.Role{Code: "viewer", Permissions: []string{"x:read"}}
	if err := p.AddRole(ctx, "web", role); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	err := p.AddRole(ctx, "web", role)
	if !errors.Is(err, permissions.ErrRoleExists) {
		t.Fatalf("got %v, want ErrRoleExists", err)
	}
}

func TestProvider_UpdateRoleRequiresExistence(t *testing.T) {
	p := newTestProvider(t)
	err := p.UpdateRole(context.Background(), "web", permissions.Role{Code: "ghost"})
	if !errors.Is(err, permissions.ErrRoleNotFound) {
		t.Fatalf("got %v, want ErrRoleNotFound", err)
	}
}

func TestProvider_UpdateRoleReplacesFields(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1", Name: "Original", Permissions: []string{"a"}})

	updated := permissions.Role{Code: "r1", Name: "Renamed", Description: "now-with-desc", Permissions: []string{"a", "b"}}
	if err := p.UpdateRole(ctx, "web", updated); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	got, _ := p.ListAllRoles(ctx, "web")
	if got[0].Name != "Renamed" {
		t.Errorf("name = %v, want Renamed", got[0].Name)
	}
	if len(got[0].Permissions) != 2 {
		t.Errorf("permissions = %v, want [a b]", got[0].Permissions)
	}
}

func TestProvider_RemoveRoleStripsAssignments(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "admin", Permissions: []string{"all"}})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer", Permissions: []string{"read"}})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"admin", "viewer"})
	_ = p.AssignRoles(ctx, "bob", "web", []string{"viewer"})

	if err := p.RemoveRole(ctx, "web", "admin"); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	// admin role gone.
	roles, _ := p.ListAllRoles(ctx, "web")
	for _, r := range roles {
		if r.Code == "admin" {
			t.Errorf("admin survived removal: %v", r)
		}
	}
	// alice should still have viewer; bob unchanged.
	aliceRoles, _ := p.Roles(ctx, "alice", "web")
	if len(aliceRoles) != 1 || aliceRoles[0].Code != "viewer" {
		t.Errorf("alice roles after strip: %v", aliceRoles)
	}
	bobRoles, _ := p.Roles(ctx, "bob", "web")
	if len(bobRoles) != 1 || bobRoles[0].Code != "viewer" {
		t.Errorf("bob roles unaffected check: %v", bobRoles)
	}
}

func TestProvider_RemoveRoleMissingErrors(t *testing.T) {
	p := newTestProvider(t)
	err := p.RemoveRole(context.Background(), "web", "ghost")
	if !errors.Is(err, permissions.ErrRoleNotFound) {
		t.Fatalf("got %v, want ErrRoleNotFound", err)
	}
}

func TestProvider_AssignRolesIsSet(t *testing.T) {
	// The Provider.AssignRoles contract is SET (not merge) per
	// memory peer. Verify the sqlite peer holds the same shape.
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r2"})

	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r2"})
	got, _ := p.Roles(ctx, "alice", "web")
	if len(got) != 1 || got[0].Code != "r2" {
		t.Errorf("AssignRoles should SET (not merge); got %v", got)
	}
}

func TestProvider_UnassignRolesIgnoresMissing(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1"})

	// Try to unassign a role she doesn't have — should be a no-op.
	if err := p.UnassignRoles(ctx, "alice", "web", []string{"r2"}); err != nil {
		t.Fatalf("UnassignRoles missing: %v", err)
	}
	got, _ := p.Roles(ctx, "alice", "web")
	if len(got) != 1 || got[0].Code != "r1" {
		t.Errorf("alice roles disturbed by no-op unassign: %v", got)
	}
}

func TestProvider_UnassignRolesNoAssignmentNoOp(t *testing.T) {
	p := newTestProvider(t)
	// No assignment row at all → silent no-op.
	if err := p.UnassignRoles(context.Background(), "alice", "web", []string{"r1"}); err != nil {
		t.Fatalf("UnassignRoles on missing assignment: %v", err)
	}
}

func TestProvider_ListAssignmentsFiltersEmptyRoles(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1"})
	_ = p.AssignRoles(ctx, "bob", "web", []string{}) // empty assignment row

	got, _ := p.ListAssignments(ctx, "web")
	if len(got) != 1 || got[0].UserID != "alice" {
		t.Errorf("ListAssignments should drop empty-roles users; got %v", got)
	}
}

func TestProvider_PermissionsDeduplicates(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1", Permissions: []string{"user:read", "user:write"}})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r2", Permissions: []string{"user:read", "order:read"}})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1", "r2"})

	perms, err := p.Permissions(ctx, "alice", "web")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	codes := make(map[string]bool)
	for _, perm := range perms {
		if codes[perm.Code] {
			t.Errorf("duplicate code in Permissions: %v", perm.Code)
		}
		codes[perm.Code] = true
	}
	wantCodes := []string{"user:read", "user:write", "order:read"}
	for _, want := range wantCodes {
		if !codes[want] {
			t.Errorf("missing permission %v", want)
		}
	}
}

func TestProvider_RolesUnknownUserSentinel(t *testing.T) {
	p := newTestProvider(t)
	_, err := p.Roles(context.Background(), "ghost", "web")
	if !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("got %v, want ErrUserNotFound", err)
	}
}

func TestProvider_MenusSetGetRoundtrip(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	want := permissions.MenuTree{
		{ID: "users", Name: "Users", Path: "/users", Permission: "user:read",
			Buttons: []permissions.Button{{Code: "create", Permission: "user:write"}}},
		{ID: "settings", Name: "Settings", Path: "/settings"}, // no permission gate
	}
	if err := p.SetMenus(ctx, "web", want); err != nil {
		t.Fatalf("SetMenus: %v", err)
	}
	got, err := p.GetMenus(ctx, "web")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != "users" || got[0].Path != "/users" {
		t.Errorf("first menu mismatch: %+v", got[0])
	}
}

func TestProvider_MenusGetMissingReturnsEmpty(t *testing.T) {
	p := newTestProvider(t)
	got, err := p.GetMenus(context.Background(), "web")
	if err != nil {
		t.Fatalf("GetMenus on missing: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("empty client should return empty menu; got %v", got)
	}
}

func TestProvider_MenusFiltersByUserPermissions(t *testing.T) {
	p := newTestProvider(t)
	ctx := context.Background()
	tree := permissions.MenuTree{
		{ID: "users", Name: "Users", Path: "/users", Permission: "user:read",
			Buttons: []permissions.Button{
				{Code: "view", Permission: "user:read"},
				{Code: "edit", Permission: "user:write"},
			},
		},
		{ID: "settings", Name: "Settings", Permission: "admin:*"},
	}
	_ = p.SetMenus(ctx, "web", tree)
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer", Permissions: []string{"user:read"}})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"viewer"})

	filtered, err := p.Menus(ctx, "alice", "web")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	// alice has user:read so she sees Users but not Settings (admin:*
	// not in her grants).
	if len(filtered) != 1 {
		t.Fatalf("filtered count = %d, want 1; got %+v", len(filtered), filtered)
	}
	if filtered[0].ID != "users" {
		t.Errorf("filtered[0] = %v, want users", filtered[0].ID)
	}
	// view button passes; edit button (user:write) is pruned.
	if len(filtered[0].Buttons) != 1 || filtered[0].Buttons[0].Code != "view" {
		t.Errorf("buttons = %+v, want only view", filtered[0].Buttons)
	}
}

func TestProvider_PingAfterCloseErrors(t *testing.T) {
	p := newTestProvider(t)
	_ = p.Close()
	if err := p.Ping(context.Background()); err == nil {
		t.Fatal("Ping after Close: want error")
	}
}
