package permissions_test

import (
	"context"
	"errors"
	"slices"
	"sort"
	"testing"

	"github.com/snaplink/sso/permissions"
)

// fixture builds a MemoryProvider with two apps and three role assignments,
// mirroring the shape used by the example config.
func fixture(t *testing.T) *permissions.MemoryProvider {
	t.Helper()
	p := permissions.NewMemoryProvider()

	// web-app
	p.AddRole("web-app", permissions.Role{
		Code:        "admin",
		Permissions: []string{"user:*", "order:*", "audit:read"},
	})
	p.AddRole("web-app", permissions.Role{
		Code:        "viewer",
		Permissions: []string{"user:read", "order:read"},
	})
	p.SetMenus("web-app", permissions.MenuTree{
		{
			ID: "m-users", Name: "Users", Permission: "user:read",
			Buttons: []permissions.Button{
				{Code: "btn-create", Permission: "user:create"},
				{Code: "btn-delete", Permission: "user:delete"},
			},
		},
		{
			ID: "m-orders", Name: "Orders", Permission: "order:read",
			Children: []permissions.MenuItem{
				{ID: "m-orders-list", Name: "All", Permission: "order:read"},
				{ID: "m-orders-refund", Name: "Refunds", Permission: "order:refund"},
			},
		},
		{
			ID: "m-audit", Name: "Audit", Permission: "audit:read",
		},
		{
			ID: "m-public", Name: "Help", // no permission gate -> always visible
		},
	})

	// mobile-app
	p.AddRole("mobile-app", permissions.Role{
		Code:        "user",
		Permissions: []string{"profile:read", "order:read"},
	})
	p.SetMenus("mobile-app", permissions.MenuTree{
		{ID: "m-profile", Name: "Profile", Permission: "profile:read"},
		{ID: "m-orders", Name: "Orders", Permission: "order:read"},
	})

	p.AssignRoles("user-alice", "web-app", []string{"admin"})
	p.AssignRoles("user-bob", "web-app", []string{"viewer"})
	p.AssignRoles("user-alice", "mobile-app", []string{"user"})

	return p
}

func TestRoles_ReturnsAssignedRoles(t *testing.T) {
	p := fixture(t)
	roles, err := p.Roles(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(roles) != 1 || roles[0].Code != "admin" {
		t.Fatalf("expected [admin], got %v", roles)
	}
}

func TestRoles_UnknownUserReturnsErrUserNotFound(t *testing.T) {
	p := fixture(t)
	_, err := p.Roles(context.Background(), "ghost", "web-app")
	if !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestRoles_PerClientIsolation(t *testing.T) {
	p := fixture(t)
	web, err := p.Roles(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("web Roles: %v", err)
	}
	mobile, err := p.Roles(context.Background(), "user-alice", "mobile-app")
	if err != nil {
		t.Fatalf("mobile Roles: %v", err)
	}
	if web[0].Code == mobile[0].Code {
		t.Fatalf("expected distinct roles per client, got %q / %q", web[0].Code, mobile[0].Code)
	}
}

func TestRoles_UnknownRoleCodeSkipped(t *testing.T) {
	// Assigning a role code that isn't defined on the client should not panic;
	// it just silently drops out of the result.
	p := permissions.NewMemoryProvider()
	p.AddRole("c", permissions.Role{Code: "real", Permissions: []string{"x"}})
	p.AssignRoles("u", "c", []string{"real", "ghost"})

	roles, err := p.Roles(context.Background(), "u", "c")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(roles) != 1 || roles[0].Code != "real" {
		t.Fatalf("expected [real], got %v", roles)
	}
}

func TestPermissions_UnionsAndDeduplicates(t *testing.T) {
	p := permissions.NewMemoryProvider()
	p.AddRole("c", permissions.Role{Code: "r1", Permissions: []string{"a", "b"}})
	p.AddRole("c", permissions.Role{Code: "r2", Permissions: []string{"b", "c"}})
	p.AssignRoles("u", "c", []string{"r1", "r2"})

	perms, err := p.Permissions(context.Background(), "u", "c")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	got := codes(perms)
	sort.Strings(got)
	want := []string{"a", "b", "c"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestPermissions_UnknownUser(t *testing.T) {
	p := fixture(t)
	_, err := p.Permissions(context.Background(), "ghost", "web-app")
	if !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound, got %v", err)
	}
}

func TestMenus_AdminSeesEverything(t *testing.T) {
	p := fixture(t)
	tree, err := p.Menus(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	ids := menuIDs(tree)
	for _, want := range []string{"m-users", "m-orders", "m-audit", "m-public"} {
		if !slices.Contains(ids, want) {
			t.Errorf("admin should see %q; tree IDs = %v", want, ids)
		}
	}

	// Order children: admin (order:*) sees both list and refund.
	orders := findItem(tree, "m-orders")
	childIDs := menuIDs(orders.Children)
	for _, want := range []string{"m-orders-list", "m-orders-refund"} {
		if !slices.Contains(childIDs, want) {
			t.Errorf("admin should see order child %q; got %v", want, childIDs)
		}
	}

	// Admin has user:* so both buttons survive.
	users := findItem(tree, "m-users")
	btnCodes := buttonCodes(users.Buttons)
	for _, want := range []string{"btn-create", "btn-delete"} {
		if !slices.Contains(btnCodes, want) {
			t.Errorf("admin should see button %q; got %v", want, btnCodes)
		}
	}
}

func TestMenus_ViewerLosesGatedNodesButKeepsPublic(t *testing.T) {
	p := fixture(t)
	tree, err := p.Menus(context.Background(), "user-bob", "web-app")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	ids := menuIDs(tree)

	// Viewer has user:read + order:read → user, orders, public stay.
	if !slices.Contains(ids, "m-users") {
		t.Errorf("viewer should keep m-users")
	}
	if !slices.Contains(ids, "m-orders") {
		t.Errorf("viewer should keep m-orders")
	}
	if !slices.Contains(ids, "m-public") {
		t.Errorf("viewer should keep ungated m-public")
	}
	// audit:read missing → m-audit pruned.
	if slices.Contains(ids, "m-audit") {
		t.Errorf("viewer should NOT see m-audit")
	}

	// Inside orders: viewer has order:read but not order:refund.
	orders := findItem(tree, "m-orders")
	childIDs := menuIDs(orders.Children)
	if !slices.Contains(childIDs, "m-orders-list") {
		t.Errorf("viewer should keep m-orders-list")
	}
	if slices.Contains(childIDs, "m-orders-refund") {
		t.Errorf("viewer should NOT see m-orders-refund")
	}

	// Buttons gated by user:create / user:delete must be filtered out
	// (viewer only has user:read).
	users := findItem(tree, "m-users")
	if len(users.Buttons) != 0 {
		t.Errorf("viewer should have no user buttons; got %v", buttonCodes(users.Buttons))
	}
}

func TestMenus_ParentKeptWhenChildrenSurvive(t *testing.T) {
	// Parent has a permission the user doesn't hold, but a child the user CAN
	// see. The current implementation keeps the parent so the surviving child
	// remains reachable.
	p := permissions.NewMemoryProvider()
	p.AddRole("c", permissions.Role{Code: "r", Permissions: []string{"section:open"}})
	p.AssignRoles("u", "c", []string{"r"})
	p.SetMenus("c", permissions.MenuTree{
		{
			ID: "parent", Permission: "section:admin", // not held
			Children: []permissions.MenuItem{
				{ID: "child", Permission: "section:open"}, // held
			},
		},
	})

	tree, err := p.Menus(context.Background(), "u", "c")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	if len(tree) != 1 || tree[0].ID != "parent" {
		t.Fatalf("expected parent kept; got %v", menuIDs(tree))
	}
	if len(tree[0].Children) != 1 || tree[0].Children[0].ID != "child" {
		t.Fatalf("expected child kept; got %v", menuIDs(tree[0].Children))
	}
}

func TestMenus_ParentPrunedWhenAllChildrenFiltered(t *testing.T) {
	p := permissions.NewMemoryProvider()
	p.AddRole("c", permissions.Role{Code: "r", Permissions: []string{"unrelated:perm"}})
	p.AssignRoles("u", "c", []string{"r"})
	p.SetMenus("c", permissions.MenuTree{
		{
			ID: "parent", Permission: "section:admin",
			Children: []permissions.MenuItem{
				{ID: "child", Permission: "section:open"},
			},
		},
	})

	tree, err := p.Menus(context.Background(), "u", "c")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	if len(tree) != 0 {
		t.Fatalf("expected fully-pruned tree; got %v", menuIDs(tree))
	}
}

func TestMenus_UnknownUserReturnsEmptyNotError(t *testing.T) {
	// A user with no role assignments shouldn't error out the UI — the menu
	// just becomes empty (after public/no-gate items are filtered through).
	p := fixture(t)
	tree, err := p.Menus(context.Background(), "ghost", "web-app")
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if len(tree) != 0 {
		// Note: the current impl returns empty when Permissions errors, even
		// if ungated public items exist. Lock this in.
		t.Fatalf("expected empty tree for unknown user, got %v", menuIDs(tree))
	}
}

func TestMenus_NoMenusConfiguredReturnsEmpty(t *testing.T) {
	p := permissions.NewMemoryProvider()
	p.AddRole("c", permissions.Role{Code: "r", Permissions: []string{"x"}})
	p.AssignRoles("u", "c", []string{"r"})

	tree, err := p.Menus(context.Background(), "u", "c")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	if len(tree) != 0 {
		t.Fatalf("expected empty tree, got %v", menuIDs(tree))
	}
}

func TestMenus_WildcardPermissionGrantsEverything(t *testing.T) {
	p := permissions.NewMemoryProvider()
	p.AddRole("c", permissions.Role{Code: "god", Permissions: []string{"*"}})
	p.AssignRoles("u", "c", []string{"god"})
	p.SetMenus("c", permissions.MenuTree{
		{ID: "a", Permission: "anything:x"},
		{ID: "b", Permission: "ping"},
		{ID: "c", Permission: "deep:nested:perm"},
	})

	tree, err := p.Menus(context.Background(), "u", "c")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	if got := menuIDs(tree); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("god role should see everything, got %v", got)
	}
}

func TestPermissionsAndRoles_AssignmentIsCopied(t *testing.T) {
	// AssignRoles should defensively copy the slice — mutating the caller's
	// slice afterward must not leak into the provider's state.
	p := permissions.NewMemoryProvider()
	p.AddRole("c", permissions.Role{Code: "r", Permissions: []string{"x"}})
	roles := []string{"r"}
	p.AssignRoles("u", "c", roles)

	roles[0] = "ghost"

	got, err := p.Roles(context.Background(), "u", "c")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(got) != 1 || got[0].Code != "r" {
		t.Fatalf("expected provider state to be insulated from caller mutation; got %v", got)
	}
}

// --- helpers ---

func codes(perms []permissions.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, p.Code)
	}
	return out
}

func menuIDs(tree permissions.MenuTree) []string {
	out := make([]string, 0, len(tree))
	for _, m := range tree {
		out = append(out, m.ID)
	}
	return out
}

func buttonCodes(btns []permissions.Button) []string {
	out := make([]string, 0, len(btns))
	for _, b := range btns {
		out = append(out, b.Code)
	}
	return out
}

func findItem(tree permissions.MenuTree, id string) permissions.MenuItem {
	for _, m := range tree {
		if m.ID == id {
			return m
		}
	}
	return permissions.MenuItem{}
}
