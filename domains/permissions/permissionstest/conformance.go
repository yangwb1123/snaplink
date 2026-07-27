// Package permissionstest hosts shared test fixtures for
// [permissions.Provider] implementations. Backend authors (memory,
// sqlite, future peers) hook their factory into [ConformanceSuite]
// to lock the equivalence operators rely on — admin RPCs / audit
// trails / login response embed should behave identically whichever
// backend is wired.
//
// Lives in a separate package so the production permissions package
// stays free of the `testing` import.
package permissionstest

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// ConformanceSuite exercises every Provider semantic both backends
// (memory + sqlite + any future peer) MUST agree on.
//
// Each backend test file calls (ConformanceSuite{Factory: f}).Run(t).
// The Factory returns a fresh Provider per subtest — instances MUST
// NOT be shared across subtests (state leakage would mask backend
// bugs).
//
// MenuLister is type-asserted; implementations that don't satisfy
// it cause the menu-listing subtests to skip rather than fail.
type ConformanceSuite struct {
	Factory func(*testing.T) permissions.Provider
}

// Run executes every conformance subtest against the suite's
// Factory.
func (s ConformanceSuite) Run(t *testing.T) {
	t.Helper()
	if s.Factory == nil {
		t.Fatal("ConformanceSuite: Factory required")
	}
	cases := []struct {
		name string
		fn   func(*testing.T, permissions.Provider)
	}{
		{"AddRole_Roundtrip", testAddRoleRoundtrip},
		{"AddRole_DuplicateRejected", testAddRoleDuplicateRejected},
		{"UpdateRole_RequiresExistence", testUpdateRoleRequiresExistence},
		{"UpdateRole_ReplacesFields", testUpdateRoleReplacesFields},
		{"RemoveRole_StripsAssignments", testRemoveRoleStripsAssignments},
		{"RemoveRole_MissingErrors", testRemoveRoleMissingErrors},
		{"AssignRoles_IsSet", testAssignRolesIsSet},
		{"UnassignRoles_IgnoresMissing", testUnassignRolesIgnoresMissing},
		{"UnassignRoles_NoAssignmentNoOp", testUnassignRolesNoAssignmentNoOp},
		{"ListAssignments_FiltersEmptyRoles", testListAssignmentsFiltersEmptyRoles},
		{"Permissions_Deduplicates", testPermissionsDeduplicates},
		{"Roles_UnknownUserSentinel", testRolesUnknownUserSentinel},
		{"Menus_SetGetRoundtrip", testMenusSetGetRoundtrip},
		{"Menus_FiltersByUserPermissions", testMenusFiltersByUserPermissions},
		{"GroupMembership_AddPreservesOthers", testGroupMembershipAddPreservesOthers},
		{"GroupMembership_RemoveIsScoped", testGroupMembershipRemoveIsScoped},
		{"SoD_StaticConflictBlocksAssign", testSoDStaticConflictBlocksAssign},
		{"SoD_StaticConflictAllowsNonConflicting", testSoDStaticConflictAllowsNonConflicting},
		{"SoD_StaticConflictBlocksAddRoleToUser", testSoDStaticConflictBlocksAddRoleToUser},
		{"SoD_ClearingConflictsRestoresDefault", testSoDClearingConflictsRestoresDefault},
		{"SoD_InvalidConflictSetRejected", testSoDInvalidConflictSetRejected},
		{"SoD_DynamicActivateRequiresAssignment", testSoDDynamicActivateRequiresAssignment},
		{"SoD_DynamicActivateBlocksConflict", testSoDDynamicActivateBlocksConflict},
		{"SoD_DynamicHoldBothActivateOne", testSoDDynamicHoldBothActivateOne},
		{"SoD_DynamicActiveRolesScopedPerSession", testSoDDynamicActiveRolesScopedPerSession},
		{"SoD_DynamicDeactivateSessionClears", testSoDDynamicDeactivateSessionClears},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := s.Factory(t)
			tc.fn(t, p)
		})
	}
}

func testAddRoleRoundtrip(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	role := permissions.Role{Code: "admin", Name: "Administrator", Permissions: []string{"user:*", "order:read"}}
	if err := p.AddRole(ctx, "web", role); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	got, _ := p.ListAllRoles(ctx, "web")
	if len(got) != 1 || got[0].Code != "admin" {
		t.Fatalf("ListAllRoles mismatch: %+v", got)
	}
}

func testAddRoleDuplicateRejected(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	role := permissions.Role{Code: "viewer"}
	_ = p.AddRole(ctx, "web", role)
	err := p.AddRole(ctx, "web", role)
	if !errors.Is(err, permissions.ErrRoleExists) {
		t.Fatalf("got %v, want ErrRoleExists", err)
	}
}

func testUpdateRoleRequiresExistence(t *testing.T, p permissions.Provider) {
	err := p.UpdateRole(context.Background(), "web", permissions.Role{Code: "ghost"})
	if !errors.Is(err, permissions.ErrRoleNotFound) {
		t.Fatalf("got %v, want ErrRoleNotFound", err)
	}
}

func testUpdateRoleReplacesFields(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1", Name: "Original"})
	if err := p.UpdateRole(ctx, "web", permissions.Role{Code: "r1", Name: "Renamed"}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	got, _ := p.ListAllRoles(ctx, "web")
	if got[0].Name != "Renamed" {
		t.Errorf("name not updated: %v", got[0].Name)
	}
}

func testRemoveRoleStripsAssignments(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "admin"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"admin", "viewer"})

	if err := p.RemoveRole(ctx, "web", "admin"); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	aliceRoles, _ := p.Roles(ctx, "alice", "web")
	if len(aliceRoles) != 1 || aliceRoles[0].Code != "viewer" {
		t.Errorf("alice roles after strip: %v, want [viewer]", aliceRoles)
	}
}

func testRemoveRoleMissingErrors(t *testing.T, p permissions.Provider) {
	err := p.RemoveRole(context.Background(), "web", "ghost")
	if !errors.Is(err, permissions.ErrRoleNotFound) {
		t.Fatalf("got %v, want ErrRoleNotFound", err)
	}
}

func testAssignRolesIsSet(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r2"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r2"})

	got, _ := p.Roles(ctx, "alice", "web")
	if len(got) != 1 || got[0].Code != "r2" {
		t.Errorf("AssignRoles SET semantics violated: %v", got)
	}
}

func testUnassignRolesIgnoresMissing(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1"})
	if err := p.UnassignRoles(ctx, "alice", "web", []string{"r2"}); err != nil {
		t.Fatalf("UnassignRoles missing: %v", err)
	}
	got, _ := p.Roles(ctx, "alice", "web")
	if len(got) != 1 || got[0].Code != "r1" {
		t.Errorf("no-op unassign disturbed state: %v", got)
	}
}

func testUnassignRolesNoAssignmentNoOp(t *testing.T, p permissions.Provider) {
	if err := p.UnassignRoles(context.Background(), "alice", "web", []string{"r1"}); err != nil {
		t.Fatalf("UnassignRoles on missing assignment: %v", err)
	}
}

func testListAssignmentsFiltersEmptyRoles(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1"})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1"})
	_ = p.AssignRoles(ctx, "bob", "web", []string{})

	got, _ := p.ListAssignments(ctx, "web")
	if len(got) != 1 || got[0].UserID != "alice" {
		t.Errorf("ListAssignments empty-roles filter: %v", got)
	}
}

func testPermissionsDeduplicates(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r1", Permissions: []string{"user:read", "user:write"}})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "r2", Permissions: []string{"user:read", "order:read"}})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"r1", "r2"})

	perms, _ := p.Permissions(ctx, "alice", "web")
	seen := make(map[string]bool)
	for _, perm := range perms {
		if seen[perm.Code] {
			t.Errorf("duplicate code: %v", perm.Code)
		}
		seen[perm.Code] = true
	}
	for _, want := range []string{"user:read", "user:write", "order:read"} {
		if !seen[want] {
			t.Errorf("missing permission %v", want)
		}
	}
}

func testRolesUnknownUserSentinel(t *testing.T, p permissions.Provider) {
	_, err := p.Roles(context.Background(), "ghost", "web")
	if !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("got %v, want ErrUserNotFound", err)
	}
}

func testMenusSetGetRoundtrip(t *testing.T, p permissions.Provider) {
	lister, ok := p.(permissions.MenuLister)
	if !ok {
		t.Skip("provider doesn't implement MenuLister")
	}
	ctx := context.Background()
	want := permissions.MenuTree{{ID: "users", Name: "Users", Path: "/users"}}
	if err := p.SetMenus(ctx, "web", want); err != nil {
		t.Fatalf("SetMenus: %v", err)
	}
	got, err := lister.GetMenus(ctx, "web")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	if len(got) != 1 || got[0].ID != "users" {
		t.Fatalf("GetMenus mismatch: %+v", got)
	}
}

func testMenusFiltersByUserPermissions(t *testing.T, p permissions.Provider) {
	ctx := context.Background()
	tree := permissions.MenuTree{
		{ID: "users", Name: "Users", Permission: "user:read"},
		{ID: "settings", Name: "Settings", Permission: "admin:*"},
	}
	_ = p.SetMenus(ctx, "web", tree)
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer", Permissions: []string{"user:read"}})
	_ = p.AssignRoles(ctx, "alice", "web", []string{"viewer"})

	filtered, err := p.Menus(ctx, "alice", "web")
	if err != nil {
		t.Fatalf("Menus: %v", err)
	}
	if len(filtered) != 1 || filtered[0].ID != "users" {
		t.Errorf("filtered tree: %+v, want only [users]", filtered)
	}
}

// testGroupMembershipAddPreservesOthers locks the optional
// GroupMembershipWriter add semantics SCIM Group membership relies on:
// adding a role leaves the user's other roles intact, and a repeat add is
// idempotent (no duplicate). Skips when the backend doesn't implement the
// extension.
func testGroupMembershipAddPreservesOthers(t *testing.T, p permissions.Provider) {
	w, ok := p.(permissions.GroupMembershipWriter)
	if !ok {
		t.Skip("provider doesn't implement GroupMembershipWriter")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "a"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "b"})
	if err := p.AssignRoles(ctx, "u", "web", []string{"a"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := w.AddRoleToUser(ctx, "u", "web", "b"); err != nil {
		t.Fatalf("AddRoleToUser: %v", err)
	}
	// Idempotent: a second add must not duplicate.
	if err := w.AddRoleToUser(ctx, "u", "web", "b"); err != nil {
		t.Fatalf("AddRoleToUser (repeat): %v", err)
	}
	codes := assignedCodes(t, p, "u", "web")
	if len(codes) != 2 || !codes["a"] || !codes["b"] {
		t.Fatalf("after add, assigned = %v, want {a,b}", codes)
	}
}

// testGroupMembershipRemoveIsScoped locks the remove semantics: removing
// one role leaves the rest, and removing an unheld role is a no-op.
func testGroupMembershipRemoveIsScoped(t *testing.T, p permissions.Provider) {
	w, ok := p.(permissions.GroupMembershipWriter)
	if !ok {
		t.Skip("provider doesn't implement GroupMembershipWriter")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "a"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "b"})
	if err := p.AssignRoles(ctx, "u", "web", []string{"a", "b"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := w.RemoveRoleFromUser(ctx, "u", "web", "a"); err != nil {
		t.Fatalf("RemoveRoleFromUser: %v", err)
	}
	// Idempotent: removing an unheld role is a no-op, not an error.
	if err := w.RemoveRoleFromUser(ctx, "u", "web", "a"); err != nil {
		t.Fatalf("RemoveRoleFromUser (repeat): %v", err)
	}
	codes := assignedCodes(t, p, "u", "web")
	if len(codes) != 1 || !codes["b"] {
		t.Fatalf("after remove, assigned = %v, want {b}", codes)
	}
}

// assignedCodes returns the set of role codes assigned to userID under
// clientID. Treats ErrUserNotFound (no roles) as the empty set.
func assignedCodes(t *testing.T, p permissions.Provider, userID, clientID string) map[string]bool {
	t.Helper()
	roles, err := p.Roles(context.Background(), userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		t.Fatalf("Roles: %v", err)
	}
	out := make(map[string]bool, len(roles))
	for _, r := range roles {
		out[r.Code] = true
	}
	return out
}
