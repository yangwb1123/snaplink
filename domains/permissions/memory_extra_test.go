package permissions_test

import (
	"context"
	"slices"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
)

// TestGetMenus_NilForUnknownClientReturnsEmpty exercises the
// no-menus-configured branch of GetMenus (the raw, unfiltered exporter
// path used by snapshots) — it must hand back an empty, non-nil tree
// rather than nil so the snapshot encoder doesn't trip on a null.
func TestGetMenus_NilForUnknownClientReturnsEmpty(t *testing.T) {
	p := permissions.NewMemoryProvider()
	tree, err := p.GetMenus(context.Background(), "no-such-client")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	if tree == nil {
		t.Fatalf("expected non-nil empty MenuTree")
	}
	if len(tree) != 0 {
		t.Fatalf("expected empty tree, got %v", tree)
	}
}

func TestGetMenus_ReturnsCopy(t *testing.T) {
	// GetMenus must defensively copy so a caller mutating the returned
	// slice can't corrupt the provider's stored tree.
	p := permissions.NewMemoryProvider()
	_ = p.SetMenus(context.Background(), "c", permissions.MenuTree{
		{ID: "a", Name: "A"},
	})
	got, err := p.GetMenus(context.Background(), "c")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	got[0].ID = "tampered"

	again, _ := p.GetMenus(context.Background(), "c")
	if again[0].ID != "a" {
		t.Fatalf("provider state mutated through returned slice: %v", again)
	}
}

func TestUnassignRoles_NoAssignmentsIsNoOp(t *testing.T) {
	// User has never been assigned anything → byClient nil branch.
	p := permissions.NewMemoryProvider()
	if err := p.UnassignRoles(context.Background(), "ghost", "c", []string{"r"}); err != nil {
		t.Fatalf("UnassignRoles on unknown user: %v", err)
	}
}

func TestUnassignRoles_EmptyClientListIsNoOp(t *testing.T) {
	// User has assignments under a DIFFERENT client, so byClient is
	// non-nil but the requested client's list is empty → len(cur)==0 branch.
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(context.Background(), "other", permissions.Role{Code: "r", Permissions: []string{"x"}})
	_ = p.AssignRoles(context.Background(), "u", "other", []string{"r"})

	if err := p.UnassignRoles(context.Background(), "u", "empty-client", []string{"r"}); err != nil {
		t.Fatalf("UnassignRoles: %v", err)
	}
	// The user's "other" client roles must be untouched.
	roles, err := p.Roles(context.Background(), "u", "other")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(roles) != 1 || roles[0].Code != "r" {
		t.Fatalf("unrelated client roles disturbed: %v", roles)
	}
}

func TestUnassignRoles_RemovesRequestedCodes(t *testing.T) {
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "a", Permissions: []string{"x"}})
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "b", Permissions: []string{"y"}})
	_ = p.AssignRoles(context.Background(), "u", "c", []string{"a", "b"})

	if err := p.UnassignRoles(context.Background(), "u", "c", []string{"a"}); err != nil {
		t.Fatalf("UnassignRoles: %v", err)
	}
	roles, _ := p.Roles(context.Background(), "u", "c")
	if len(roles) != 1 || roles[0].Code != "b" {
		t.Fatalf("expected only [b] left, got %v", roles)
	}
}

func TestAddRoleToUser_FirstAssignmentCreatesMap(t *testing.T) {
	// User has no prior assignment map → the assignmentsByUser[userID]==nil
	// initialization branch runs.
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "r", Permissions: []string{"x"}})

	if err := p.AddRoleToUser(context.Background(), "fresh", "c", "r"); err != nil {
		t.Fatalf("AddRoleToUser: %v", err)
	}
	roles, err := p.Roles(context.Background(), "fresh", "c")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if len(roles) != 1 || roles[0].Code != "r" {
		t.Fatalf("expected [r], got %v", roles)
	}
}

func TestAddRoleToUser_IdempotentWhenAlreadyHeld(t *testing.T) {
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "r", Permissions: []string{"x"}})
	_ = p.AssignRoles(context.Background(), "u", "c", []string{"r"})

	if err := p.AddRoleToUser(context.Background(), "u", "c", "r"); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	roles, _ := p.Roles(context.Background(), "u", "c")
	if len(roles) != 1 {
		t.Fatalf("re-adding a held role should be a no-op, got %v", roles)
	}
}

func TestAddRoleToUser_PreservesExistingRoles(t *testing.T) {
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "a", Permissions: []string{"x"}})
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "b", Permissions: []string{"y"}})
	_ = p.AssignRoles(context.Background(), "u", "c", []string{"a"})

	if err := p.AddRoleToUser(context.Background(), "u", "c", "b"); err != nil {
		t.Fatalf("AddRoleToUser: %v", err)
	}
	roles, _ := p.Roles(context.Background(), "u", "c")
	got := make([]string, 0, len(roles))
	for _, r := range roles {
		got = append(got, r.Code)
	}
	slices.Sort(got)
	if !slices.Equal(got, []string{"a", "b"}) {
		t.Fatalf("expected [a b], got %v", got)
	}
}

func TestRemoveRoleFromUser_NoAssignmentsIsNoOp(t *testing.T) {
	// byClient nil branch.
	p := permissions.NewMemoryProvider()
	if err := p.RemoveRoleFromUser(context.Background(), "ghost", "c", "r"); err != nil {
		t.Fatalf("RemoveRoleFromUser on unknown user: %v", err)
	}
}

func TestRemoveRoleFromUser_EmptyClientListIsNoOp(t *testing.T) {
	// byClient non-nil (assignment under another client), requested
	// client's list empty → len(cur)==0 branch.
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(context.Background(), "other", permissions.Role{Code: "r", Permissions: []string{"x"}})
	_ = p.AssignRoles(context.Background(), "u", "other", []string{"r"})

	if err := p.RemoveRoleFromUser(context.Background(), "u", "empty-client", "r"); err != nil {
		t.Fatalf("RemoveRoleFromUser: %v", err)
	}
	roles, _ := p.Roles(context.Background(), "u", "other")
	if len(roles) != 1 {
		t.Fatalf("unrelated client roles disturbed: %v", roles)
	}
}

func TestRemoveRoleFromUser_RevokesAndLeavesOthers(t *testing.T) {
	p := permissions.NewMemoryProvider()
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "a", Permissions: []string{"x"}})
	_ = p.AddRole(context.Background(), "c", permissions.Role{Code: "b", Permissions: []string{"y"}})
	_ = p.AssignRoles(context.Background(), "u", "c", []string{"a", "b"})

	if err := p.RemoveRoleFromUser(context.Background(), "u", "c", "a"); err != nil {
		t.Fatalf("RemoveRoleFromUser: %v", err)
	}
	roles, _ := p.Roles(context.Background(), "u", "c")
	if len(roles) != 1 || roles[0].Code != "b" {
		t.Fatalf("expected only [b] left, got %v", roles)
	}
}

func TestRemoveRole_StripsCodeFromEveryAssignment(t *testing.T) {
	// RemoveRole must rip the role out of EVERY user's assignment list
	// under that client (the §4 "detach from assignments" invariant), not
	// just delete the definition.
	p := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = p.AddRole(ctx, "c", permissions.Role{Code: "doomed", Permissions: []string{"x"}})
	_ = p.AddRole(ctx, "c", permissions.Role{Code: "keep", Permissions: []string{"y"}})
	_ = p.AssignRoles(ctx, "alice", "c", []string{"doomed", "keep"})
	_ = p.AssignRoles(ctx, "bob", "c", []string{"doomed"})
	// A user assigned the role under a DIFFERENT client must NOT be touched.
	_ = p.AddRole(ctx, "other", permissions.Role{Code: "doomed", Permissions: []string{"z"}})
	_ = p.AssignRoles(ctx, "carol", "other", []string{"doomed"})

	if err := p.RemoveRole(ctx, "c", "doomed"); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}

	// alice keeps only "keep".
	aliceRoles, _ := p.Roles(ctx, "alice", "c")
	if len(aliceRoles) != 1 || aliceRoles[0].Code != "keep" {
		t.Fatalf("alice should keep only [keep], got %v", aliceRoles)
	}
	// bob now has no roles under c.
	if _, err := p.Roles(ctx, "bob", "c"); err == nil {
		t.Fatalf("bob should have no roles after his only role was removed")
	}
	// carol's cross-client assignment survives.
	carolRoles, err := p.Roles(ctx, "carol", "other")
	if err != nil || len(carolRoles) != 1 || carolRoles[0].Code != "doomed" {
		t.Fatalf("carol's cross-client role wrongly stripped: %v / %v", carolRoles, err)
	}
}
