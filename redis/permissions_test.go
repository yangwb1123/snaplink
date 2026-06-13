package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/permissions/permissionstest"
)

// TestPermissionProvider_Conformance runs the shared Provider conformance
// suite against the Redis peer. Pinned-in equivalence with the memory +
// SQLite peers (see permissions/memory_conformance_test.go and
// permissions/sqlite/sqlite_conformance_test.go) is the whole point —
// operators swapping backends should see no behavior differences.
//
// A fresh miniredis fake is spun up per Factory call so subtests never share
// state (state leakage would mask backend bugs, which the suite warns about).
func TestPermissionProvider_Conformance(t *testing.T) {
	permissionstest.ConformanceSuite{
		Factory: func(t *testing.T) permissions.Provider {
			t.Helper()
			_, rdb := newTestClient(t)
			return NewPermissionProvider(rdb)
		},
	}.Run(t)
}

// TestPermissionProvider_EmptyAssignClearsRow locks the Redis-specific index
// bookkeeping the conformance suite only exercises indirectly: assigning an
// empty set after a real assignment must drop the user out of
// ListAssignments (the empty-roles filter) AND make Roles return the
// unknown-user sentinel — the assignment row + the users index entry are both
// cleared.
func TestPermissionProvider_EmptyAssignClearsRow(t *testing.T) {
	ctx := context.Background()
	_, rdb := newTestClient(t)
	p := NewPermissionProvider(rdb)

	if err := p.AddRole(ctx, "web", permissions.Role{Code: "r1"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"r1"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := p.AssignRoles(ctx, "alice", "web", nil); err != nil {
		t.Fatalf("AssignRoles clear: %v", err)
	}
	got, err := p.ListAssignments(ctx, "web")
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("after clear, assignments = %v, want none", got)
	}
	if _, err := p.Roles(ctx, "alice", "web"); !errors.Is(err, permissions.ErrUserNotFound) {
		t.Errorf("Roles after clear = %v, want ErrUserNotFound", err)
	}
}

// TestPermissionProvider_UnassignEmptiesIndex locks that unassigning the last
// role leaves the user out of ListAssignments — the emptied assignment SET is
// deleted and the users index pruned, matching the memory + SQLite peers.
func TestPermissionProvider_UnassignEmptiesIndex(t *testing.T) {
	ctx := context.Background()
	_, rdb := newTestClient(t)
	p := NewPermissionProvider(rdb)

	if err := p.AddRole(ctx, "web", permissions.Role{Code: "r1"}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"r1"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := p.UnassignRoles(ctx, "alice", "web", []string{"r1"}); err != nil {
		t.Fatalf("UnassignRoles: %v", err)
	}
	got, err := p.ListAssignments(ctx, "web")
	if err != nil {
		t.Fatalf("ListAssignments: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("after unassign-last, assignments = %v, want none", got)
	}
}

// TestPermissionProvider_RemoveRoleStripsAllUsers locks that RemoveRole rips
// the code out of EVERY user's assignment under the client (not just one) —
// the per-user index drives the strip, so a multi-user fan-out must not miss
// anyone.
func TestPermissionProvider_RemoveRoleStripsAllUsers(t *testing.T) {
	ctx := context.Background()
	_, rdb := newTestClient(t)
	p := NewPermissionProvider(rdb)

	for _, code := range []string{"admin", "viewer"} {
		if err := p.AddRole(ctx, "web", permissions.Role{Code: code}); err != nil {
			t.Fatalf("AddRole %s: %v", code, err)
		}
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"admin", "viewer"}); err != nil {
		t.Fatalf("AssignRoles alice: %v", err)
	}
	if err := p.AssignRoles(ctx, "bob", "web", []string{"admin"}); err != nil {
		t.Fatalf("AssignRoles bob: %v", err)
	}
	if err := p.RemoveRole(ctx, "web", "admin"); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}

	aliceRoles, _ := p.Roles(ctx, "alice", "web")
	if len(aliceRoles) != 1 || aliceRoles[0].Code != "viewer" {
		t.Errorf("alice roles after strip = %v, want [viewer]", aliceRoles)
	}
	// bob held only "admin" — the strip empties his row, so he drops out of
	// ListAssignments and Roles returns the unknown-user sentinel.
	if _, err := p.Roles(ctx, "bob", "web"); !errors.Is(err, permissions.ErrUserNotFound) {
		t.Errorf("bob Roles after strip = %v, want ErrUserNotFound", err)
	}
	got, _ := p.ListAssignments(ctx, "web")
	if len(got) != 1 || got[0].UserID != "alice" {
		t.Errorf("assignments after strip = %v, want only alice", got)
	}
}
