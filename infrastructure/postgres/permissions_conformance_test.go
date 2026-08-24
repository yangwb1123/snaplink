package postgres

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/permissions/permissionstest"
)

// truncatePermissions wipes the three permissions tables so each conformance
// subtest (which gets a fresh Provider from the Factory) starts clean —
// instances MUST NOT share state, which the suite warns would mask backend
// bugs.
func truncatePermissions(t *testing.T, db interface {
	ExecContext(context.Context, string, ...any) (interface{ RowsAffected() (int64, error) }, error)
}) {
	t.Helper()
}

// freshPermissionProvider returns a PermissionProvider over the shared test DB
// with the three permissions tables truncated.
func freshPermissionProvider(t *testing.T) *PermissionProvider {
	t.Helper()
	p, err := NewPermissionProvider(testConfig(t))
	if err != nil {
		t.Fatalf("NewPermissionProvider: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	if _, err := p.db.ExecContext(context.Background(),
		"TRUNCATE permissions_roles, permissions_assignments, permissions_menus, permissions_conflict_sets, permissions_active_roles"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return p
}

// TestPermissionProvider_Conformance runs the shared Provider conformance suite
// against the Postgres peer. Pinned-in equivalence with the memory + SQLite +
// Redis peers is the whole point — operators swapping backends should see no
// behavior differences. One shared pool is reused across subtests and truncated
// per Factory call, so the integration test needs only a single live DB
// connection.
func TestPermissionProvider_Conformance(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	db, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	permissionstest.ConformanceSuite{
		Factory: func(t *testing.T) permissions.Provider {
			t.Helper()
			p, err := NewPermissionProviderWithDB(db, cfg.Dialect)
			if err != nil {
				t.Fatalf("NewPermissionProviderWithDB: %v", err)
			}
			if _, err := db.ExecContext(context.Background(),
				"TRUNCATE permissions_roles, permissions_assignments, permissions_menus, permissions_conflict_sets, permissions_active_roles"); err != nil {
				t.Fatalf("truncate: %v", err)
			}
			return p
		},
	}.Run(t)
}

// TestPermissionProvider_RemoveRoleStripsAllUsers locks that RemoveRole rips the
// code out of EVERY user's assignment under the client (not just one) — a
// multi-user fan-out must not miss anyone, and a user left with no roles drops
// out of ListAssignments / Roles.
func TestPermissionProvider_RemoveRoleStripsAllUsers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := freshPermissionProvider(t)

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
	// bob held only "admin" — the strip empties his role list, so Roles returns
	// the unknown-user sentinel and ListAssignments prunes the empty row.
	if _, err := p.Roles(ctx, "bob", "web"); err != permissions.ErrUserNotFound {
		t.Errorf("bob Roles after strip = %v, want ErrUserNotFound", err)
	}
	got, _ := p.ListAssignments(ctx, "web")
	if len(got) != 1 || got[0].UserID != "alice" {
		t.Errorf("assignments after strip = %v, want only alice", got)
	}
}
