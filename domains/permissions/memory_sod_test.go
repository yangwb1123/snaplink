package permissions_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// TestMemoryProvider_SetConflictSets_Validation locks the hygiene rule
// shared by SetConflictSets and SetActivationConflictSets: every declared
// set must name two-or-more DISTINCT, non-empty role codes.
func TestMemoryProvider_SetConflictSets_Validation(t *testing.T) {
	m := permissions.NewMemoryProvider()
	ctx := context.Background()
	cases := []struct {
		name    string
		sets    [][]string
		wantErr bool
	}{
		{"nil clears, no error", nil, false},
		{"valid pair", [][]string{{"a", "b"}}, false},
		{"valid triple", [][]string{{"a", "b", "c"}}, false},
		{"single role", [][]string{{"a"}}, true},
		{"duplicate collapses to one distinct code", [][]string{{"a", "a"}}, true},
		{"empty code", [][]string{{"a", ""}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := m.SetConflictSets(ctx, "web", tc.sets)
			if tc.wantErr && !errors.Is(err, permissions.ErrInvalidConflictSet) {
				t.Fatalf("got %v, want ErrInvalidConflictSet", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestMemoryProvider_SetConflictSets_DefensiveCopy proves the stored
// conflict table doesn't alias the caller's slice in either direction:
// mutating the slice passed to SetConflictSets, or the slice returned by
// ConflictSets, must not reach into the Provider's internal state.
func TestMemoryProvider_SetConflictSets_DefensiveCopy(t *testing.T) {
	m := permissions.NewMemoryProvider()
	ctx := context.Background()
	sets := [][]string{{"a", "b"}}
	if err := m.SetConflictSets(ctx, "web", sets); err != nil {
		t.Fatalf("SetConflictSets: %v", err)
	}
	sets[0][0] = "mutated"
	got, _ := m.ConflictSets(ctx, "web")
	if got[0][0] != "a" {
		t.Fatalf("stored conflict set aliased the caller's input slice: %v", got)
	}
	got[0][0] = "also-mutated"
	got2, _ := m.ConflictSets(ctx, "web")
	if got2[0][0] != "a" {
		t.Fatalf("ConflictSets returned an alias into stored state: %v", got2)
	}
}

// TestMemoryProvider_ConflictError_ThreeWaySet locks the multi-way
// collision report: a 3-role conflict set trips on any 2+ of its members
// appearing together, and *ConflictError.Roles reports every offender.
func TestMemoryProvider_ConflictError_ThreeWaySet(t *testing.T) {
	m := permissions.NewMemoryProvider()
	ctx := context.Background()
	for _, code := range []string{"a", "b", "c"} {
		_ = m.AddRole(ctx, "web", permissions.Role{Code: code})
	}
	if err := m.SetConflictSets(ctx, "web", [][]string{{"a", "b", "c"}}); err != nil {
		t.Fatalf("SetConflictSets: %v", err)
	}
	err := m.AssignRoles(ctx, "alice", "web", []string{"a", "b", "c"})
	var cErr *permissions.ConflictError
	if !errors.As(err, &cErr) {
		t.Fatalf("errors.As(*ConflictError) failed for %v", err)
	}
	if len(cErr.Roles) != 3 {
		t.Errorf("ConflictError.Roles = %v, want all 3 codes", cErr.Roles)
	}
}

// TestMemoryProvider_RemoveRole_StripsActiveSessions locks the cleanup
// invariant: removing a role definition also clears it out of any
// session's DSoD activation state, so a later re-added role with the same
// code can't silently reactivate in a stale session.
func TestMemoryProvider_RemoveRole_StripsActiveSessions(t *testing.T) {
	m := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = m.AddRole(ctx, "web", permissions.Role{Code: "viewer"})
	_ = m.AssignRoles(ctx, "alice", "web", []string{"viewer"})
	if err := m.ActivateRoles(ctx, "alice", "web", "sess-1", []string{"viewer"}); err != nil {
		t.Fatalf("ActivateRoles: %v", err)
	}
	if err := m.RemoveRole(ctx, "web", "viewer"); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	active, err := m.ActiveRoles(ctx, "alice", "web", "sess-1")
	if err != nil || len(active) != 0 {
		t.Fatalf("active roles after RemoveRole = %v, %v; want empty", active, err)
	}
}

// TestMemoryProvider_ActivateRoles_ChecksSSoDToo is the defense-in-depth
// regression: SetConflictSets explicitly does NOT retroactively re-validate
// an assignment that predates it (documented gap), but ActivateRoles still
// refuses to activate the conflicting pair because it checks the SSoD
// table too, not just its own DSoD table.
func TestMemoryProvider_ActivateRoles_ChecksSSoDToo(t *testing.T) {
	m := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = m.AddRole(ctx, "web", permissions.Role{Code: "a"})
	_ = m.AddRole(ctx, "web", permissions.Role{Code: "b"})
	if err := m.AssignRoles(ctx, "alice", "web", []string{"a", "b"}); err != nil {
		t.Fatalf("AssignRoles before SSoD declared: %v", err)
	}
	if err := m.SetConflictSets(ctx, "web", [][]string{{"a", "b"}}); err != nil {
		t.Fatalf("SetConflictSets: %v", err)
	}
	err := m.ActivateRoles(ctx, "alice", "web", "sess-1", []string{"a", "b"})
	if !errors.Is(err, permissions.ErrRoleConflict) {
		t.Fatalf("ActivateRoles: got %v, want ErrRoleConflict (SSoD defense-in-depth)", err)
	}
}

// TestMemoryProvider_ActivationConflictSets_IndependentOfSSoD proves the
// two conflict tables are genuinely separate: declaring an SSoD set for a
// pair does not populate ActivationConflictSets, and vice versa.
func TestMemoryProvider_ActivationConflictSets_IndependentOfSSoD(t *testing.T) {
	m := permissions.NewMemoryProvider()
	ctx := context.Background()
	_ = m.SetConflictSets(ctx, "web", [][]string{{"a", "b"}})
	_ = m.SetActivationConflictSets(ctx, "web", [][]string{{"c", "d"}})

	ssod, _ := m.ConflictSets(ctx, "web")
	dsod, _ := m.ActivationConflictSets(ctx, "web")
	if len(ssod) != 1 || ssod[0][0] != "a" {
		t.Errorf("ConflictSets = %v, want [[a b]]", ssod)
	}
	if len(dsod) != 1 || dsod[0][0] != "c" {
		t.Errorf("ActivationConflictSets = %v, want [[c d]]", dsod)
	}
}

// TestMemoryProvider_ActiveRoles_UnknownSession returns an empty slice (not
// an error) for a session that never called ActivateRoles — mirrors the
// "no roles yet" contract documented on SessionRoleActivator.
func TestMemoryProvider_ActiveRoles_UnknownSession(t *testing.T) {
	m := permissions.NewMemoryProvider()
	active, err := m.ActiveRoles(context.Background(), "ghost", "web", "sess-1")
	if err != nil || len(active) != 0 {
		t.Fatalf("ActiveRoles unknown session = %v, %v; want empty, nil", active, err)
	}
}
