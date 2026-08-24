package permissionstest

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// Separation of Duty (SoD) subtests. SoDProvider (SSoD) and
// SessionRoleActivator (DSoD) are OPTIONAL Provider extensions (same
// type-assert-and-skip pattern as MenuLister / GroupMembershipWriter
// above): a backend that doesn't implement them skips these subtests
// entirely rather than failing, so redis/postgres/sqlite peers that
// haven't grown SoD support yet keep passing this suite unmodified.

// testSoDStaticConflictBlocksAssign locks the SSoD contract: AssignRoles
// rejects a set that holds two roles from the same declared conflict set,
// and the rejection leaves no partial assignment behind.
func testSoDStaticConflictBlocksAssign(t *testing.T, p permissions.Provider) {
	sod, ok := p.(permissions.SoDProvider)
	if !ok {
		t.Skip("provider doesn't implement SoDProvider")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "approver"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "requester"})
	if err := sod.SetConflictSets(ctx, "web", [][]string{{"approver", "requester"}}); err != nil {
		t.Fatalf("SetConflictSets: %v", err)
	}
	err := p.AssignRoles(ctx, "alice", "web", []string{"approver", "requester"})
	if !errors.Is(err, permissions.ErrRoleConflict) {
		t.Fatalf("AssignRoles conflicting set: got %v, want ErrRoleConflict", err)
	}
	var cErr *permissions.ConflictError
	if !errors.As(err, &cErr) {
		t.Fatalf("errors.As(*ConflictError) failed for %v", err)
	}
	if len(cErr.Roles) != 2 {
		t.Errorf("ConflictError.Roles = %v, want both codes", cErr.Roles)
	}
	if _, err := p.Roles(ctx, "alice", "web"); !errors.Is(err, permissions.ErrUserNotFound) {
		t.Errorf("rejected AssignRoles left a partial assignment: %v", err)
	}
}

// testSoDStaticConflictAllowsNonConflicting proves a declared conflict set
// only blocks the specific combination — assigning one of the two roles
// (or an unrelated role alongside one of them) still succeeds.
func testSoDStaticConflictAllowsNonConflicting(t *testing.T, p permissions.Provider) {
	sod, ok := p.(permissions.SoDProvider)
	if !ok {
		t.Skip("provider doesn't implement SoDProvider")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "approver"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "requester"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer"})
	if err := sod.SetConflictSets(ctx, "web", [][]string{{"approver", "requester"}}); err != nil {
		t.Fatalf("SetConflictSets: %v", err)
	}
	if err := p.AssignRoles(ctx, "bob", "web", []string{"approver", "viewer"}); err != nil {
		t.Fatalf("AssignRoles non-conflicting: %v", err)
	}
	got, _ := p.Roles(ctx, "bob", "web")
	if len(got) != 2 {
		t.Errorf("Roles after non-conflicting assign: %v", got)
	}
}

// testSoDStaticConflictBlocksAddRoleToUser locks the same SSoD enforcement
// through the GroupMembershipWriter delta path (SCIM add-member), not just
// the whole-set AssignRoles path.
func testSoDStaticConflictBlocksAddRoleToUser(t *testing.T, p permissions.Provider) {
	sod, ok := p.(permissions.SoDProvider)
	if !ok {
		t.Skip("provider doesn't implement SoDProvider")
	}
	w, ok := p.(permissions.GroupMembershipWriter)
	if !ok {
		t.Skip("provider doesn't implement GroupMembershipWriter")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "approver"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "requester"})
	_ = sod.SetConflictSets(ctx, "web", [][]string{{"approver", "requester"}})
	if err := p.AssignRoles(ctx, "carol", "web", []string{"approver"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	err := w.AddRoleToUser(ctx, "carol", "web", "requester")
	if !errors.Is(err, permissions.ErrRoleConflict) {
		t.Fatalf("AddRoleToUser conflicting: got %v, want ErrRoleConflict", err)
	}
	got, _ := p.Roles(ctx, "carol", "web")
	if len(got) != 1 || got[0].Code != "approver" {
		t.Errorf("rejected AddRoleToUser disturbed state: %v", got)
	}
}

// testSoDClearingConflictsRestoresDefault is the additivity guarantee: a
// Provider with SetConflictSets(nil) — the default, unconfigured state —
// enforces nothing, matching pre-SoD AssignRoles behavior exactly.
func testSoDClearingConflictsRestoresDefault(t *testing.T, p permissions.Provider) {
	sod, ok := p.(permissions.SoDProvider)
	if !ok {
		t.Skip("provider doesn't implement SoDProvider")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "a"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "b"})
	_ = sod.SetConflictSets(ctx, "web", [][]string{{"a", "b"}})
	if err := p.AssignRoles(ctx, "dave", "web", []string{"a", "b"}); err == nil {
		t.Fatalf("expected conflict before clearing")
	}
	if err := sod.SetConflictSets(ctx, "web", nil); err != nil {
		t.Fatalf("SetConflictSets clear: %v", err)
	}
	sets, err := sod.ConflictSets(ctx, "web")
	if err != nil || len(sets) != 0 {
		t.Fatalf("ConflictSets after clear = %v, %v; want empty", sets, err)
	}
	if err := p.AssignRoles(ctx, "dave", "web", []string{"a", "b"}); err != nil {
		t.Fatalf("AssignRoles after clearing conflicts (additive default): %v", err)
	}
}

// testSoDInvalidConflictSetRejected locks the hygiene check: a set naming
// only one distinct role code isn't a constraint and is rejected outright.
func testSoDInvalidConflictSetRejected(t *testing.T, p permissions.Provider) {
	sod, ok := p.(permissions.SoDProvider)
	if !ok {
		t.Skip("provider doesn't implement SoDProvider")
	}
	err := sod.SetConflictSets(context.Background(), "web", [][]string{{"solo"}})
	if !errors.Is(err, permissions.ErrInvalidConflictSet) {
		t.Fatalf("SetConflictSets(single-role set): got %v, want ErrInvalidConflictSet", err)
	}
}

// testSoDDynamicActivateRequiresAssignment locks the DSoD guardrail: a
// session can only activate roles the subject actually holds.
func testSoDDynamicActivateRequiresAssignment(t *testing.T, p permissions.Provider) {
	act, ok := p.(permissions.SessionRoleActivator)
	if !ok {
		t.Skip("provider doesn't implement SessionRoleActivator")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer"})
	_ = p.AssignRoles(ctx, "erin", "web", []string{"viewer"})
	err := act.ActivateRoles(ctx, "erin", "web", "sess-1", []string{"editor"})
	if !errors.Is(err, permissions.ErrRoleNotAssigned) {
		t.Fatalf("ActivateRoles unassigned role: got %v, want ErrRoleNotAssigned", err)
	}
}

// testSoDDynamicActivateBlocksConflict locks DSoD's own declaration table:
// activating two roles from a declared DSoD set is rejected even though
// both are legitimately held.
func testSoDDynamicActivateBlocksConflict(t *testing.T, p permissions.Provider) {
	act, ok := p.(permissions.SessionRoleActivator)
	if !ok {
		t.Skip("provider doesn't implement SessionRoleActivator")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "approver"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "requester"})
	_ = p.AssignRoles(ctx, "frank", "web", []string{"approver", "requester"})
	if err := act.SetActivationConflictSets(ctx, "web", [][]string{{"approver", "requester"}}); err != nil {
		t.Fatalf("SetActivationConflictSets: %v", err)
	}
	err := act.ActivateRoles(ctx, "frank", "web", "sess-1", []string{"approver", "requester"})
	if !errors.Is(err, permissions.ErrRoleConflict) {
		t.Fatalf("ActivateRoles conflicting: got %v, want ErrRoleConflict", err)
	}
}

// testSoDDynamicHoldBothActivateOne is the headline DSoD scenario: a
// subject legitimately HOLDS two mutually-exclusive-to-activate roles
// (AssignRoles succeeds — DSoD is a table independent of SSoD), and one
// session activates only a non-conflicting subset of one.
func testSoDDynamicHoldBothActivateOne(t *testing.T, p permissions.Provider) {
	act, ok := p.(permissions.SessionRoleActivator)
	if !ok {
		t.Skip("provider doesn't implement SessionRoleActivator")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "approver"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "requester"})
	if err := p.AssignRoles(ctx, "grace", "web", []string{"approver", "requester"}); err != nil {
		t.Fatalf("AssignRoles (DSoD allows holding both): %v", err)
	}
	if err := act.SetActivationConflictSets(ctx, "web", [][]string{{"approver", "requester"}}); err != nil {
		t.Fatalf("SetActivationConflictSets: %v", err)
	}
	if err := act.ActivateRoles(ctx, "grace", "web", "sess-1", []string{"approver"}); err != nil {
		t.Fatalf("ActivateRoles single role: %v", err)
	}
	active, err := act.ActiveRoles(ctx, "grace", "web", "sess-1")
	if err != nil || len(active) != 1 || active[0].Code != "approver" {
		t.Fatalf("ActiveRoles = %+v, %v; want [approver]", active, err)
	}
}

// testSoDDynamicActiveRolesScopedPerSession locks the per-session
// isolation: the same subject's two concurrent sessions can each activate
// a different (individually non-conflicting) role without one clobbering
// the other.
func testSoDDynamicActiveRolesScopedPerSession(t *testing.T, p permissions.Provider) {
	act, ok := p.(permissions.SessionRoleActivator)
	if !ok {
		t.Skip("provider doesn't implement SessionRoleActivator")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "approver"})
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "requester"})
	_ = p.AssignRoles(ctx, "heidi", "web", []string{"approver", "requester"})
	if err := act.ActivateRoles(ctx, "heidi", "web", "sess-a", []string{"approver"}); err != nil {
		t.Fatalf("ActivateRoles sess-a: %v", err)
	}
	if err := act.ActivateRoles(ctx, "heidi", "web", "sess-b", []string{"requester"}); err != nil {
		t.Fatalf("ActivateRoles sess-b: %v", err)
	}
	a, _ := act.ActiveRoles(ctx, "heidi", "web", "sess-a")
	b, _ := act.ActiveRoles(ctx, "heidi", "web", "sess-b")
	if len(a) != 1 || a[0].Code != "approver" {
		t.Errorf("sess-a active = %+v, want [approver]", a)
	}
	if len(b) != 1 || b[0].Code != "requester" {
		t.Errorf("sess-b active = %+v, want [requester]", b)
	}
}

// testSoDDynamicDeactivateSessionClears locks logout/session-end cleanup:
// DeactivateSession empties the session's active set and is idempotent.
func testSoDDynamicDeactivateSessionClears(t *testing.T, p permissions.Provider) {
	act, ok := p.(permissions.SessionRoleActivator)
	if !ok {
		t.Skip("provider doesn't implement SessionRoleActivator")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer"})
	_ = p.AssignRoles(ctx, "ivan", "web", []string{"viewer"})
	_ = act.ActivateRoles(ctx, "ivan", "web", "sess-1", []string{"viewer"})
	if err := act.DeactivateSession(ctx, "ivan", "web", "sess-1"); err != nil {
		t.Fatalf("DeactivateSession: %v", err)
	}
	active, err := act.ActiveRoles(ctx, "ivan", "web", "sess-1")
	if err != nil || len(active) != 0 {
		t.Fatalf("ActiveRoles after deactivate = %v, %v; want empty", active, err)
	}
	// Idempotent repeat.
	if err := act.DeactivateSession(ctx, "ivan", "web", "sess-1"); err != nil {
		t.Fatalf("DeactivateSession (repeat): %v", err)
	}
}

// testSoDDynamicAssignmentMutationClears requires a fresh activation after
// membership changes. Otherwise a role removed and later re-assigned could
// silently regain authority from an old session projection.
func testSoDDynamicAssignmentMutationClears(t *testing.T, p permissions.Provider) {
	act, ok := p.(permissions.SessionRoleActivator)
	if !ok {
		t.Skip("provider doesn't implement SessionRoleActivator")
	}
	ctx := context.Background()
	_ = p.AddRole(ctx, "web", permissions.Role{Code: "viewer"})
	if err := p.AssignRoles(ctx, "jane", "web", []string{"viewer"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := act.ActivateRoles(ctx, "jane", "web", "sess-1", []string{"viewer"}); err != nil {
		t.Fatalf("ActivateRoles: %v", err)
	}
	if err := p.UnassignRoles(ctx, "jane", "web", []string{"viewer"}); err != nil {
		t.Fatalf("UnassignRoles: %v", err)
	}
	if err := p.AssignRoles(ctx, "jane", "web", []string{"viewer"}); err != nil {
		t.Fatalf("AssignRoles after unassign: %v", err)
	}
	active, err := act.ActiveRoles(ctx, "jane", "web", "sess-1")
	if err != nil || len(active) != 0 {
		t.Fatalf("ActiveRoles after assignment mutation = %v, %v; want empty", active, err)
	}
}
