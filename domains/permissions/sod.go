package permissions

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Sentinel errors for Separation of Duty (SoD) violations.
var (
	// ErrRoleConflict is returned by AssignRoles, AddRoleToUser, and
	// ActivateRoles when the resulting role set would hold (or activate)
	// two-or-more codes from the same declared conflict set. errors.As
	// recovers *ConflictError for the offending codes; errors.Is keeps
	// matching through wrapping.
	ErrRoleConflict = errors.New("permissions: roles violate separation of duty")

	// ErrRoleNotAssigned is returned by ActivateRoles (DSoD) when a
	// requested role code isn't currently held by the subject: a session
	// may only ACTIVATE a subset of roles the subject is already
	// ASSIGNED, never a role it doesn't hold.
	ErrRoleNotAssigned = errors.New("permissions: role not assigned to user")

	// ErrInvalidConflictSet is returned by SetConflictSets /
	// SetActivationConflictSets when a set names fewer than two distinct,
	// non-empty role codes — a "conflict" of one role is not a
	// constraint.
	ErrInvalidConflictSet = errors.New("permissions: conflict set requires at least two distinct role codes")
)

// ConflictError reports exactly which declared conflict set tripped and
// which of the requested codes collided, so admin UIs and audit trails can
// explain WHY an assignment/activation was rejected instead of a bare
// "conflict" message. Wraps ErrRoleConflict via Unwrap so
// errors.Is(err, ErrRoleConflict) keeps matching after logging/wrapping.
type ConflictError struct {
	ClientID string
	Set      []string // the declared conflict set that tripped
	Roles    []string // the subset of Set present in the rejected request (len >= 2)
}

func (e *ConflictError) Error() string {
	return fmt.Sprintf("permissions: roles %v conflict under separation-of-duty set %v (client %q)", e.Roles, e.Set, e.ClientID)
}

// Unwrap lets errors.Is(err, ErrRoleConflict) match through wrapping.
func (e *ConflictError) Unwrap() error { return ErrRoleConflict }

// SoDProvider is an optional Provider extension (mirrors the MenuLister /
// GroupMembershipWriter pattern: type-assert before use, so a backend that
// doesn't implement it leaves base Provider callers unaffected) for
// declaring STATIC Separation of Duty (SSoD) constraints: sets of role
// codes that must never be held by the same subject under the same client
// at the same time — e.g. "approver" and "requester" for one workflow.
//
// Declarations are purely additive: a Provider with zero declared sets
// enforces nothing, so AssignRoles/AddRoleToUser behave EXACTLY as they
// did before this extension existed — unconfigured behavior is
// byte-identical to the pre-SoD Provider contract. Enforcement lives
// inside the base Provider's AssignRoles and (via GroupMembershipWriter)
// AddRoleToUser; SoDProvider only manages the declarations those methods
// consult.
type SoDProvider interface {
	// SetConflictSets replaces clientID's ENTIRE table of SSoD conflict
	// sets — SET semantics, like SetMenus/AssignRoles, not a merge. Each
	// inner slice names two-or-more role codes that may never be
	// assigned to the same subject at once; a set with fewer than two
	// distinct non-empty codes is rejected with ErrInvalidConflictSet and
	// the whole call is a no-op (no partial write). Passing nil/empty
	// clears every constraint for clientID, restoring the additive
	// default (assignment enforcement becomes a no-op).
	//
	// SetConflictSets does NOT retroactively re-validate assignments that
	// already exist: a set declared after a now-conflicting assignment
	// took effect only blocks the NEXT AssignRoles/AddRoleToUser call for
	// that subject (mirrors how editing a Role definition doesn't
	// retroactively revoke access already resolved elsewhere in this
	// package). ActivateRoles (DSoD) additionally checks this table as
	// defense-in-depth against exactly that gap — see
	// SessionRoleActivator.
	SetConflictSets(ctx context.Context, clientID string, sets [][]string) error

	// ConflictSets returns clientID's currently declared SSoD sets.
	ConflictSets(ctx context.Context, clientID string) ([][]string, error)
}

// SessionRoleActivator is an optional Provider extension for Dynamic
// Separation of Duty (DSoD): a subject may legitimately HOLD (via
// AssignRoles) two roles that are mutually exclusive to ACTIVATE within
// one session/context — e.g. a subject holds both "approver" and
// "requester" system-wide, but must pick only one per workflow instance.
// DSoD tracks a per-session ACTIVE subset distinct from the subject's full
// ASSIGNED set: Roles/Permissions/Menus are untouched by activation (they
// keep reporting the full assigned set) — activation is an additional,
// opt-in axis a caller consults only when it cares which roles are "in
// effect" for the CURRENT session.
//
// sessionID is caller-defined and opaque to the Provider (typically an
// OIDC session id / Subject.SID, or a login-request nonce). The same
// (userID, clientID) pair carries independent activation state per
// sessionID, so two concurrent sessions for one subject can each activate
// a different (individually non-conflicting) subset without contention.
type SessionRoleActivator interface {
	// SetActivationConflictSets replaces clientID's ENTIRE table of DSoD
	// conflict sets, independent of any SSoD sets declared via
	// SoDProvider — a pair MAY be DSoD-only (holdable together, only
	// exclusive to activate). SET semantics and validation mirror
	// SoDProvider.SetConflictSets.
	SetActivationConflictSets(ctx context.Context, clientID string, sets [][]string) error

	// ActivationConflictSets returns clientID's currently declared DSoD
	// sets.
	ActivationConflictSets(ctx context.Context, clientID string) ([][]string, error)

	// ActivateRoles selects the subset of the subject's ASSIGNED roles
	// (Provider.Roles) that becomes ACTIVE for sessionID. Every requested
	// code MUST already be held — activating an unassigned code returns
	// ErrRoleNotAssigned. Activating two codes that share either a DSoD
	// set (this interface) or an SSoD set (SoDProvider) returns
	// *ConflictError even when the subject legitimately holds both
	// (checking SSoD too is defense-in-depth for a set declared after a
	// conflicting assignment already existed — see
	// SoDProvider.SetConflictSets). Replaces the session's prior
	// activation (SET semantics).
	ActivateRoles(ctx context.Context, userID, clientID, sessionID string, roles []string) error

	// ActiveRoles returns the Role objects currently activated for
	// sessionID — a subset of Roles(ctx, userID, clientID). Empty (not an
	// error) when the session hasn't called ActivateRoles yet.
	ActiveRoles(ctx context.Context, userID, clientID, sessionID string) ([]Role, error)

	// DeactivateSession clears sessionID's activation state entirely
	// (session end / logout). Idempotent.
	DeactivateSession(ctx context.Context, userID, clientID, sessionID string) error
}

// validateConflictSets rejects any set naming fewer than two distinct,
// non-empty role codes — shared by SetConflictSets and
// SetActivationConflictSets so both tables apply identical hygiene.
func validateConflictSets(sets [][]string) error {
	for _, set := range sets {
		distinct := make(map[string]struct{}, len(set))
		for _, code := range set {
			if code == "" {
				return ErrInvalidConflictSet
			}
			distinct[code] = struct{}{}
		}
		if len(distinct) < 2 {
			return ErrInvalidConflictSet
		}
	}
	return nil
}

// ValidateConflictSets exposes the shared declaration hygiene to durable
// providers. Keeping validation here prevents memory and SQL/Redis peers from
// accepting different conflict-set shapes.
func ValidateConflictSets(sets [][]string) error { return validateConflictSets(sets) }

// findConflict scans sets for the first declared conflict set with
// two-or-more codes present in candidateCodes, returning a populated
// *ConflictError describing the collision (nil when candidateCodes is
// SoD-clean against every set). Shared by AssignRoles/AddRoleToUser (SSoD,
// over the ASSIGNED set) and ActivateRoles (SSoD+DSoD, over the requested
// ACTIVE subset) so every enforcement point agrees on one algorithm.
func findConflict(clientID string, sets [][]string, candidateCodes []string) *ConflictError {
	for _, set := range sets {
		hit := hitsInSet(set, candidateCodes)
		if len(hit) >= 2 {
			return &ConflictError{ClientID: clientID, Set: append([]string(nil), set...), Roles: hit}
		}
	}
	return nil
}

// CheckRoleConflict reports the first declared conflict set hit by a role
// candidate. Durable providers use the same error shape as MemoryProvider so
// admin callers and authorization adapters stay backend-independent.
func CheckRoleConflict(clientID string, sets [][]string, candidateCodes []string) error {
	if conflict := findConflict(clientID, sets, candidateCodes); conflict != nil {
		return conflict
	}
	return nil
}

// hitsInSet returns the codes in candidateCodes that also appear in set,
// preserving candidateCodes' order (stable, deterministic error messages).
func hitsInSet(set, candidateCodes []string) []string {
	var hit []string
	for _, code := range candidateCodes {
		if slices.Contains(set, code) {
			hit = append(hit, code)
		}
	}
	return hit
}

// --- MemoryProvider implementation of SoDProvider + SessionRoleActivator ---
//
// Kept in this file (rather than a separate memory_sod.go) to stay under
// the per-directory go-file fan-out budget (see directory_fanout_test.go);
// memory_resources.go/resources.go got the two-file split earlier because
// this package was already at the budget ceiling.

// SetConflictSets implements SoDProvider (SSoD). Validates before taking
// the lock so a rejected call never partially mutates state.
func (m *MemoryProvider) SetConflictSets(_ context.Context, clientID string, sets [][]string) error {
	if err := validateConflictSets(sets); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(sets) == 0 {
		delete(m.ssodConflicts, clientID)
		return nil
	}
	m.ssodConflicts[clientID] = cloneConflictSets(sets)
	return nil
}

// ConflictSets implements SoDProvider.
func (m *MemoryProvider) ConflictSets(_ context.Context, clientID string) ([][]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConflictSets(m.ssodConflicts[clientID]), nil
}

// SetActivationConflictSets implements SessionRoleActivator's own DSoD
// declaration table, independent of SoDProvider's SSoD table above.
func (m *MemoryProvider) SetActivationConflictSets(_ context.Context, clientID string, sets [][]string) error {
	if err := validateConflictSets(sets); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(sets) == 0 {
		delete(m.dsodConflicts, clientID)
		return nil
	}
	m.dsodConflicts[clientID] = cloneConflictSets(sets)
	return nil
}

// ActivationConflictSets implements SessionRoleActivator.
func (m *MemoryProvider) ActivationConflictSets(_ context.Context, clientID string) ([][]string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return cloneConflictSets(m.dsodConflicts[clientID]), nil
}

// ActivateRoles implements SessionRoleActivator. Checks assignment first
// (ErrRoleNotAssigned), then both conflict tables — SSoD union DSoD — so a
// constraint declared either way rejects the same request.
func (m *MemoryProvider) ActivateRoles(_ context.Context, userID, clientID, sessionID string, roles []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	held := m.assignmentsByUser[userID][clientID]
	for _, code := range roles {
		if !slices.Contains(held, code) {
			return fmt.Errorf("%w: %q", ErrRoleNotAssigned, code)
		}
	}
	combined := append(append([][]string{}, m.ssodConflicts[clientID]...), m.dsodConflicts[clientID]...)
	if c := findConflict(clientID, combined, roles); c != nil {
		return c
	}
	m.activeRoles[sessionKey(userID, clientID, sessionID)] = append([]string{}, roles...)
	return nil
}

// ActiveRoles implements SessionRoleActivator. A role code that was
// activated but later removed from the system (RemoveRole) is silently
// skipped, mirroring how Roles() filters stale codes out of an assignment
// list.
func (m *MemoryProvider) ActiveRoles(_ context.Context, userID, clientID, sessionID string) ([]Role, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	codes := m.activeRoles[sessionKey(userID, clientID, sessionID)]
	if len(codes) == 0 {
		return nil, nil
	}
	defs := m.rolesByClient[clientID]
	out := make([]Role, 0, len(codes))
	for _, code := range codes {
		if r, ok := defs[code]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// DeactivateSession implements SessionRoleActivator. Idempotent.
func (m *MemoryProvider) DeactivateSession(_ context.Context, userID, clientID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.activeRoles, sessionKey(userID, clientID, sessionID))
	return nil
}

// sessionKey composes the activeRoles map key. NUL-separated: none of the
// three IDs can legitimately contain a NUL byte, so unlike a printable
// delimiter (":", "|") this can't be spoofed by a crafted ID.
func sessionKey(userID, clientID, sessionID string) string {
	return userID + "\x00" + clientID + "\x00" + sessionID
}

// splitSessionKey recovers (userID, clientID) from a sessionKey produced by
// sessionKey. Only clientID is needed by stripActiveRole today; userID is
// returned for symmetry and to keep the tuple self-documenting at call
// sites.
func splitSessionKey(key string) (userID, clientID string, ok bool) {
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) != 3 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// stripActiveRole removes roleCode from every session's active set under
// clientID. Called by RemoveRole (memory.go) under m.mu so a
// deleted-then-recreated role code can't silently reactivate in a stale
// session without a fresh ActivateRoles call.
func (m *MemoryProvider) stripActiveRole(clientID, roleCode string) {
	for key, codes := range m.activeRoles {
		_, kClient, ok := splitSessionKey(key)
		if !ok || kClient != clientID || !slices.Contains(codes, roleCode) {
			continue
		}
		m.activeRoles[key] = slices.DeleteFunc(append([]string{}, codes...), func(c string) bool { return c == roleCode })
	}
}

// cloneConflictSets deep-copies a conflict-set table so callers can't
// mutate stored state through a slice they passed in or one they got back.
func cloneConflictSets(sets [][]string) [][]string {
	if len(sets) == 0 {
		return nil
	}
	cp := make([][]string, len(sets))
	for i, s := range sets {
		cp[i] = append([]string(nil), s...)
	}
	return cp
}

// Compile-time checks that MemoryProvider satisfies the optional SoD
// extensions.
var (
	_ SoDProvider          = (*MemoryProvider)(nil)
	_ SessionRoleActivator = (*MemoryProvider)(nil)
)
