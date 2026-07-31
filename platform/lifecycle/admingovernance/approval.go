// Package admingovernance holds the admin governance framework: per-tenant/
// admin write quotas, a generic two-person change-approval workflow, a
// destructive-action confirmation guard, and an IP/geo allowlist for the
// /api/v1/admin/* control plane. Every mechanism is opt-in — a deployment
// that never wires one of these types (or never calls the corresponding
// interfaces/admin.Middleware setter) sees byte-identical behavior to a
// build without this package.
//
// The change-approval workflow generalizes core.BreakGlassStore's
// propose/approve/self-approval-refusal shape beyond emergency-access grants
// to arbitrary admin mutation types: an admin PROPOSES an action_type +
// payload, a DIFFERENT admin APPROVES it, and — when an Applier is
// registered for that action_type — the approval immediately APPLIES the
// change. An action_type with no registered Applier still completes the
// propose/approve lifecycle; it simply has no in-process side effect,
// leaving the caller to follow through out-of-band.
package admingovernance

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ChangeStatus is the lifecycle state of a proposed admin change.
type ChangeStatus string

const (
	ChangeStatusPending  ChangeStatus = "pending"
	ChangeStatusApproved ChangeStatus = "approved"
	ChangeStatusApplied  ChangeStatus = "applied"
	ChangeStatusRejected ChangeStatus = "rejected"
	// ChangeStatusFailed marks a change whose Applier returned an error.
	// Approval already happened — a failed apply is reported on the record
	// (FailureNote), not silently reverted.
	ChangeStatusFailed ChangeStatus = "failed"
)

// ChangeRequest is a generic, two-person-controlled admin mutation record.
// Payload is a caller-defined JSON document interpreted only by whichever
// Applier is registered for ActionType — this package never inspects it.
type ChangeRequest struct {
	ID         string          `json:"id"`
	ActionType string          `json:"action_type"`
	Payload    json.RawMessage `json:"payload"`
	// Reason is the mandatory ticket/justification, mirroring break-glass's
	// mandatory reason: an unexplained governed change is itself an audit
	// finding.
	Reason      string       `json:"reason"`
	ProposedBy  string       `json:"proposed_by"`
	ApprovedBy  string       `json:"approved_by,omitempty"`
	Status      ChangeStatus `json:"status"`
	FailureNote string       `json:"failure_note,omitempty"`
	CreatedAt   time.Time    `json:"created_at"`
	DecidedAt   time.Time    `json:"decided_at,omitempty"`
}

// Sentinel errors an ApprovalStore implementation MUST return (checked via
// errors.Is) so callers can map them to the correct HTTP status — mirrors
// core.BreakGlassStore's Approve contract.
var (
	ErrChangeNotFound     = errors.New("admingovernance: change request not found")
	ErrChangeSelfApproval = errors.New("admingovernance: approver must differ from proposer")
	ErrChangeNotPending   = errors.New("admingovernance: change request is not pending")
)

// ApprovalStore persists generic change-approval requests. Implementations
// MUST enforce the self-approval refusal and the pending-only transition
// authoritatively (not merely rely on a caller's pre-check) — mirrors
// core.BreakGlassStore.
type ApprovalStore interface {
	// Propose persists a new PENDING change request. The store assigns
	// CreatedAt; the caller supplies everything else (including ID).
	Propose(ctx context.Context, c ChangeRequest) (ChangeRequest, error)
	// Get returns one record by ID. Returns ErrChangeNotFound when unknown.
	Get(ctx context.Context, id string) (ChangeRequest, error)
	// List returns every non-terminal-decided-but-unapplied plus applied
	// record, newest first — an operator-facing audit list, not filtered to
	// only-pending.
	List(ctx context.Context) ([]ChangeRequest, error)
	// Approve atomically transitions a pending record to Approved, stamping
	// ApprovedBy and DecidedAt. MUST reject approverID == ProposedBy with
	// ErrChangeSelfApproval, and a non-pending record with
	// ErrChangeNotPending — the store is the atomic authority even when
	// handlers pre-check.
	Approve(ctx context.Context, id, approverID string) (ChangeRequest, error)
	// Reject marks a pending record Rejected. Same not-pending / not-found
	// contract as Approve (self-approval has no meaning for a rejection, so
	// it is not checked).
	Reject(ctx context.Context, id, approverID string) (ChangeRequest, error)
	// MarkApplied / MarkFailed record an Applier's outcome after Approve.
	// Both are no-ops (return the current record unchanged) when the record
	// is not in Approved status — Apply only ever follows a fresh Approve.
	MarkApplied(ctx context.Context, id string) (ChangeRequest, error)
	MarkFailed(ctx context.Context, id, note string) (ChangeRequest, error)
}

// Applier performs the real mutation a ChangeRequest describes, once
// approved. Registered per action_type via Registry.Register. An Applier
// error is captured on the record (MarkFailed) rather than propagated —
// approval already happened, so the failure is reported back to whoever
// reads the change, not undone.
type Applier func(ctx context.Context, payload []byte) error

// Registry maps an action_type to its Applier. The zero value is a valid,
// empty registry (every Lookup misses) — matching the "nil means off"
// convention every other optional SDK subsystem here follows.
type Registry struct {
	appliers map[string]Applier
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry { return &Registry{appliers: map[string]Applier{}} }

// Register wires fn as the Applier for actionType, overwriting any prior
// registration for the same type.
func (r *Registry) Register(actionType string, fn Applier) {
	if r == nil || fn == nil {
		return
	}
	if r.appliers == nil {
		r.appliers = map[string]Applier{}
	}
	r.appliers[actionType] = fn
}

// Lookup returns the Applier registered for actionType, or ok=false when
// none was registered (or r is nil) — the caller then leaves the change in
// Approved status for out-of-band follow-through.
func (r *Registry) Lookup(actionType string) (fn Applier, ok bool) {
	if r == nil {
		return nil, false
	}
	fn, ok = r.appliers[actionType]
	return fn, ok
}

// ApproveAndApply approves id on behalf of approverID and, when an Applier
// is registered for the resulting record's ActionType, invokes it
// immediately and records the outcome (MarkApplied / MarkFailed). reg may be
// nil (equivalent to an empty Registry — every change stays Approved,
// never auto-applied). Centralizes the orchestration so HTTP handlers stay
// thin, mirroring how HandleApproveBreakGlass composes store calls.
func ApproveAndApply(ctx context.Context, store ApprovalStore, reg *Registry, id, approverID string) (ChangeRequest, error) {
	c, err := store.Approve(ctx, id, approverID)
	if err != nil {
		return ChangeRequest{}, err
	}
	fn, ok := reg.Lookup(c.ActionType)
	if !ok {
		return c, nil
	}
	if applyErr := fn(ctx, c.Payload); applyErr != nil {
		if failed, mErr := store.MarkFailed(ctx, id, applyErr.Error()); mErr == nil {
			return failed, nil
		}
		return c, nil
	}
	applied, mErr := store.MarkApplied(ctx, id)
	if mErr != nil {
		return c, nil
	}
	return applied, nil
}

// RequiredActionTypes is a configured allow-list of action_type values the
// propose endpoint accepts. An empty set (the zero value) is permissive —
// ANY action_type is accepted — matching "unconfigured means unrestricted"
// for a brand-new opt-in feature; an operator narrows it by listing the
// action types they actually govern.
type RequiredActionTypes map[string]bool

// NewRequiredActionTypes builds a RequiredActionTypes set from configured
// action-type strings.
func NewRequiredActionTypes(actionTypes []string) RequiredActionTypes {
	s := make(RequiredActionTypes, len(actionTypes))
	for _, t := range actionTypes {
		s[t] = true
	}
	return s
}

// Allows reports whether actionType may be proposed: true when the set is
// empty (unrestricted) or actionType is explicitly listed.
func (s RequiredActionTypes) Allows(actionType string) bool {
	if len(s) == 0 {
		return true
	}
	return s[actionType]
}
