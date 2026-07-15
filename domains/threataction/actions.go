package threataction

import (
	"context"
	"fmt"

	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/shared/core"
)

// FamilyRevoker is the minimal interface for refresh token family revocation.
// Defined locally (not importing protocols/oauth/oauthspi) to keep the domain
// layer free of upward imports toward protocols.
type FamilyRevoker interface {
	// DeleteFamily removes every refresh token (active or consumed)
	// sharing the supplied FamilyID. Returns the count of active tokens
	// that were killed. Idempotent.
	DeleteFamily(ctx context.Context, familyID string) (int, error)
}

// SubjectRevoker is the minimal interface for subject-scoped refresh token
// revocation — the fallback RevokeFamilyExecutor uses when a threat carries
// no FamilyID. Neither anomaly.Runner (built from an anomaly.Signal, which
// precedes token issuance) nor tokenanomaly.Detector (built from a
// tokenanomaly.Finding, which has no family concept) ever populate
// Threat.FamilyID today, so without this fallback revoke_family is a
// permanent no-op in production. Defined locally (not importing
// protocols/oauth/oauthspi) to keep the domain layer free of upward imports
// toward protocols, exactly like FamilyRevoker above. Matches
// oauthspi.RefreshTokenSubjectIndex's method signature exactly, so the same
// production RefreshTokenStore instance that implements FamilyRevoker also
// satisfies this without any adapter.
type SubjectRevoker interface {
	// DeleteAllForSubject removes every refresh token bound to
	// (subjectID, clientID). Returns the count of deleted entries.
	// Idempotent.
	DeleteAllForSubject(ctx context.Context, subjectID, clientID string) (int, error)
}

// SuspendSessionExecutor suspends a user's sessions. It wraps a
// core.SessionManager and best-effort suspends every active session
// for the threat's SubjectID.
//
// FAIL-OPEN: a store error is returned but never blocks sibling actions.
// Also publishes a KindSessionSuspended cluster bus event (best-effort,
// mirroring RevokeFamilyExecutor's KindTokenRevoked broadcast) so a peer
// replica's session cache, if any, learns of the suspension instead of
// only the replica that handled the anomaly signal.
type SuspendSessionExecutor struct {
	sessions core.SessionManager
	bus      cluster.Bus
}

// NewSuspendSessionExecutor builds a SuspendSessionExecutor.
// sessions may be nil; Execute is then a safe no-op (for builds
// without a SessionManager). bus may also be nil (safe no-op publish),
// e.g. for a single-replica build with no cluster coordination wired.
func NewSuspendSessionExecutor(sessions core.SessionManager, bus cluster.Bus) *SuspendSessionExecutor {
	return &SuspendSessionExecutor{sessions: sessions, bus: bus}
}

// Name returns the executor identifier.
func (e *SuspendSessionExecutor) Name() string { return "suspend_session" }

// Execute suspends every active session for the threat's SubjectID.
// Also publishes a KindSessionSuspended cluster bus event for cross-replica
// propagation.
func (e *SuspendSessionExecutor) Execute(ctx context.Context, threat Threat, _ ThreatPolicy) (ActionResult, error) {
	if e.sessions == nil || threat.SubjectID == "" {
		return ActionResult{Action: ActionSuspend, OK: false, Detail: "no session manager or empty subject"}, nil
	}
	sessions, err := e.sessions.ListByUser(ctx, threat.SubjectID)
	if err != nil {
		return ActionResult{Action: ActionSuspend, OK: false, Detail: err.Error()}, err
	}
	var suspended int
	var lastErr error
	for _, s := range sessions {
		if s.Revoked {
			continue
		}
		if err := e.sessions.Destroy(ctx, s.ID); err != nil {
			lastErr = err
			continue
		}
		suspended++
	}
	detail := fmt.Sprintf("suspended %d session(s) for subject %s", suspended, threat.SubjectID)
	if lastErr != nil {
		detail += fmt.Sprintf(" (partial: %v)", lastErr)
	}
	// Best-effort cluster bus broadcast, mirroring RevokeFamilyExecutor. Fires
	// whenever ListByUser itself succeeded (even a partial per-session Destroy
	// failure) — a peer dropping a session cache entry it may not even hold is
	// always safe (idempotent), so over-notifying here never costs more than a
	// wasted cache miss on the receiving side.
	if e.bus != nil {
		_ = e.bus.Publish(ctx, cluster.Event{
			Kind: cluster.KindSessionSuspended,
			Key:  threat.SubjectID,
			Payload: map[string]string{
				"threat_action": string(ActionSuspend),
				"threat_type":   threat.Type,
				"subject_id":    threat.SubjectID,
			},
		})
	}
	return ActionResult{Action: ActionSuspend, OK: suspended > 0 || lastErr == nil, Detail: detail}, lastErr
}

// RevokeFamilyExecutor revokes a refresh token family. It wraps an
// oauthspi.RefreshTokenFamilyTracker and deletes the entire family
// identified by the threat's FamilyID.
//
// Neither production caller (anomaly.Runner, tokenanomaly.Detector) ever
// populates Threat.FamilyID — a login event precedes token issuance, and a
// token Finding has no family concept — so the family-scoped path alone
// makes this executor a permanent no-op. subjects is the fallback: when
// FamilyID is empty, Execute revokes every refresh token for the threat's
// SubjectID instead, mirroring SuspendSessionExecutor's subject-scoped
// design (broader than one family, but the only granularity available from
// either detection source).
//
// FAIL-OPEN: a store error is returned but never blocks sibling actions.
type RevokeFamilyExecutor struct {
	families FamilyRevoker
	subjects SubjectRevoker
	bus      cluster.Bus
}

// NewRevokeFamilyExecutor builds a RevokeFamilyExecutor.
// families and subjects may each independently be nil; Execute degrades to
// whichever path(s) are wired, and is a safe no-op when neither is (for
// builds without refresh token tracking).
func NewRevokeFamilyExecutor(families FamilyRevoker, subjects SubjectRevoker, bus cluster.Bus) *RevokeFamilyExecutor {
	return &RevokeFamilyExecutor{families: families, subjects: subjects, bus: bus}
}

// Name returns the executor identifier.
func (e *RevokeFamilyExecutor) Name() string { return "revoke_family" }

// Execute revokes the refresh token family identified by FamilyID when one
// is present and a family tracker is wired. Otherwise it falls back to
// revoking every refresh token for the threat's SubjectID via the optional
// SubjectRevoker extension — see the type doc for why this fallback exists.
// Either path publishes a KindTokenRevoked cluster bus event for
// cross-replica propagation.
func (e *RevokeFamilyExecutor) Execute(ctx context.Context, threat Threat, _ ThreatPolicy) (ActionResult, error) {
	if e.families != nil && threat.FamilyID != "" {
		return e.revokeFamily(ctx, threat)
	}
	if e.subjects != nil && threat.SubjectID != "" {
		return e.revokeSubject(ctx, threat)
	}
	return ActionResult{Action: ActionRevoke, OK: false, Detail: "no family tracker or empty family ID"}, nil
}

// revokeFamily is the original family-scoped path: unchanged behavior from
// before the SubjectRevoker fallback existed.
func (e *RevokeFamilyExecutor) revokeFamily(ctx context.Context, threat Threat) (ActionResult, error) {
	count, err := e.families.DeleteFamily(ctx, threat.FamilyID)
	if err != nil {
		return ActionResult{Action: ActionRevoke, OK: false, Detail: err.Error()}, err
	}
	detail := fmt.Sprintf("revoked %d token(s) in family %s", count, threat.FamilyID)
	e.publishRevoked(ctx, threat, threat.FamilyID)
	return ActionResult{Action: ActionRevoke, OK: true, Detail: detail}, nil
}

// revokeSubject is the fallback path for a threat with no FamilyID (or no
// family tracker wired): it kills every refresh token the subject holds for
// the threat's ClientID — empty ClientID mirrors DeleteAllForSubject's own
// "every client" semantics.
func (e *RevokeFamilyExecutor) revokeSubject(ctx context.Context, threat Threat) (ActionResult, error) {
	count, err := e.subjects.DeleteAllForSubject(ctx, threat.SubjectID, threat.ClientID)
	if err != nil {
		return ActionResult{Action: ActionRevoke, OK: false, Detail: err.Error()}, err
	}
	detail := fmt.Sprintf("revoked %d refresh token(s) for subject %s", count, threat.SubjectID)
	e.publishRevoked(ctx, threat, threat.SubjectID)
	return ActionResult{Action: ActionRevoke, OK: true, Detail: detail}, nil
}

// publishRevoked best-effort broadcasts a KindTokenRevoked cluster event
// keyed by key (the FamilyID on the family path, the SubjectID on the
// subject-scoped fallback) so a peer replica's cache learns of the
// revocation. Nil bus (no cluster coordination wired) is a safe no-op.
func (e *RevokeFamilyExecutor) publishRevoked(ctx context.Context, threat Threat, key string) {
	if e.bus == nil {
		return
	}
	_ = e.bus.Publish(ctx, cluster.Event{
		Kind: cluster.KindTokenRevoked,
		Key:  key,
		Payload: map[string]string{
			"threat_action": string(ActionRevoke),
			"threat_type":   threat.Type,
			"subject_id":    threat.SubjectID,
		},
	})
}

// StepUpMFAExecutor tags a user's sessions for MFA step-up on the
// next authentication. It wraps a core.SessionTrustManager and marks
// every active session for step-up.
//
// FAIL-OPEN: a store error is returned but never blocks sibling actions.
type StepUpMFAExecutor struct {
	trustMgr core.SessionTrustManager
	sessions core.SessionManager
}

// NewStepUpMFAExecutor builds a StepUpMFAExecutor.
func NewStepUpMFAExecutor(trustMgr core.SessionTrustManager, sessions core.SessionManager) *StepUpMFAExecutor {
	return &StepUpMFAExecutor{trustMgr: trustMgr, sessions: sessions}
}

// Name returns the executor identifier.
func (e *StepUpMFAExecutor) Name() string { return "step_up_mfa" }

// Execute marks every active session for the threat's SubjectID for MFA
// step-up challenge on the next request.
func (e *StepUpMFAExecutor) Execute(ctx context.Context, threat Threat, _ ThreatPolicy) (ActionResult, error) {
	if e.trustMgr == nil || e.sessions == nil || threat.SubjectID == "" {
		return ActionResult{Action: ActionStepUpMFA, OK: false, Detail: "no trust manager or empty subject"}, nil
	}
	sessions, err := e.sessions.ListByUser(ctx, threat.SubjectID)
	if err != nil {
		return ActionResult{Action: ActionStepUpMFA, OK: false, Detail: err.Error()}, err
	}
	var marked int
	var lastErr error
	for _, s := range sessions {
		if s.Revoked {
			continue
		}
		if err := e.trustMgr.MarkStepUp(ctx, s.ID); err != nil {
			lastErr = err
			continue
		}
		marked++
	}
	detail := fmt.Sprintf("marked %d session(s) for MFA step-up for subject %s", marked, threat.SubjectID)
	if lastErr != nil {
		detail += fmt.Sprintf(" (partial: %v)", lastErr)
	}
	return ActionResult{Action: ActionStepUpMFA, OK: marked > 0 || lastErr == nil, Detail: detail}, lastErr
}

// ChallengeExecutor tags a user's sessions for a fresh verification
// challenge on the next authentication. It wraps a core.SessionTrustManager
// and marks every active session for step-up, exactly like StepUpMFAExecutor.
//
// Design note: ActionChallenge ("challenge") and ActionStepUpMFA
// ("step_up_mfa") are DISTINCT policy-facing action names, but today they
// produce the SAME underlying effect — core.SessionTrustManager exposes
// exactly one primitive for "require something extra on the next auth":
// MarkStepUp, which sets Session.StepUpRequired (shared/core/types_auth.go).
// There is no separate "soft re-auth" flag on Session distinct from
// StepUpRequired, so a lighter-weight "challenge" cannot be distinguished
// from a full MFA step-up at the SessionManager layer yet. Keeping
// ChallengeExecutor as its own type (rather than aliasing StepUpMFAExecutor)
// means policy authors get both names AND gives a future SessionManager
// extension (e.g. a genuine "soft challenge" primitive alongside MarkStepUp)
// an obvious, isolated place to diverge without touching step_up_mfa's
// contract.
//
// FAIL-OPEN: a store error is returned but never blocks sibling actions.
type ChallengeExecutor struct {
	trustMgr core.SessionTrustManager
	sessions core.SessionManager
}

// NewChallengeExecutor builds a ChallengeExecutor.
func NewChallengeExecutor(trustMgr core.SessionTrustManager, sessions core.SessionManager) *ChallengeExecutor {
	return &ChallengeExecutor{trustMgr: trustMgr, sessions: sessions}
}

// Name returns the executor identifier.
func (e *ChallengeExecutor) Name() string { return "challenge" }

// Execute marks every active session for the threat's SubjectID for a
// verification challenge on the next request. See the ChallengeExecutor
// doc comment: this currently shares MarkStepUp with StepUpMFAExecutor,
// the only mechanism core.SessionTrustManager exposes today.
func (e *ChallengeExecutor) Execute(ctx context.Context, threat Threat, _ ThreatPolicy) (ActionResult, error) {
	if e.trustMgr == nil || e.sessions == nil || threat.SubjectID == "" {
		return ActionResult{Action: ActionChallenge, OK: false, Detail: "no trust manager or empty subject"}, nil
	}
	sessions, err := e.sessions.ListByUser(ctx, threat.SubjectID)
	if err != nil {
		return ActionResult{Action: ActionChallenge, OK: false, Detail: err.Error()}, err
	}
	var marked int
	var lastErr error
	for _, s := range sessions {
		if s.Revoked {
			continue
		}
		if err := e.trustMgr.MarkStepUp(ctx, s.ID); err != nil {
			lastErr = err
			continue
		}
		marked++
	}
	detail := fmt.Sprintf("marked %d session(s) for challenge for subject %s", marked, threat.SubjectID)
	if lastErr != nil {
		detail += fmt.Sprintf(" (partial: %v)", lastErr)
	}
	return ActionResult{Action: ActionChallenge, OK: marked > 0 || lastErr == nil, Detail: detail}, lastErr
}

// NotifyExecutor emits an audit event for admin notification. The
// existing audit sink and webhook pipeline picks it up.
//
// FAIL-OPEN: an audit error is returned but never blocks sibling actions.
type NotifyExecutor struct{}

// NewNotifyExecutor builds a NotifyExecutor.
func NewNotifyExecutor() *NotifyExecutor {
	return &NotifyExecutor{}
}

// Name returns the executor identifier.
func (e *NotifyExecutor) Name() string { return "notify" }

// Execute records the threat as an audit event so the existing webhook
// and notification pipeline picks it up. This executor is a pass-through
// — the registry handles audit recording; this executor exists as a
// named action the policy engine can assign.
func (e *NotifyExecutor) Execute(_ context.Context, threat Threat, policy ThreatPolicy) (ActionResult, error) {
	detail := "notification recorded for threat " + threat.Type + " on subject " + threat.SubjectID
	return ActionResult{Action: ActionNotify, OK: true, Detail: detail}, nil
}
