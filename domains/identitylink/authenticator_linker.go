package identitylink

import (
	"context"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// AuthenticatorLinker adapts a [Store] + [MergePolicy] pair into the
// (provider, subject) -> userID resolution shape a federated login
// Callback needs — see domains/authenticators.OIDCFederationAuthenticator's
// UserLinker. This package deliberately does NOT import domains/authenticators
// (avoiding a new inter-domain coupling): AuthenticatorLinker's ResolveUserID
// method satisfies UserLinker STRUCTURALLY — Go interface satisfaction needs
// no import, only a matching method signature.
//
// AuthenticatorLinker wraps [resolveWithDecision] (the same logic [Resolve]
// uses) so it can additionally call [RecordMergeDecision] on every genuine
// conflict — the package doc's "every link/unlink/merge decision must be
// audited" invariant applies here exactly as it does to a hand-written
// integration, so this ready-made adapter must not skip it.
type AuthenticatorLinker struct {
	store   Store
	policy  MergePolicy
	auditor *audit.Recorder
}

// NewAuthenticatorLinker returns an AuthenticatorLinker backed by store +
// policy — the SAME pair an operator wires via sso.WithIdentityLinkStore /
// sso.WithIdentityMergePolicy, so a login resolution and the self-service
// /me/identities surface stay consistent with each other. A nil policy is
// treated by [Resolve] as [RejectPolicy] (never a silent no-op — see
// MergePolicy's doc). auditor may be nil (RecordMergeDecision no-ops).
func NewAuthenticatorLinker(store Store, policy MergePolicy, auditor *audit.Recorder) *AuthenticatorLinker {
	return &AuthenticatorLinker{store: store, policy: policy, auditor: auditor}
}

// ResolveUserID implements the authenticators.UserLinker method shape.
//
// incomingUserID passed to resolution is subject itself: a federated
// Callback with no linker wired defaults AuthResult.UserID to the raw
// external subject (see OIDCFederationAuthenticator.Callback) — so "subject"
// IS "the account the login would use absent this conflict", exactly
// [Conflict.IncomingUserID]'s contract. A genuine conflict only arises once
// some OTHER flow (an operator's "connect an additional identity" self-service
// action, built on [Store.Link]) has already linked (provider, subject) to a
// DIFFERENT account — see the package doc's "Live login-flow wiring" section.
// This method never calls [Store.Link] itself: creating a link is a
// deliberate, separate act this package leaves to that other flow, never an
// automatic side effect of a login resolving successfully.
//
// Every genuine conflict (found != nil) is audited via [RecordMergeDecision]
// before returning, whether the policy allowed or rejected it.
func (l *AuthenticatorLinker) ResolveUserID(ctx context.Context, provider, subject string) (string, error) {
	userID, conflict, decision, err := resolveWithDecision(ctx, l.store, l.policy, provider, subject, subject)
	if conflict != nil {
		RecordMergeDecision(ctx, l.auditor, *conflict, decision, err)
	}
	return userID, err
}
