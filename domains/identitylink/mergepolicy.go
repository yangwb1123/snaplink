package identitylink

import (
	"context"
	"errors"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// ErrAccountConflict is returned by Resolve (and by RejectPolicy.Resolve) when
// a Conflict is refused. Callers integrating Resolve into a login flow should
// treat it exactly like any other authentication failure — it MUST NOT leak
// which account owns the conflicting link (oracle-leak hardening, AGENTS.md
// §3): collapse it into the same generic failure response other
// authentication errors use, never a distinct "this identity belongs to
// someone else" message.
var ErrAccountConflict = errors.New("identitylink: external identity already linked to a different account")

// Conflict describes a detected identity-linking collision: the external
// identity (Provider, Subject) that is authenticating right now is ALREADY
// actively linked (per Store.FindByProviderSubject) to ExistingUserID, but
// resolving the login normally (e.g. a federated authenticator defaulting
// AuthResult.UserID to the external subject itself) would use a DIFFERENT
// account, IncomingUserID.
type Conflict struct {
	// Provider + Subject identify the external identity being authenticated.
	Provider string
	Subject  string
	// ExistingUserID is the account ALREADY linked to (Provider, Subject).
	ExistingUserID string
	// IncomingUserID is the account the login would use absent this Conflict.
	IncomingUserID string
}

// Decision is a MergePolicy's verdict on a Conflict.
type Decision struct {
	// Allow, when true, permits the login to proceed as FinalUserID instead
	// of being rejected.
	Allow bool
	// FinalUserID is the account the login should proceed as when Allow is
	// true. Reference policies set it to Conflict.ExistingUserID (the
	// account that owned the link first), so a returning federated user
	// always lands on the SAME account regardless of which "side" logged in
	// most recently.
	FinalUserID string
	// Reason is an operator-facing explanation — audit metadata only, never
	// echoed to the end user (oracle-leak hardening).
	Reason string
}

// MergePolicy decides what happens when a login flow discovers a Conflict.
// Deliberately UNLIKE most optional SPIs in this codebase, there is no
// nil-is-a-no-op convention here: [Resolve] treats a nil MergePolicy as
// [RejectPolicy] explicitly, because staying silent about an identity
// collision — silently picking one account, or silently merging state — is
// never a safe default an absent policy should imply.
type MergePolicy interface {
	// Resolve decides conflict. An error is treated as a rejection
	// (fail-closed, AGENTS.md §3) exactly like Allow: false.
	Resolve(ctx context.Context, conflict Conflict) (Decision, error)
}

// RejectPolicy is the safe DEFAULT MergePolicy: every Conflict is refused.
// This is the recommended policy for any deployment that has not
// deliberately decided how to merge two accounts — auto-picking a winner, or
// merging live session/consent/token state, has security implications (e.g.
// a lower-privileged account silently absorbing a higher-privileged one's
// identity, or vice versa) that only the operator can judge safe for their
// own data model.
type RejectPolicy struct{}

// Resolve always refuses. Implements MergePolicy.
func (RejectPolicy) Resolve(_ context.Context, _ Conflict) (Decision, error) {
	return Decision{Allow: false, Reason: "identity already linked to a different account"}, ErrAccountConflict
}

// LinkOnlyMergePolicy is a CONSERVATIVE reference merge strategy: an operator
// who explicitly wires it accepts that a Conflict is auto-resolved by
// re-pointing every one of the losing account's (IncomingUserID) Identity
// link records onto the winning account (ExistingUserID always wins — see
// Conflict's doc comment). It touches NOTHING else — see the package doc for
// the full list of what is deliberately left unmerged and why a fuller merge
// is out of scope for this package.
type LinkOnlyMergePolicy struct {
	store Store
}

// NewLinkOnlyMergePolicy returns a LinkOnlyMergePolicy backed by store. store
// must be the SAME Store the caller's Resolve/login flow uses — the policy
// both reads and writes it.
func NewLinkOnlyMergePolicy(store Store) *LinkOnlyMergePolicy {
	return &LinkOnlyMergePolicy{store: store}
}

// Resolve implements MergePolicy: it merges conflict.IncomingUserID's
// identity links onto conflict.ExistingUserID and, on success, allows the
// login to proceed as the (now-merged) ExistingUserID.
func (p *LinkOnlyMergePolicy) Resolve(ctx context.Context, conflict Conflict) (Decision, error) {
	if p.store == nil {
		return Decision{Allow: false, Reason: "identitylink: LinkOnlyMergePolicy has no store"}, ErrAccountConflict
	}
	if err := p.mergeLinks(ctx, conflict); err != nil {
		return Decision{Allow: false, Reason: "identitylink: link merge failed"}, err
	}
	return Decision{
		Allow:       true,
		FinalUserID: conflict.ExistingUserID,
		Reason:      "identity links merged onto existing account (sessions/consents/tokens NOT merged — see package doc)",
	}, nil
}

// mergeLinks re-links every ACTIVE identity currently owned by
// conflict.IncomingUserID onto conflict.ExistingUserID, then revokes the
// losing account's copy. Best-effort per link: a link that fails to
// re-attach (e.g. already active on the winner) is skipped rather than
// aborting the whole merge, so one stale entry can never block consolidating
// the rest.
func (p *LinkOnlyMergePolicy) mergeLinks(ctx context.Context, conflict Conflict) error {
	losing, err := p.store.ListByUser(ctx, conflict.IncomingUserID)
	if err != nil {
		return err
	}
	for _, l := range losing {
		if _, err := p.store.Link(ctx, conflict.ExistingUserID, l.Provider, l.Subject); err != nil {
			continue
		}
		_ = p.store.Unlink(ctx, conflict.IncomingUserID, l.ID)
	}
	return nil
}

var _ MergePolicy = RejectPolicy{}
var _ MergePolicy = (*LinkOnlyMergePolicy)(nil)

// Resolve is the seam a login flow (or a custom Authenticator's Callback)
// calls once it has an external (provider, subject) pair and a candidate
// incomingUserID — the account the login would use absent any conflict
// (e.g. AuthResult.UserID, which the built-in federated authenticators set
// to the external subject itself).
//
// When store is nil, or no active link for (provider, subject) exists yet,
// or that link already belongs to incomingUserID, Resolve returns
// (incomingUserID, nil) UNCHANGED — byte-identical to not calling Resolve at
// all. Only a genuine conflict (an ACTIVE link under a DIFFERENT user)
// reaches policy. A nil policy is treated as RejectPolicy{} (see MergePolicy
// doc — never a silent no-op). A store lookup error fails CLOSED (returns
// ErrAccountConflict) rather than risk silently proceeding past an
// unreadable conflict signal.
//
// Callers that also need to audit the verdict (via [RecordMergeDecision])
// without duplicating this logic should call [resolveWithDecision] instead —
// Resolve is a thin wrapper that discards the extra detail.
func Resolve(ctx context.Context, store Store, policy MergePolicy, provider, subject, incomingUserID string) (string, error) {
	userID, _, _, err := resolveWithDecision(ctx, store, policy, provider, subject, incomingUserID)
	return userID, err
}

// resolveWithDecision is Resolve's core logic, additionally returning the
// detected Conflict (nil when none was found — the no-op paths) and the
// MergePolicy's Decision, so a caller that must audit the verdict (e.g.
// AuthenticatorLinker) can do so with the exact Conflict/Decision pair
// RecordMergeDecision expects, instead of re-deriving them.
func resolveWithDecision(ctx context.Context, store Store, policy MergePolicy, provider, subject, incomingUserID string) (userID string, conflict *Conflict, decision Decision, err error) {
	if store == nil {
		return incomingUserID, nil, Decision{}, nil
	}
	existing, found, err := store.FindByProviderSubject(ctx, provider, subject)
	if err != nil {
		return "", nil, Decision{}, ErrAccountConflict
	}
	if !found || existing.UserID == incomingUserID {
		return incomingUserID, nil, Decision{}, nil
	}
	if policy == nil {
		policy = RejectPolicy{}
	}
	c := Conflict{
		Provider:       provider,
		Subject:        subject,
		ExistingUserID: existing.UserID,
		IncomingUserID: incomingUserID,
	}
	d, rErr := policy.Resolve(ctx, c)
	if rErr != nil || !d.Allow {
		return "", &c, d, ErrAccountConflict
	}
	return d.FinalUserID, &c, d, nil
}

// RecordMergeDecision emits the audit event for a MergePolicy verdict on
// conflict — EventIdentityMergeRejected when decision.Allow is false or
// resolveErr is non-nil, EventIdentityMerged otherwise. Mirrors
// domains/userlifecycle.RecordTransition: a free function taking the
// *audit.Recorder explicitly (no ambient global) so the caller controls
// WHEN it fires and can enrich the event with request-scoped fields (actor
// IP, trace id) before or after calling it. No-op when auditor is nil.
//
// This is the audit hook for the merge-decision half of "every
// link/unlink/merge decision must be audited": callers integrating [Resolve]
// into a login flow MUST call this alongside it. The self-service unlink
// path (DELETE /me/identities/:id) is audited separately by the interfaces/sso
// accessor RecordIdentityUnlinked, which has an HTTP request to enrich with.
func RecordMergeDecision(ctx context.Context, auditor *audit.Recorder, conflict Conflict, decision Decision, resolveErr error) {
	if auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventIdentityMerged,
		Outcome: audit.OutcomeSuccess,
		ActorID: conflict.IncomingUserID,
	}
	if resolveErr != nil || !decision.Allow {
		evt.Type = audit.EventIdentityMergeRejected
		evt.Outcome = audit.OutcomeFailure
	}
	audit.SetMeta(evt, "provider", conflict.Provider)
	audit.SetMeta(evt, "existing_user_id", conflict.ExistingUserID)
	audit.SetMeta(evt, "incoming_user_id", conflict.IncomingUserID)
	if decision.Reason != "" {
		audit.SetMeta(evt, "reason", decision.Reason)
	}
	auditor.Record(ctx, evt)
}
