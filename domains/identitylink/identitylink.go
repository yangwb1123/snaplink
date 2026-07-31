// Package identitylink implements SELF-SERVICE identity linking / account
// merging: it lets an end user see and manage the set of external identities
// (federated IdP subjects, or another local account folded in) that are
// allowed to authenticate into their ONE account, and gives an operator a
// documented, safe-by-default seam for the "two different local accounts
// both claim the same external identity" conflict.
//
// # Scope vs. existing "external identity" concepts
//
// This package is deliberately distinct from two other concepts already in
// the codebase, so it does not duplicate them:
//
//   - core.User.ExternalID / core.User.Provider is a single, 1:1 mapping a
//     login authenticator (e.g. authenticators.OIDCFederationAuthenticator)
//     stamps onto the user record it upserts on every login. It has no
//     history, no self-service surface, and supports exactly ONE external
//     identity per user — replaced wholesale on every CreateOrUpdate.
//   - domains/federation implements OpenID Federation 1.0 trust chains:
//     RP/OP TRUST between servers (which relying parties this AS trusts to
//     register clients, and vice versa). That is server-to-server trust, not
//     an end user's own account linkage.
//
// identitylink adds a many-to-one, historied, self-service-visible layer on
// top of the single ExternalID field: a user may accumulate several ACTIVE
// [Identity] links (Google + GitHub + a migrated legacy account), list them
// (GET /me/identities) and unlink one (DELETE /me/identities/:id) without
// ever losing their last way to log in — see the last-authentication-method
// guard the self-service handler applies before calling [Store.Unlink].
//
// # MergePolicy scope (IMPORTANT limitation)
//
// [MergePolicy] is the decision seam for the conflict described above: a
// login flow resolves an external (provider, subject) pair that
// [Store.FindByProviderSubject] shows is ALREADY linked to a DIFFERENT local
// account than the one the login would otherwise use. [RejectPolicy] — the
// safe default — refuses the login outright with [ErrAccountConflict]; an
// operator who has not deliberately decided how to merge two accounts should
// never have that decision made for them silently.
//
// [LinkOnlyMergePolicy] is a CONSERVATIVE reference implementation for the
// operator who explicitly wants automatic consolidation. It ONLY re-points
// the losing account's [Identity] link records onto the winning account. It
// deliberately does NOT touch sessions, consents, OAuth/refresh tokens,
// MFA/passkey enrollments, or the audit trail belonging to the losing
// account — those remain a large, orthogonal, transactional multi-store
// migration that a real deployment must design around its OWN data model
// (e.g. does the losing account's audit history get relabeled? do its active
// refresh-token families get revoked or re-issued under the winner?). This
// package does not answer that; it only guarantees the identity links
// themselves end up consistent. Callers wiring [LinkOnlyMergePolicy] MUST
// treat every OTHER store as still keyed on the losing account's id unless
// they separately migrate it.
//
// # Live login-flow wiring
//
// Password/TOTP/WebAuthn logins have no external identity to resolve. The
// stock binary does wire [NewAuthenticatorLinker] into its static and
// connection-backed OIDC federation authenticators when identity linking is
// enabled. SDK embedders and other custom Authenticators can use [Resolve] or
// the same adapter directly. A genuine conflict only arises after a separate,
// deliberate account-connect flow has created a link for one local account
// while another account authenticates with the same provider/subject pair.
package identitylink

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Status is the lifecycle state of one [Identity] link.
type Status string

const (
	// StatusActive is a currently-usable link: it counts toward login
	// resolution ([Store.FindByProviderSubject]) and the self-service
	// last-authentication-method guard.
	StatusActive Status = "active"
	// StatusRevoked marks a link the user (or an operator) unlinked. Kept in
	// the store for audit/history; [Store.ListByUser] does not return it and
	// [Store.FindByProviderSubject] does not match it.
	StatusRevoked Status = "revoked"
)

// Identity is one external identity linked to a local user account.
type Identity struct {
	// ID is the opaque per-link handle used to unlink it. Stable per link.
	ID string `json:"id"`
	// UserID is the LOCAL account this identity is linked to.
	UserID string `json:"user_id"`
	// Provider names the authenticator/IdP this identity came from (the same
	// string an AuthResult.Provider / core.User.Provider would carry, e.g.
	// "google", "github", or a federated OIDC authenticator's configured
	// Name).
	Provider string `json:"provider"`
	// Subject is the external, provider-scoped identifier (the upstream
	// `sub` claim, or the legacy local account id when this link records a
	// folded-in account rather than a federated identity).
	Subject string `json:"subject"`
	// Status is the link's current lifecycle state.
	Status Status `json:"status"`
	// LinkedAt is when the link was created.
	LinkedAt time.Time `json:"linked_at"`
	// UnlinkedAt is when the link was revoked. Zero while StatusActive.
	UnlinkedAt time.Time `json:"unlinked_at,omitzero"`
}

// Store persists per-user identity links. Implementations live in
// identitylink/<backend>/. When no Store is wired the
// self-service /me/identities surface is simply absent — byte-identical to a
// build without the feature.
type Store interface {
	// ListByUser returns userID's ACTIVE links, oldest first (never an error
	// for "none linked" — an empty slice), mirroring the ConsentStore /
	// SessionManager self-service list conventions.
	ListByUser(ctx context.Context, userID string) ([]Identity, error)

	// Link records a new active link between userID and (provider, subject).
	// Idempotent: relinking the SAME (userID, provider, subject) while it is
	// already active returns the existing Identity unchanged rather than a
	// duplicate. A pair actively owned by another user returns
	// ErrAccountConflict; implementations MUST enforce that uniqueness under
	// concurrent calls.
	Link(ctx context.Context, userID, provider, subject string) (Identity, error)

	// Unlink revokes the ACTIVE link "id" belonging to userID. Ownership is
	// enforced by the store itself: an id belonging to another user, one
	// that is already revoked, or one that never existed all return
	// ErrNotFound — the SAME response either way (oracle-safe: the caller's
	// 404 never reveals whether the id exists under someone else's account).
	Unlink(ctx context.Context, userID, id string) error

	// FindByProviderSubject looks up the ACTIVE link (if any) for a given
	// (provider, subject) pair, regardless of owner. This is the seam a
	// login flow uses to discover "this external identity is already linked
	// to SOMEONE" before deciding whether that someone is the account the
	// login is currently resolving. found is false when no active link
	// exists for the pair.
	FindByProviderSubject(ctx context.Context, provider, subject string) (Identity, bool, error)
}

// AtomicMerger is the capability LinkOnlyMergePolicy requires. The conflict
// ownership check and reassignment of every active IncomingUserID link MUST
// commit atomically; a stale conflict returns ErrAccountConflict without
// changing either account.
type AtomicMerger interface {
	MergeUserLinks(ctx context.Context, conflict Conflict) error
}

// Sentinel errors. The self-service handler maps ErrLastAuthMethod to the
// stable wire code identity_unlink_last_method (see docs/error-codes.md);
// ErrNotFound collapses to the same 404 as an unowned/unknown id.
var (
	// ErrNotFound is returned by Store.Unlink when id does not resolve to an
	// ACTIVE link owned by the given userID.
	ErrNotFound = errors.New("identitylink: not found")

	// ErrLastAuthMethod is returned by GuardUnlink (and surfaced by the
	// self-service handler as HTTP 409) when removing a link would leave the
	// account with no remaining way to authenticate.
	ErrLastAuthMethod = errors.New("identitylink: cannot unlink the last remaining authentication method")

	// ErrInvalidIdentity rejects empty local IDs, providers, or external
	// subjects before they can create ambiguous global ownership records.
	ErrInvalidIdentity = errors.New("identitylink: user, provider, and subject are required")
)

// ValidateLinkInput validates the stable identity-link key fields without
// rewriting them; provider-scoped subjects remain case-sensitive and opaque.
func ValidateLinkInput(userID, provider, subject string) error {
	if strings.TrimSpace(userID) == "" ||
		strings.TrimSpace(provider) == "" ||
		strings.TrimSpace(subject) == "" {
		return ErrInvalidIdentity
	}
	return nil
}

// ValidateConflict rejects malformed or self-conflicting merge requests.
func ValidateConflict(conflict Conflict) error {
	if err := ValidateLinkInput(conflict.IncomingUserID, conflict.Provider, conflict.Subject); err != nil {
		return err
	}
	if strings.TrimSpace(conflict.ExistingUserID) == "" ||
		conflict.ExistingUserID == conflict.IncomingUserID {
		return ErrInvalidIdentity
	}
	return nil
}

// PasswordPresenceChecker is an OPTIONAL capability a core.PasswordCredentialStore
// implementation MAY satisfy so GuardUnlink's "does this user have another
// primary authentication method" check can consult it. It exists because
// core.PasswordCredentialStore.VerifyPassword is deliberately unable to
// distinguish "no credential set" from "wrong password" (anti-enumeration —
// see AGENTS.md), so it cannot answer this question by itself.
//
// A credential store that does not implement this interface is treated as
// UNKNOWN by the self-service unlink handler, which then fails CLOSED
// (assumes no password) — a user is never SILENTLY locked out of their own
// account for want of this optional method; an operator adds it to their
// store to allow unlinking down to zero identities for password-holding
// users. See infrastructure/defaultimpl/memorystorecredential, which
// implements it.
type PasswordPresenceChecker interface {
	// HasPassword reports whether userID currently has a stored credential.
	// Unlike VerifyPassword this is a governance/guard query, not a login
	// check — no anti-enumeration timing concern applies because the caller
	// already knows userID (it is the authenticated bearer's own subject).
	HasPassword(ctx context.Context, userID string) (bool, error)
}

// GuardUnlink is the PURE, deterministic core of the "don't let a user lock
// themselves out" guard: it decides whether removing one more active link
// leaves the account with a working authentication method.
//
// activeCount is the number of ACTIVE identity links the user has BEFORE the
// removal (including the one about to be removed). hasOtherMethod reports
// whether the account has some OTHER usable primary authentication method
// (today: a local password credential, via [PasswordPresenceChecker]).
//
// Returns ErrLastAuthMethod when activeCount <= 1 (this is the user's only
// linked identity) AND hasOtherMethod is false — i.e. removing it would
// leave zero ways to log in. Returns nil (removal is safe) otherwise.
func GuardUnlink(activeCount int, hasOtherMethod bool) error {
	if activeCount <= 1 && !hasOtherMethod {
		return ErrLastAuthMethod
	}
	return nil
}
