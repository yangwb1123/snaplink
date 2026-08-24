package core

import (
	"context"
	"errors"
	"time"
)

// Invitation is a single-use, emailed credential that grants org (tenant)
// membership to a recipient. An org/admin mints one bound to a target email,
// tenant, and the TenantRole to grant on accept; the opaque Token is delivered
// out-of-band (email) and redeemed exactly once. Redemption is what creates the
// membership edge, so the token IS a live credential — it MUST NOT be serialized
// in any API response (the Token json tag is "-"); only its non-secret metadata
// (tenant, email, role, expiry) is safe to expose to an admin roster view.
type Invitation struct {
	Token     string     `json:"-"` // opaque token value (store primary key); NEVER serialized — it is a live credential
	TenantID  string     `json:"tenant_id"`
	Email     string     `json:"email"`
	Role      TenantRole `json:"role"` // org standing to grant on accept
	ExpiresAt time.Time  `json:"expires_at"`
}

// IsExpired reports whether the invitation has passed its expiry.
func (i *Invitation) IsExpired() bool { return time.Since(i.ExpiresAt) > 0 }

// InvitationStore persists single-use org-invitation tokens. When nil (not
// wired), org invitations are disabled — byte-identical to a build without them.
// memory + sqlite peers ship in defaultimpl + defaultimpl/sqlite. Mirrors the
// other single-use credential stores: Issue then a destructive Consume.
type InvitationStore interface {
	// Issue stores a new invitation (keyed by inv.Token).
	Issue(ctx context.Context, inv *Invitation) error

	// Consume atomically retrieves AND deletes the invitation. Missing, expired,
	// or already-consumed all return ErrInvitationNotFound (single response —
	// oracle-safe; the accept handler collapses all three to one response). The
	// single-use delete is what stops a replayed invitation.
	Consume(ctx context.Context, token string) (*Invitation, error)

	// ListByTenant returns the pending invitations for an org (admin roster view).
	// Implementations MAY include expired rows; callers MUST NOT surface the token
	// value (the Token json tag enforces this on the wire).
	ListByTenant(ctx context.Context, tenantID string) ([]*Invitation, error)

	// Revoke deletes ALL pending invitations for (tenantID, email). The admin
	// roster identifies an invitation by recipient email — the token is a live
	// credential (json:"-") and is never surfaced — and re-sends can leave
	// multiple live tokens for one recipient, so revocation is a bulk delete.
	// Idempotent: nothing pending is a no-op (no pending-invitation oracle).
	Revoke(ctx context.Context, tenantID, email string) error
}

// ErrInvitationNotFound is the sentinel Consume returns when an invitation is
// missing, expired, or already consumed. Callers MUST collapse all three to a
// single wire response (anti-enumeration / oracle-safe).
var ErrInvitationNotFound = errors.New("sso: invitation not found or expired")

// --- Sibling single-use self-service credential stores ---
//
// EmailChangeToken / EmailVerificationToken (and their stores) are the same
// family as Invitation — single-use, short-TTL tokens delivered out-of-band
// and consumed destructively. They share this file (with Invitation) because
// shared/core is at its frozen per-directory file ceiling; each store's
// docstring names its memory + sqlite peers.

// EmailChangeToken is a single-use, short-TTL token authorizing a verified
// email change for an AUTHENTICATED user. Bound to (userID, newEmail) at issue
// time and delivered to the NEW address — consuming it proves the user controls
// that address, which is why PATCH /me deliberately refuses email edits and
// routes them through this flow instead.
type EmailChangeToken struct {
	Token     string    // opaque token value (store primary key)
	UserID    string    // the user changing their email
	NewEmail  string    // the address being verified + committed
	ExpiresAt time.Time // absolute expiry
}

// IsExpired reports whether the token has passed its expiry.
func (e *EmailChangeToken) IsExpired() bool { return time.Since(e.ExpiresAt) > 0 }

// EmailChangeStore persists single-use email-change verification tokens. When
// nil (not wired), the verified-email-change flow is disabled — byte-identical
// to a build without it. memory + sqlite peers ship in defaultimpl. Mirrors
// PasswordResetStore: Issue then a single destructive Consume.
type EmailChangeStore interface {
	// Issue stores a new token (keyed by tok.Token).
	Issue(ctx context.Context, tok *EmailChangeToken) error

	// Consume atomically retrieves AND deletes the token. Missing, expired, or
	// already-consumed all return ErrEmailChangeTokenNotFound (single response —
	// oracle-safe; the verify handler collapses it to one email_change_invalid).
	Consume(ctx context.Context, token string) (*EmailChangeToken, error)
}

// EmailChangeRevoker is the OPTIONAL admin-plane extension to EmailChangeStore
// (mirrors PasswordResetRevoker). A store that implements it lets a helpdesk
// invalidate every pending email-change token for a user — the recovery path
// for a token sent to the wrong address or an email-ownership dispute. The admin
// endpoint type-asserts this and returns 501 when unsupported. memory + sqlite
// peers implement it.
type EmailChangeRevoker interface {
	// RevokeByUser deletes all pending email-change tokens bound to userID and
	// returns the count removed. Idempotent: no pending tokens returns 0.
	RevokeByUser(ctx context.Context, userID string) (int, error)
}

// EmailChangeLister is the OPTIONAL admin-plane read extension (mirrors
// PasswordResetLister): a helpdesk sees a user's pending email-change tokens and
// their target address + expiry without exposing the token value. 501 when the
// wired store doesn't implement it. memory + sqlite peers implement it.
type EmailChangeLister interface {
	// ListByUser returns all pending email-change tokens bound to userID. The
	// handler surfaces only new_email + expiry, never the token value.
	ListByUser(ctx context.Context, userID string) ([]*EmailChangeToken, error)
}

// ErrEmailChangeTokenNotFound is the sentinel Consume returns when a token is
// missing, expired, or already consumed. Callers MUST collapse all three to a
// single email_change_invalid wire response.
var ErrEmailChangeTokenNotFound = errors.New("sso: email change token not found or expired")

// EmailVerificationToken is a single-use, short-TTL token authorizing signup
// email verification. Bound to (Username, Email) at issue time and delivered
// to the target address — consuming it before user creation proves the
// registrant controls that email.
type EmailVerificationToken struct {
	Token        string    // SHA-256 hash of the raw token (store primary key)
	Username     string    // the desired username at signup
	Email        string    // the address being verified
	PasswordHash string    // bcrypt hash of the signup password; set at issue, consumed at verify
	ExpiresAt    time.Time // absolute expiry
}

// IsExpired reports whether the token has passed its expiry.
func (e *EmailVerificationToken) IsExpired() bool { return time.Since(e.ExpiresAt) > 0 }

// EmailVerificationStore persists single-use signup email-verification tokens.
// Issue stores the SHA-256 hash as the key; Consume atomically retrieves AND
// deletes the token by SHA-256 hash. Missing, expired, or already-consumed all
// return ErrVerificationTokenNotFound (oracle-safe).
type EmailVerificationStore interface {
	// Issue stores a new token (keyed by tok.Token — the SHA-256 hash).
	Issue(ctx context.Context, tok *EmailVerificationToken) error

	// Consume atomically retrieves AND deletes the token by its SHA-256 hash.
	// Returns ErrVerificationTokenNotFound on any failure.
	Consume(ctx context.Context, token string) (*EmailVerificationToken, error)
}

// EmailVerificationRevoker is an OPTIONAL extension of EmailVerificationStore.
// When implemented, it allows the signup handler to cancel any existing pending
// token for a username before issuing a new one — prevents last-writer-wins
// races where concurrent duplicate registrations strand the earlier token.
// memory + sqlite peers implement it.
type EmailVerificationRevoker interface {
	// RevokeByUsername deletes any pending token for username. Idempotent;
	// returns 0 and nil when no token exists.
	RevokeByUsername(ctx context.Context, username string) (int, error)
}

// ErrVerificationTokenNotFound is the sentinel Consume returns when a token is
// missing, expired, or already consumed. Callers MUST collapse all cases to a
// single verification_invalid wire response.
var ErrVerificationTokenNotFound = errors.New("sso: email verification token not found or expired")
