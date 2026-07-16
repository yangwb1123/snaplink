package core

import (
	"context"
	"errors"
	"time"
)

// PasswordResetToken is a single-use, short-TTL token that authorizes an
// UNAUTHENTICATED password reset (the forgot-password flow). It is bound to a
// userID at issue time, so a token can only reset the credential of the user it
// was minted for — never an arbitrary account. Delivered out-of-band (email /
// SMS) and consumed exactly once at /auth/reset-password.
type PasswordResetToken struct {
	Token     string    // the opaque token value (store primary key)
	UserID    string    // the user this reset is bound to
	ExpiresAt time.Time // absolute expiry
}

// IsExpired reports whether the token has passed its expiry.
func (r *PasswordResetToken) IsExpired() bool { return time.Since(r.ExpiresAt) > 0 }

// PasswordResetStore persists single-use password-reset tokens. When nil (not
// wired), the forgot-password flow is disabled — byte-identical to a build
// without it. memory + sqlite peers ship in defaultimpl + defaultimpl/sqlite.
// Mirrors DeviceSecretStore: Issue then a single destructive Consume.
type PasswordResetStore interface {
	// Issue stores a new token (keyed by rt.Token).
	Issue(ctx context.Context, rt *PasswordResetToken) error

	// Consume atomically retrieves AND deletes the token. Missing, expired, or
	// already-consumed all return ErrResetTokenNotFound (single response —
	// oracle-safe; the reset handler collapses it to one reset_invalid). The
	// single-use delete is what stops a replayed reset token.
	Consume(ctx context.Context, token string) (*PasswordResetToken, error)
}

// PasswordResetRevoker is the OPTIONAL admin-plane extension to
// PasswordResetStore (mirrors DeviceSecretRevoker). A store that implements it
// lets a helpdesk invalidate every outstanding reset token for a user without
// waiting for TTL expiry — the recovery path when a token was sent to the wrong
// address, leaked, or the user lost access to the delivery channel. The admin
// endpoint type-asserts this and returns 501 when the wired store doesn't
// support it. memory + sqlite peers implement it.
type PasswordResetRevoker interface {
	// RevokeByUser deletes all pending reset tokens bound to userID and returns
	// the count removed. Idempotent: a user with no pending tokens returns 0.
	RevokeByUser(ctx context.Context, userID string) (int, error)
}

// PasswordResetLister is the OPTIONAL admin-plane read extension: it lets a
// helpdesk see whether a user has outstanding reset tokens and when they expire
// (e.g. "I didn't get the reset email"), WITHOUT exposing token material — the
// admin endpoint projects only expiry, never the token value. 501 when the wired
// store doesn't implement it. memory + sqlite peers implement it.
type PasswordResetLister interface {
	// ListByUser returns all pending reset tokens bound to userID. Expired tokens
	// MAY be included (the handler flags them); callers MUST NOT surface the
	// token value.
	ListByUser(ctx context.Context, userID string) ([]*PasswordResetToken, error)
}

// ErrResetTokenNotFound is the sentinel Consume returns when a token is missing,
// expired, or already consumed. Callers MUST collapse all three to a single
// reset_invalid wire response (anti-enumeration / oracle-safe).
var ErrResetTokenNotFound = errors.New("sso: password reset token not found or expired")

// -----------------------------------------------------------------------------
// PasswordCredentialStore extensions. Co-located here (not in spi.go, which
// declares PasswordCredentialStore itself) purely to stay under spi.go's
// 500-line budget (AGENTS.md §0.1) — thematically this is still
// password-credential SPI, same family as PasswordResetStore above.

// PasswordAgeReader is an OPTIONAL extension a PasswordCredentialStore MAY
// satisfy to report when userID's CURRENT password credential was last set
// (via SetPassword or SetPasswordHash). It backs the login-time
// PasswordPolicyConfig.MaxAgeDays enforcement (interfaces/sso
// rejectExpiredPassword); a store that does not implement it — or that
// errors — makes that policy dimension a silent no-op (fail-open) for its
// users, mirroring every other policy gate whose backing signal is
// unavailable (AGENTS.md §3 Fail Modes). Callers type-assert. NOT folded into
// the base PasswordCredentialStore interface: not every deployment tracks
// credential age, and this keeps the core SPI narrow (mirrors
// PasswordHashImporter above).
//
// Never called on the anti-enumeration path: by the time a caller invokes
// this, the password has ALREADY verified via VerifyPassword, so there is no
// timing/oracle concern here the way there is for an unknown-user lookup.
type PasswordAgeReader interface {
	// PasswordChangedAt returns the time userID's current credential was set.
	// Returns a non-nil error when unknown/unavailable — the caller MUST
	// treat that as "can't determine, don't enforce" rather than treating a
	// zero time as "always expired".
	PasswordChangedAt(ctx context.Context, userID string) (time.Time, error)
}

// PasswordCredentialDeleter is an OPTIONAL extension a PasswordCredentialStore
// MAY satisfy to actually remove a stored credential rather than merely
// overwrite it. The admin user-CRUD delete path (DELETE
// /api/v1/admin/users/:id) type-asserts for this and calls it BEST-EFFORT
// after the user row itself is gone — the same "unsupported ⇒ silently skip"
// shape the optional UserProvider uniqueness-check extensions use. A store
// that doesn't implement it simply leaves an orphaned, unreachable hash
// behind (unreachable because the userID it was keyed on no longer resolves
// to a user) rather than failing the delete.
type PasswordCredentialDeleter interface {
	// DeletePassword removes userID's stored credential, if any. A missing
	// credential is NOT an error (idempotent, matching SetPassword's
	// create-or-replace shape).
	DeletePassword(ctx context.Context, userID string) error
}

// PasswordHistoryStore persists a bounded ring of a user's recent passwords
// so a PasswordPolicyConfig.MaxHistory > 0 policy can reject reuse at
// password-change time (POST /me/password, POST /auth/reset-password — see
// interfaces/sso.WithPasswordHistoryStore). Both methods take the PLAINTEXT
// candidate: hashing/comparison is entirely the store's own concern,
// deliberately decoupled from PasswordCredentialStore's own hash-at-rest, so
// a history store can be backed by a different scheme or swapped
// independently. Optional: when nil (not wired), no history is enforced —
// byte-identical to a build without the feature.
type PasswordHistoryStore interface {
	// Record adds newPassword to userID's history ring, evicting the oldest
	// entry once at capacity. Called AFTER a password change already
	// succeeded; implementations should treat this as best-effort bookkeeping,
	// not a step that can roll back the change.
	Record(ctx context.Context, userID, newPassword string) error

	// CheckHistory reports whether newPassword matches any password
	// currently retained in userID's history ring. Called BEFORE accepting
	// a password change.
	CheckHistory(ctx context.Context, userID, newPassword string) (bool, error)
}
