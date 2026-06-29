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
