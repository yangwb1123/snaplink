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
func (r *PasswordResetToken) IsExpired() bool { return time.Now().After(r.ExpiresAt) }

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

// ErrResetTokenNotFound is the sentinel Consume returns when a token is missing,
// expired, or already consumed. Callers MUST collapse all three to a single
// reset_invalid wire response (anti-enumeration / oracle-safe).
var ErrResetTokenNotFound = errors.New("sso: password reset token not found or expired")
