package core

import (
	"context"
	"errors"
	"time"
)

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
func (e *EmailChangeToken) IsExpired() bool { return time.Now().After(e.ExpiresAt) }

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

// ErrEmailChangeTokenNotFound is the sentinel Consume returns when a token is
// missing, expired, or already consumed. Callers MUST collapse all three to a
// single email_change_invalid wire response.
var ErrEmailChangeTokenNotFound = errors.New("sso: email change token not found or expired")
