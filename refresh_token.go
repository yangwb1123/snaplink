package sso

import (
	"context"
	"errors"
	"time"
)

// RefreshToken is the server-side record bound to a single OAuth 2.0
// refresh token. The handleToken refresh_token branch consumes one of
// these to mint a new access token; consumption is one-shot (rotation),
// so a presented-twice refresh token is always rejected as invalid_grant.
//
// ClientID is captured at issue time so the token endpoint can reject
// presentation by any other client (RFC 6749 §6: refresh tokens MUST be
// bound to the client they were issued to). Scopes carry the original
// grant so refresh requests can narrow scope but never expand it.
//
// Provider + Attributes are re-stamped into the new access token's
// claims so a refreshed token carries the same subject metadata as the
// original — downstream consumers see no difference between the first
// access token and its refreshes.
type RefreshToken struct {
	UserID     string
	ClientID   string
	Provider   string            // authentication method used at original issue
	Scopes     []string          // original grant; new tokens MUST be a subset
	Attributes map[string]string // forwarded into the new token subject's Claims
	IssuedAt   time.Time
	ExpiresAt  time.Time

	// FamilyID groups every refresh token that descends from a single
	// authorization event (login, authz_code exchange, or device flow).
	// Rotation propagates the FamilyID unchanged, so a 30-day chain of
	// rotations all share one FamilyID. On reuse detection (OAuth
	// Security BCP §4.13), the server kills the entire family — not
	// just the replayed leaf — invalidating any active token an
	// attacker might have already obtained from a stolen refresh
	// token. Empty FamilyID means the store doesn't track families.
	FamilyID string
}

// IsExpired reports whether the refresh token's lifetime has elapsed.
// Stores SHOULD also enforce TTL on their side (expired tokens are
// indistinguishable from missing for security reasons), but this helper
// lets the handler short-circuit a known-stale lookup.
func (r *RefreshToken) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}

// RefreshTokenStore persists OAuth 2.0 refresh tokens. Implementations
// MUST enforce single-use rotation semantics: Consume returns the stored
// RefreshToken AND deletes it atomically, so a token presented twice
// (replay or family-reuse attack) always fails the second time.
//
// Implementations SHOULD also enforce TTL expiry (expired tokens are
// indistinguishable from missing for security reasons).
//
// The store is intentionally a separate SPI from AuthCodeStore even
// though the shapes are similar: refresh-token lifetimes are measured
// in days/weeks vs. authorization-code minutes, and rotation semantics
// differ (auth codes always one-shot; refresh tokens are one-shot per
// rotation but the token *family* persists across many rotations).
type RefreshTokenStore interface {
	// Issue persists token with the supplied RefreshToken payload.
	// Implementations are free to reject duplicate tokens — generators
	// MUST produce cryptographically random values to make collisions
	// improbable.
	Issue(ctx context.Context, token string, info *RefreshToken) error

	// Consume atomically removes and returns the token's payload.
	// Returns ErrRefreshTokenNotFound when the token is unknown,
	// expired, or already consumed. The three cases are deliberately
	// indistinguishable to callers to limit oracle leakage.
	Consume(ctx context.Context, token string) (*RefreshToken, error)
}

// ErrRefreshTokenNotFound is returned by RefreshTokenStore.Consume when
// the token is missing, expired, or already consumed. The token endpoint
// maps it to OAuth 2.0's `invalid_grant` error so all three failure
// cases look identical from the wire.
var ErrRefreshTokenNotFound = errors.New("sso: refresh token not found or expired")

// RefreshTokenInspector is an OPTIONAL extension to RefreshTokenStore
// that lets the introspection (RFC 7662) and revocation (RFC 7009)
// endpoints peek / delete refresh tokens without going through the
// single-use rotation contract of Consume.
//
// Implement it on the concrete store type when the backend can answer
// non-destructive queries. Without it, /token/introspect and
// /token/revoke fall back to access-token-only behavior.
type RefreshTokenInspector interface {
	// Inspect returns the stored RefreshToken without consuming it.
	// Returns ErrRefreshTokenNotFound for unknown / expired tokens.
	Inspect(ctx context.Context, token string) (*RefreshToken, error)

	// Delete removes the token without going through Consume's rotation
	// path. Idempotent: deleting an unknown token returns nil (matches
	// RFC 7009 §2.2 which says servers MUST respond as if the token had
	// been revoked even if it wasn't recognized).
	Delete(ctx context.Context, token string) error
}

// RefreshTokenSubjectIndex is an OPTIONAL extension for backends that
// can enumerate tokens by (subject, client). Used by the "logout
// everywhere" endpoint /token/revoke-all to kill every refresh token
// a user holds for a given client without the user having to present
// each one.
//
// Returns the count of deleted entries (useful for audit). Backends
// that can't enumerate efficiently should NOT implement this — the
// fallback is per-token revocation via /token/revoke, and operators
// who need bulk revocation can layer a custom store on top.
type RefreshTokenSubjectIndex interface {
	DeleteAllForSubject(ctx context.Context, userID, clientID string) (int, error)
}

// RefreshTokenFamilyTracker is an OPTIONAL extension that turns on
// OAuth Security BCP §4.13/§4.14 family-wide reuse detection. Stores
// that implement it MUST:
//
//  1. Remember the FamilyID of every refresh token long enough to
//     detect a replayed-after-rotation presentation. The minimum
//     window is the refresh token TTL; longer is better for audit.
//  2. Treat a Consume of a known-but-already-consumed token as a
//     reuse signal — return ErrRefreshTokenReused so the handler can
//     kill the whole family via DeleteFamily.
//
// Without this extension, reuse fails as plain invalid_grant (the
// stolen leaf can't be redeemed twice) but any active token already
// minted by an attacker who rotated first stays alive until expiry.
// With it, the FIRST replay of any descendant invalidates every
// sibling — the attacker's window collapses.
type RefreshTokenFamilyTracker interface {
	// DeleteFamily removes every refresh token (active or consumed)
	// sharing the supplied FamilyID. Returns the count of active
	// tokens that were killed; consumed-only entries are bookkeeping
	// for reuse detection and aren't counted. Idempotent — deleting
	// an unknown family returns (0, nil).
	DeleteFamily(ctx context.Context, familyID string) (int, error)
}

// ErrRefreshTokenReused is returned by stores that implement
// RefreshTokenFamilyTracker when Consume sees a token that was
// previously consumed within the family-tracking window. The handler
// maps it to invalid_grant on the wire (per RFC 6749 §5.2 +
// oracle-leak hardening) but ALSO kills the entire family before
// returning, so an attacker who replays a stolen leaf can't continue
// rotating from a sibling they already obtained.
var ErrRefreshTokenReused = errors.New("sso: refresh token already consumed (reuse detected)")
