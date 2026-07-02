package core

import (
	"context"
	"time"
)

// RecoveryCodeStore persists single-use MFA recovery codes. When a
// user loses their TOTP device or WebAuthn authenticator, recovery
// codes serve as the backdoor — each code can be consumed once.
//
// Codes are generated as random tokens, their hashes stored. The
// plaintext codes are shown to the user exactly once (at enrollment
// confirmation). The store only ever sees the bcrypt (or SHA-256)
// hash, so a database leak doesn't expose usable recovery codes.
type RecoveryCodeStore interface {
	// Generate creates N new recovery codes for the user, returning
	// the plaintext codes (shown to the user once). Each code's hash
	// is persisted. Previous unused codes are NOT invalidated.
	Generate(ctx context.Context, userID string, n int) (codes []string, err error)

	// Consume validates and consumes a single recovery code. Returns
	// true when the code was valid and consumed. False when the code
	// is unknown or already consumed — callers MUST NOT distinguish
	// between the two (anti-enumeration).
	Consume(ctx context.Context, userID, code string) (ok bool, err error)

	// CountRemaining returns how many unused recovery codes the user
	// still has. Used by the UI to warn users when the pool is low.
	CountRemaining(ctx context.Context, userID string) (int, error)

	// RevokeAll invalidates all remaining recovery codes for the
	// user. Used when the user regenerates codes or MFA is reset.
	RevokeAll(ctx context.Context, userID string) error
}

// RecoveryCode constants.
const (
	DefaultRecoveryCodeCount = 8                                  // number of codes generated per batch
	RecoveryCodeBytes        = 16                                 // 16 bytes → 32 hex chars per code
	RecoveryCodeAlphabet     = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I/O/0/1
)

// TrustedDevice describes one "remember this device" MFA-skip grant, as
// surfaced by the self-service GET /me/devices listing. Metadata only — the
// opaque bearer token that actually authorizes the skip exists ONLY at Trust
// time (returned once) and is never retrievable again; the store holds just
// its hash, the exact RecoveryCodeStore contract above applied to a
// longer-lived, login-time credential instead of a one-shot code.
type TrustedDevice struct {
	// ID is the opaque record identifier used by the self-service DELETE and
	// by TrustedDeviceStore.Revoke. Distinct from the token: leaking the ID
	// (e.g. in a log line) grants nothing, unlike the token.
	ID     string `json:"id"`
	UserID string `json:"user_id"`
	// ClientID is the OAuth client this grant applies to. A login-time Verify
	// only succeeds for a login to the SAME client the grant was minted
	// under — trusting a device for one application can never silently widen
	// to skip MFA on every application the user happens to hold a client for.
	ClientID string `json:"client_id"`
	// Label is a caller-supplied or user-agent-derived display string (e.g.
	// "Chrome on macOS") shown in the self-service device list. Never used
	// for any security decision — purely cosmetic.
	Label string `json:"label,omitempty"`

	CreatedAt time.Time `json:"created_at,omitzero"`
	// ExpiresAt bounds how long this grant can skip MFA — see
	// DefaultTrustedDeviceTTL. There is no renew-on-use: Verify never
	// extends ExpiresAt, so a device that is never re-trusted decays on its
	// own instead of staying trusted forever.
	ExpiresAt time.Time `json:"expires_at,omitzero"`
	// LastUsedAt is the zero time until the grant's first successful Verify,
	// then the time of the most recent one — operator-facing context only
	// (e.g. flagging a grant that was minted but never actually used).
	LastUsedAt time.Time `json:"last_used_at,omitzero"`
}

// TrustedDeviceStore persists "remember this device" grants that let a
// completed MFA step-up be skipped on a LATER login from the SAME (user,
// client, device) triple — see login.Request.DeviceToken and the
// risk-scorer step-up gate that consults it.
//
// The device identity is the opaque bearer token itself, not a browser/OS
// fingerprint: Trust mints a cryptographically random token and returns it
// to the caller exactly once (mirrors how a refresh token or a recovery
// code is handed out), then persists ONLY its hash. There is deliberately
// no reversible fingerprint of the device stored anywhere — a leaked
// database row grants nothing without the still-secret plaintext token,
// and there is no raw client-supplied device-identifying data to leak in
// the first place.
type TrustedDeviceStore interface {
	// Trust mints a new grant for (userID, clientID), persists only the
	// token's hash, and returns the plaintext token (the caller is
	// responsible for presenting it back as login.Request.DeviceToken on a
	// later login — e.g. stored client-side as a long-lived cookie) plus the
	// persisted record. ttl <= 0 means the caller wants the store's own
	// default (implementations SHOULD apply DefaultTrustedDeviceTTL).
	Trust(ctx context.Context, userID, clientID, label string, ttl time.Duration) (token string, device *TrustedDevice, err error)

	// Verify reports whether token is a live, unexpired grant for
	// EXACTLY (userID, clientID). Implementations MUST NOT distinguish
	// "unknown token", "expired", "wrong user", and "wrong client" in the
	// returned bool — all four are ordinary "MFA is still required," never
	// an error surfaced to the login caller (anti-enumeration, same
	// discipline as RecoveryCodeStore.Consume). A true result updates
	// LastUsedAt best-effort; Verify NEVER extends ExpiresAt.
	Verify(ctx context.Context, userID, clientID, token string) (bool, error)

	// ListByUser returns the caller's live grants — metadata only, NEVER a
	// token or its hash — for the self-service GET /me/devices surface.
	ListByUser(ctx context.Context, userID string) ([]TrustedDevice, error)

	// Revoke removes one grant by its opaque ID, scoped to userID so a
	// cross-user revoke can never touch someone else's grant. Idempotent:
	// an unknown or already-revoked (userID, id) is a no-op, matching
	// MFAEnrollmentStore.RemoveFactor's contract (the self-service handler
	// enforces ownership up front via ListByUser, same as the MFA-factor
	// delete handler).
	Revoke(ctx context.Context, userID, id string) error

	// RevokeAll removes every grant for a user and returns the count
	// removed. Called on password change and other account-compromise
	// signals so a stolen "remember this device" grant can't outlive the
	// credential it was minted under.
	RevokeAll(ctx context.Context, userID string) (int, error)
}

// TrustedDevice constants.
const (
	// TrustedDeviceTokenBytes mirrors oauth refresh-token entropy (32 bytes /
	// 256 bits): a trusted-device token is a bearer-equivalent MFA-skip
	// credential and must resist brute force at the same strength.
	TrustedDeviceTokenBytes = 32

	// DefaultTrustedDeviceTTL bounds how long a single "remember this
	// device" grant can skip MFA before the user has to complete step-up
	// again. 30 days balances convenience (most legitimate return visits
	// land inside the window) against blast radius: a device is NEVER
	// trusted permanently — a single completed-MFA moment can extend
	// convenience for weeks, never forever.
	DefaultTrustedDeviceTTL = 30 * 24 * time.Hour
)
