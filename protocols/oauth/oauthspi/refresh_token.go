package oauthspi

import (
	"context"
	"encoding/json"
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

	// Resources carries RFC 8707 resource indicators captured at
	// the original authorization. The rotation grant stamps these
	// into the new access token's aud claim so a refresh of a
	// resource-scoped token produces another resource-scoped
	// token without the caller having to re-supply the parameter.
	Resources []string

	// AuthorizationDetails preserves the RFC 9396 grant captured
	// at the original authorization (login, auth_code exchange,
	// or device flow). Rotation re-stamps it into the new access
	// token's `authorization_details` claim so the binding
	// survives the chain — without this, refreshed tokens would
	// silently lose fine-grained authorization the user already
	// consented to. Preserved as raw JSON so extension fields
	// pass through unchanged; empty = no RAR on the original
	// grant. Stores that don't know about RAR can ignore the
	// field — propagation degrades to "lost on rotation" exactly
	// as the v1 behavior was.
	AuthorizationDetails json.RawMessage

	// SID is the OIDC Core §2 session identifier captured at the
	// original authorization. Rotation re-stamps it into the new
	// access + id tokens so back-channel logout's `sid` claim
	// matches across the entire token family — RPs that bound
	// local state to the sid see continuity across refreshes.
	// Empty = no session anchor (the rotation simply omits the
	// sid claim on emitted tokens).
	SID string

	// Amr / Acr / AuthTime capture the ORIGINAL authentication event so a
	// refreshed access token keeps the same amr/acr/auth_time as the first
	// token issued (RFC 9068 §2.2; AGENTS.md §3 "Refresh: propagates original
	// AMR without resetting AuthTime"). Rotation propagates all three
	// UNCHANGED. Without them a rotation silently downgrades a step-up/MFA
	// session: a resource server doing RFC 9470 step-up on amr/acr would
	// reject or down-trust EVERY post-refresh request despite a live MFA
	// authentication. Empty Amr falls back to Provider at rotation; empty Acr
	// omits the acr claim; a zero AuthTime omits auth_time. Stores that
	// predate these fields degrade to the v1 "lost on rotation" behavior.
	Amr      []string
	Acr      string
	AuthTime time.Time

	// ConfirmationJKT is the RFC 9449 DPoP JKT this refresh token is bound to.
	// Empty means unbound (no DPoP was presented at issue time). When non-empty,
	// the rotation handler MUST reject any refresh-grant request whose presented
	// DPoP proof does not carry the same key — a stolen refresh token can't be
	// redeemed with an attacker-controlled key.
	ConfirmationJKT string `json:"confirmation_jkt,omitempty"`
}

// RefreshAuthContext groups the original authentication-event claims threaded
// into IssueRefreshToken so they can be persisted on the RefreshToken record
// and propagated unchanged across rotation (RFC 9068 §2.2). Grouping them keeps
// the already-long issue signature from gaining one positional parameter per
// claim. A zero value (no AMR/ACR/AuthTime) reproduces the pre-feature
// behavior exactly.
type RefreshAuthContext struct {
	AMR      []string
	ACR      string
	AuthTime time.Time
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

// RefreshTokenSubjectCounter is an OPTIONAL companion to
// RefreshTokenSubjectIndex that counts a subject's tokens for a client
// WITHOUT deleting them. It lets callers preview the blast radius of a
// bulk revocation — e.g. a GDPR erasure dry-run — since DeleteAllForSubject
// is destructive and gives no count without acting. Empty clientID counts
// across every client, mirroring DeleteAllForSubject's semantics.
type RefreshTokenSubjectCounter interface {
	CountForSubject(ctx context.Context, userID, clientID string) (int, error)
}

// RefreshTokenClientPurger is an OPTIONAL extension for backends that can
// enumerate tokens by client. It powers tenant-level active revocation: when
// an admin suspends a tenant, the server purges the refresh tokens of every
// client in that tenant so already-issued tokens can't be silently re-used
// after suspension. The suspension check (WithTenantSuspensionCheck) only
// lazily rejects a token on its next validate — and only when wired — and
// never touches refresh tokens; this is the proactive companion.
//
// Returns the count of deleted entries (for audit). Backends that can't
// enumerate by client should NOT implement this — the fallback is the
// existing per-subject (RefreshTokenSubjectIndex) and per-token
// (RefreshTokenInspector.Delete) revocation paths.
type RefreshTokenClientPurger interface {
	// DeleteAllForClient removes every refresh token bound to clientID
	// across all subjects. Returns the count deleted. Empty clientID MUST
	// be a no-op, not a wildcard — wiping the whole store on a blank
	// argument would be a footgun.
	DeleteAllForClient(ctx context.Context, clientID string) (int, error)
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

// RefreshTokenRotationLimiter is an OPTIONAL extension that caps how
// FAST a single refresh-token FAMILY may rotate. It closes the gap left
// by RefreshTokenFamilyTracker: family-reuse detection only fires when
// the SAME leaf is presented twice, so an attacker who steals a refresh
// token and rotates ONCE — while the victim keeps rotating the original
// chain — produces TWO live, diverging leaves whose siblings are never
// double-presented. Both parties rotating the same family at a combined
// rate above any one client's normal cadence is the classic tell; a
// per-family velocity cap turns that tell into an actionable signal.
//
// The limiter is keyed by FamilyID and counts rotations within a
// sliding-or-fixed window. The handler calls RecordRotation AFTER the
// successful single-use Consume of the presented token and BEFORE
// issuing the rotated token. On windowExceeded the handler treats the
// family as compromised — exactly the reuse-class response — and kills
// it via the existing DeleteFamily path.
//
// Implement it on the concrete store type (type-asserted like
// RefreshTokenInspector / RefreshTokenFamilyTracker). Stores that don't
// implement it, or a limiter that's configured with a non-positive cap,
// are byte-identical to a build without the feature.
//
// FAIL-OPEN contract: a RecordRotation transport/store error MUST NOT
// block a legitimate refresh. The velocity cap is a defense layer, not a
// correctness gate (the opposite of family-reuse fail-closed) — the
// handler logs the error and lets the rotation proceed, exactly like the
// JTI-replay default and ratelimit.Allow. An impl MUST therefore return
// windowExceeded=false alongside a non-nil err on any store failure (never
// fail closed by reporting the window exceeded on an error path).
//
// (A Redis peer — out of scope for the in-core change — can satisfy this
// with an atomic INCR + conditional EXPIRE per FamilyID, the same
// fixed-window primitive as ratelimit.Allow; left shaped for that.)
type RefreshTokenRotationLimiter interface {
	// RecordRotation records one rotation of familyID and reports the
	// post-increment count within the current window plus whether the
	// configured per-window cap was exceeded. An empty familyID is a
	// no-op: (0, false, nil) — a family-untracked store can't velocity-
	// limit, mirroring DeleteFamily's empty-id contract.
	RecordRotation(ctx context.Context, familyID string) (count int, windowExceeded bool, err error)
}
