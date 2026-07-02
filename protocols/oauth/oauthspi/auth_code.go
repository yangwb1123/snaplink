package oauthspi

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// AuthCode is the server-side record bound to a single OAuth 2.0
// authorization code. The handleToken authorization_code branch consumes
// one of these to mint an access token; consumption is one-shot.
//
// RedirectURI is captured at issue time so the token endpoint can verify
// the exchange request supplies the same value (RFC 6749 §4.1.3). Nonce
// is stored for the OIDC ID Token nonce-binding requirement; the server
// passes it back unchanged to the issuer (future OIDC work).
//
// CodeChallenge + CodeChallengeMethod capture the PKCE (RFC 7636) binding
// when a public client opts in. When CodeChallenge is empty, PKCE is
// skipped at exchange entirely — backwards compatible with confidential
// clients that don't use PKCE. When non-empty, the exchange MUST present
// a code_verifier that derives to this challenge under the named method;
// failure maps to invalid_grant per RFC 7636 §4.6.
type AuthCode struct {
	UserID      string
	ClientID    string
	RedirectURI string
	Scopes      []string
	Nonce       string
	Provider    string            // authentication method used at issue time
	Attributes  map[string]string // forwarded into the token subject's Claims

	// AuthTime is when the end user actually authenticated at /auth/login,
	// captured when this code was issued. The token endpoint stamps it into
	// the minted access + id token `auth_time` claim so a code redeemed
	// seconds-to-minutes later still reports the true authentication moment
	// (OIDC Core §2) rather than the exchange time. Zero = the store didn't
	// persist it (or a pre-upgrade code) → the exchange falls back to now.
	AuthTime            time.Time
	CodeChallenge       string   // PKCE challenge captured at issue (empty = no PKCE)
	CodeChallengeMethod string   // PKCE method: "S256" | "plain"
	Resources           []string // RFC 8707 resource indicators (target audiences)

	// AuthMethods (the RFC 8176 amr tags the authenticator recorded) and
	// ACR (the satisfied AuthResult.AchievedACR) capture authentication
	// strength at issue so the /token exchange replays them into the minted
	// token's amr/acr — instead of collapsing amr to the provider id and
	// dropping acr. Empty AuthMethods → the exchange falls back to the
	// provider id; empty ACR → the acr claim is omitted.
	AuthMethods []string
	ACR         string

	// AuthorizationDetails carries the RFC 9396 array of
	// fine-grained authorization elements verbatim from the
	// authorization request to the token exchange. Preserved as
	// raw JSON so type-specific extensions don't need to be
	// modeled in this SDK. Empty = no authorization_details on
	// the eventual access token.
	AuthorizationDetails json.RawMessage

	// SID is the OIDC Core §2 session identifier captured at
	// /auth/login (the active SessionManager session ID). The
	// /token authorization_code grant re-stamps it into the
	// minted access + refresh tokens so the entire token chain
	// shares one sid — RPs that bound state to the sid at first
	// id_token receipt can correlate it across the back-channel
	// logout. Empty = no session anchor.
	SID string

	// ConfirmationJKT is the RFC 9449 §10 DPoP JWK thumbprint this
	// authorization code is bound to, captured when the client presents a
	// DPoP proof AT /auth/login (the authorization step) — distinct from
	// the access/refresh token cnf.jkt binding, which is derived from
	// whatever proof arrives separately at the /token EXCHANGE. Empty means
	// unbound (no DPoP was presented at issue time); the exchange skips the
	// gate entirely, exactly like the pre-feature behavior. When non-empty,
	// the authorization_code grant MUST reject an exchange whose presented
	// DPoP proof key doesn't match — otherwise an attacker who intercepts a
	// code minted for one client's DPoP key could redeem it under a key of
	// their own choosing. A mismatch collapses to the SAME invalid_grant as
	// every other AuthCode failure (oracle-leak hardening, AGENTS.md §3) —
	// it must never surface as a distinguishable error.
	ConfirmationJKT string

	ExpiresAt time.Time
}

// IsExpired reports whether the code's lifetime has elapsed. Callers that
// retrieve an AuthCode SHOULD check this even though Consume() already
// does — it lets a custom store skip the round trip when its own TTL
// already cleared the entry.
func (c *AuthCode) IsExpired() bool {
	return time.Since(c.ExpiresAt) > 0
}

// AuthCodeStore persists short-lived OAuth 2.0 authorization codes.
// Implementations MUST enforce single-use semantics: Consume returns the
// stored AuthCode AND deletes it atomically. Re-consuming an already-
// consumed code returns ErrAuthCodeNotFound.
//
// Implementations SHOULD also enforce TTL expiry (expired codes are
// indistinguishable from missing for security reasons).
type AuthCodeStore interface {
	// Issue persists code with the supplied AuthCode payload. Implementations
	// are free to reject duplicate codes — generators MUST produce
	// cryptographically random values to make collisions improbable.
	Issue(ctx context.Context, code string, info *AuthCode) error

	// Consume atomically removes and returns the code's payload. Returns
	// ErrAuthCodeNotFound when the code is unknown, expired, or already
	// consumed. The three cases are deliberately indistinguishable to
	// callers to limit oracle leakage.
	Consume(ctx context.Context, code string) (*AuthCode, error)
}

// ErrAuthCodeNotFound is returned by AuthCodeStore.Consume when the code
// is missing, expired, or already consumed. The token endpoint maps it
// to OAuth 2.0's `invalid_grant` error so all three failure cases look
// identical from the wire.
var ErrAuthCodeNotFound = errors.New("sso: authorization code not found or expired")
