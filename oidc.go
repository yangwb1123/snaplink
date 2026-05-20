package sso

import (
	"context"
	"slices"
	"time"
)

// hasOpenIDScope reports whether the slice contains the OIDC "openid"
// trigger scope. Tiny wrapper kept to localize the literal so changes
// to scope semantics stay in one place.
func hasOpenIDScope(scopes []string) bool {
	return slices.Contains(scopes, ScopeOpenID)
}

// IDTokenRequest carries the inputs an IDTokenIssuer needs to mint an
// OpenID Connect Core 1.0 ID Token. The server populates this from the
// successful authentication context — Nonce is the value the relying
// party supplied at /auth/login and is mandatory for OIDC implicit /
// hybrid flows; AMR + ACR carry the strength signal (which authenticator
// + how strong) so downstream relying parties can apply step-up policy.
type IDTokenRequest struct {
	Subject  string            // user identifier (sub claim)
	Audience string            // client_id of the relying party (aud claim)
	Nonce    string            // echoed nonce per OIDC §2 — empty omits the claim
	AuthTime time.Time         // when the user was actually authenticated
	AMR      []string          // Authentication Methods References (e.g. ["pwd", "mfa"])
	ACR      string            // Authentication Context Class Reference
	AZP      string            // Authorized Party — used when aud is multi-valued
	Claims   map[string]string // extra OIDC-defined claims (email, name, ...)
	TTL      time.Duration     // 0 = let the issuer pick (typically same as access TTL)

	// SID is the OIDC Core §2 session identifier. When populated,
	// the issued ID token carries a `sid` claim — RPs that store
	// the session id on first login can match it to a later
	// back-channel logout_token's sid for surgical session
	// invalidation (vs the coarser "kill every session for this
	// sub" fallback). Empty omits the claim.
	SID string
}

// IDTokenIssuer mints OIDC ID Tokens. Optional SPI — when the server
// has no issuer wired, /auth/login and /token responses omit the
// `id_token` field even when the request carries the "openid" scope.
//
// The default implementation (defaultimpl.Ed25519JWTIssuer) implements
// this interface directly so deployments can share one signing key
// between access tokens and ID tokens. Pass the same instance to both
// WithTokenIssuer and WithIDTokenIssuer for that wiring.
type IDTokenIssuer interface {
	IssueIDToken(ctx context.Context, req *IDTokenRequest) (string, error)
}
