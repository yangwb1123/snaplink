package oidc

import (
	"context"
	"time"
)

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

	// AccessToken, when non-empty, is the access_token value returned in
	// the SAME response as this id_token. The issuer then stamps the OIDC
	// Core §3.1.3.6 `at_hash` claim (base64url of the left-most half of
	// the access_token's hash, the hash chosen by the id_token's signing
	// alg). at_hash is REQUIRED whenever an access_token accompanies the
	// id_token, so populate this on every such flow (authorization_code,
	// login, device, CIBA, silent-renewal); leaving it empty omits the
	// claim and is byte-identical to the pre-at_hash behavior.
	AccessToken string

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

// UserinfoSigner is an optional extension to IDTokenIssuer. When the
// wired IDTokenIssuer implements this interface AND a client's
// UserinfoSignedResponseAlg metadata is set, /userinfo returns a
// signed JWT (Content-Type: application/jwt) instead of plain JSON.
//
// The default Ed25519JWTIssuer implements this interface — the
// returned JWT uses the same signing key as access + id tokens so
// RPs verify all three with one JWKS entry.
//
// claims is the projected user-info claim set (sub + scope-gated
// OIDC claims + amr/acr/auth_time when carried by the access token).
// audience is the client_id the userinfo response is bound to —
// stamped into the JWT's `aud` claim per OIDC Core §5.3.2.
type UserinfoSigner interface {
	SignUserInfo(ctx context.Context, audience string, claims map[string]any) (string, error)
}

// MetadataSigner is the optional extension a TokenIssuer / IDTokenIssuer
// MAY implement to enable RFC 8414 §2.1 signed metadata. When wired
// via [WithMetadataSigner], discovery emits an additional
// `signed_metadata` field whose value is a JWS of the metadata claim
// set — RPs verify the signature against JWKS before trusting
// endpoints, defending against a tampering proxy.
//
// The default Ed25519JWTIssuer implements this; the same signing key
// the issuer uses for access / id / userinfo tokens signs the
// metadata, so one JWKS entry covers everything.
type MetadataSigner interface {
	SignMetadata(ctx context.Context, claims map[string]any) (string, error)
}
