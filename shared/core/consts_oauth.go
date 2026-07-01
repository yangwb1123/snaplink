package core

import "time"

// OIDC Core §3.1.2.1 prompt values. Space-separated combinations are
// allowed by the spec EXCEPT for "none" which MUST appear alone.
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

// OAuth2 grant types accepted by /token.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange" // RFC 8693
	GrantCIBA              = "urn:openid:params:grant-type:ciba"               // OIDC CIBA Core 1.0 §10.1
	// GrantJWTBearer is the RFC 7523 JWT Bearer Token Grant — a client exchanges
	// an externally-signed JWT assertion for an access token. The assertion is
	// validated against a configurable trust anchor (issuer JWKS or OIDC Discovery).
	GrantJWTBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// CIBAAMR is the AMR / provider value recorded for a token minted via the CIBA
// grant — the user confirmed out of band on a separate authentication device.
const CIBAAMR = "ciba"

// RFC 8693 token type URIs used by the token-exchange grant.
//
// SPIFFE JWT-SVIDs are exchanged as the STANDARD TokenTypeJWT
// ("urn:ietf:params:oauth:token-type:jwt") — they ARE generic JWTs, so
// no bespoke SPIFFE token-type URI is minted (which would be
// non-standard and force SVID-bearing workloads onto a custom value).
// The server disambiguates a SVID from a locally-issued JWT by trying the
// local issuers first and only falling back to the SPIFFE validator (which
// further requires a spiffe:// sub) — so an ordinary jwt subject_token is
// unaffected.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
	// TokenTypeDeviceSecret is the actor_token_type for the OpenID Connect
	// Native SSO 1.0 device-secret token exchange (§3.2).
	TokenTypeDeviceSecret = "urn:openid:params:token-type:device-secret"
)

// AMR (RFC 8176) value placed on a token minted from an accepted SPIFFE
// JWT-SVID, so a downstream service can tell the principal authenticated
// as a mesh workload (not an interactive user).
const AMRSpiffe = "spiffe"

// AMRSaml is the AMR (RFC 8176) value placed on a token minted from a
// validated SAML 2.0 assertion (an operator's forked SAML SP authenticator
// completing the assertion-consumer flow), so a downstream service can tell
// the principal authenticated via a SAML IdP federation.
const AMRSaml = "saml"

// Revocation tags returned by /logout.
const (
	RevokedSession = "session"
	RevokedToken   = "token"
)

// Built-in token strategy names. Custom strategies may use any string.
const (
	TokenStrategyJWT     = "jwt"
	TokenStrategySession = "session"
)

// HTTP token_type response values. "Bearer" is the RFC 6750 default;
// "DPoP" (RFC 9449) signals the token is sender-constrained via the
// DPoP JWK thumbprint stamped in `cnf.jkt`.
const (
	TokenTypeNameBearer = "Bearer"
	TokenTypeNameDPoP   = "DPoP"
)

// PKCE (RFC 7636) method names + verifier length bounds. The RFC mandates
// support for "S256" and tolerates "plain" only for legacy clients —
// production deployments should reject "plain" via deployment policy
// (Client.RequirePKCE only enforces presence, not method choice; a
// future tightening can add a per-client AllowedPKCEMethods filter).
const (
	PKCEMethodPlain    = "plain"
	PKCEMethodS256     = "S256"
	PKCEVerifierMinLen = 43  // per RFC 7636 §4.1
	PKCEVerifierMaxLen = 128 // per RFC 7636 §4.1
)

// Dependency names referenced by Server.requireDeps.
const (
	DepTokenIssuer  = "tokenIssuer"
	DepUserProvider = "userProvider"
	DepClientStore  = "clientStore"
	DepSessionMgr   = "sessionMgr"
)

// Defaults used by NewServer when the corresponding option is not supplied.
const (
	DefaultSessionDuration = 24 * time.Hour
	DefaultTokenTTL        = time.Hour
	DefaultAuthCodeTTL     = 10 * time.Minute
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	DefaultDeviceCodeTTL   = 10 * time.Minute
	DefaultDevicePollMin   = 5 * time.Second
	DefaultIssuer          = "snaplink-sso"
	// DefaultDeviceSecretTTL bounds a Native SSO device_secret's validity.
	DefaultDeviceSecretTTL = 15 * time.Minute
	// DefaultPasswordResetTTL bounds a forgot-password reset token's validity.
	// Short by design — a reset token is a credential-takeover primitive.
	DefaultPasswordResetTTL = 15 * time.Minute
	// DefaultEmailChangeTTL bounds a verified-email-change token's validity.
	DefaultEmailChangeTTL = 15 * time.Minute
)

// SupportedGrants is the canonical list returned for unsupported_grant_type errors.
var SupportedGrants = []string{
	GrantAuthorizationCode,
	GrantRefreshToken,
	GrantClientCredentials,
	GrantDeviceCode,
	GrantTokenExchange,
	GrantJWTBearer,
}
