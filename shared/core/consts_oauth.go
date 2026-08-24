package core

import "time"

// PathMyPreferences is kept with the split wire constants to keep the main
// endpoint-constant file below its hard line budget.
const PathMyPreferences = "/me/preferences"

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

	// GrantTypeSAML2Bearer is the RFC 7522 SAML 2.0 Bearer Assertion Profile
	// grant type URN. The client presents a base64-encoded SAML 2.0 assertion
	// which is decoded, signature-verified, and validated (audience, conditions,
	// SubjectConfirmation method=Bearer) before issuing OAuth tokens for the
	// SAML NameID-mapped local user.
	GrantTypeSAML2Bearer = "urn:ietf:params:oauth:grant-type:saml2-bearer"

	// GrantTypeAgentDelegation is the delegation_token grant type URN
	// (domains/tokenexchange/agentidentity): an AI agent — an identity
	// distinct from any human User or OAuth Client — redeems a previously
	// created, human-authorized AgentSession for an access token whose
	// `sub` is the AGENT's own identity but whose `act` claim (RFC 8693
	// §4.1, ActorClaim) points back to the delegating human. Vendor-
	// namespaced (urn:snaplink:...) rather than urn:ietf:params:... — this
	// is a snaplink-specific extension, not an IETF-registered grant type.
	GrantTypeAgentDelegation = "urn:snaplink:params:oauth:grant-type:delegation"
)

// CIBAAMR is the AMR / provider value recorded for a token minted via the CIBA
// grant — the user confirmed out of band on a separate authentication device.
const CIBAAMR = "ciba"

// AMRPassword is the AMR (RFC 8176) value recorded for a password-based login
// (domains/authenticators.PasswordAuthenticator sets AuthResult.AuthMethods to
// this via domains/authenticators.AuthMethodPwd). Duplicated here rather than
// imported — domains/authenticators imports interfaces/sso, which imports
// shared/core, so shared/core importing back up to domains/authenticators
// would cycle. Used by the login-time password-max-age gate (interfaces/sso
// rejectExpiredPassword) to confirm THIS login actually used a password
// before consulting PasswordCredentialStore's age signal.
const AMRPassword = "pwd"

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
	DPoPPrefix          = "DPoP "
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
	// DefaultBreakGlassTTL is the window granted to a break-glass admin
	// session when the caller omits ttl_seconds — short by design, the same
	// rationale as DefaultPasswordResetTTL: an unbounded grant is the audit
	// finding a break-glass control exists to prevent.
	DefaultBreakGlassTTL = 15 * time.Minute
	// MaxBreakGlassTTL is the hard ceiling on a break-glass admin session
	// regardless of caller input; requests above it are rejected rather than
	// silently clamped, so an operator's monitoring sees the misuse attempt.
	MaxBreakGlassTTL = time.Hour
)

// SupportedGrants is the canonical list of every grant type the /token
// built-in dispatcher switch (interfaces/sso's dispatchTokenGrant) recognizes
// as a literal case — independent of whether that grant's backing
// store/wiring is actually configured on this deployment. The same
// convention already documented for GrantDeviceCode in
// interfaces/sso/server_discovery_config.go's applyGrantEndpoints ("
// SupportedGrants still lists it for unsupported_grant_type") even though
// discovery's grant_types_supported only advertises device_code/CIBA once
// their store is wired. Two consumers depend on this list being complete:
// the /token unsupported_grant_type error body's supported_grants field, and
// DCR (RFC 7591) registration validation
// (oauthvalidate.ValidateDCRMetadata), which REJECTS any client-requested
// grant_type absent from this list — so a missing entry here doesn't just
// mis-report an error body, it silently blocks DCR clients from ever
// registering for a grant type the server actually dispatches (GrantCIBA had
// a literal `case GrantCIBA:` in dispatchTokenGrant, same as GrantDeviceCode/
// GrantTokenExchange/GrantJWTBearer above it, but was missing here).
// Deliberately excludes grant types registered only via the DYNAMIC
// WithCustomGrant mechanism (e.g. GrantTypeSAML2Bearer,
// GrantTypeAgentDelegation) — those aren't literal switch cases in
// dispatchTokenGrant, so whether they're DCR-registrable is a separate,
// per-deployment decision.
var SupportedGrants = []string{
	GrantAuthorizationCode,
	GrantRefreshToken,
	GrantClientCredentials,
	GrantDeviceCode,
	GrantTokenExchange,
	GrantJWTBearer,
	GrantCIBA,
}
