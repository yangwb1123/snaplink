package core

import "time"

// Endpoint paths registered by Server.Mount.
const (
	PathHealth         = "/health"
	PathLivez          = "/livez"
	PathReadyz         = "/readyz"
	PathLogin          = "/auth/login"
	PathMFAComplete    = "/auth/mfa"
	PathSendCode       = "/auth/send-code"
	PathCallback       = "/auth/callback"
	PathToken          = "/token"
	PathIntrospect     = "/token/introspect"
	PathRevoke         = "/token/revoke"
	PathRevokeAll      = "/token/revoke-all"
	PathDeviceCode     = "/device/code"
	PathDeviceVerify   = "/device/verify"
	PathUserInfo       = "/userinfo"
	PathLogout         = "/logout"
	PathEndSession     = "/end_session"
	PathPAR            = "/par" // RFC 9126 Pushed Authorization Requests
	PathAPIPrefix      = "/api/v1"
	PathClientByID     = "/clients/:id"
	PathAuditEvents    = "/audit/events"
	PathAuditEventByID = "/audit/events/:id"

	PathMyPermissions = "/permissions/me"
	PathMyMenus       = "/menus/me"
	PathMyRoles       = "/roles/me"

	PathNetPolicies        = "/netpolicy/policies"
	PathNetPolicyByName    = "/netpolicy/policies/:name"
	PathNetPolicyClassify  = "/netpolicy/classify"
	PathNetPolicyResolveMe = "/netpolicy/resolve-me"
)

// HTTP header names and well-known values.
const (
	HeaderAuthorization        = "Authorization"
	HeaderContentType          = "Content-Type"
	HeaderRequestID            = "X-Request-Id"
	HeaderTraceparent          = "Traceparent"
	HeaderParentSpanID         = "X-Parent-Span-Id"
	HeaderAccessControlOrigin  = "Access-Control-Allow-Origin"
	HeaderAccessControlMethods = "Access-Control-Allow-Methods"
	HeaderAccessControlHeaders = "Access-Control-Allow-Headers"

	BearerPrefix    = "Bearer "
	TokenTypeBearer = "Bearer"
	ContentTypeJSON = "application/json"

	CORSAllowedMethods = "GET, POST, OPTIONS"
	CORSAllowedHeaders = "Content-Type, Authorization"
	CORSAllowAllOrigin = "*"
)

// JSON response keys used across handlers.
const (
	KeyError            = "error"
	KeyErrorDescription = "error_description"
	KeyStatus           = "status"
	KeyIssuer           = "issuer"
	KeyVersion          = "version"
	KeyVCSRevision      = "vcs_revision"
	KeyVCSTime          = "vcs_time"
	KeyProviders        = "providers"
	KeySupportedGrants  = "supported_grants"
	KeySessionID        = "session_id"
	KeyAccessToken      = "access_token"
	KeyRefreshToken     = "refresh_token"
	KeyTokenType        = "token_type"
	KeyExpiresIn        = "expires_in"
	KeyScope            = "scope"
	KeyRevoked          = "revoked"
	KeyTokenStrategy    = "token_strategy"
	KeyRecommendedLang  = "recommended_language"
	KeyCountryCode      = "country_code"
	KeyCode             = "code"
	KeyState            = "state"
	KeyRedirectURI      = "redirect_uri"
	KeyIssuedTokenType  = "issued_token_type" // RFC 8693 token-exchange response key

	// RFC 7662 introspection response keys.
	KeyActive    = "active"
	KeyTokenHint = "token_type_hint"
	KeySub       = "sub"
	KeyIss       = "iss"
	KeyAud       = "aud"
	KeyExp       = "exp"
	KeyIat       = "iat"
	KeyNbf       = "nbf"
	KeyClientID  = "client_id"
	KeyStrategy  = "token_strategy_used"

	// RFC 9068 §2.2 access-token claim keys also surfaced on
	// introspection responses per RFC 7662 §2.2.
	KeyJTI      = "jti"
	KeyAuthTime = "auth_time"
	KeyACR      = "acr"
	KeyAMR      = "amr"

	// OIDC response key for the ID Token (OIDC Core §3.1.3.3).
	KeyIDToken = "id_token"

	// MFA orchestration response keys. KeyMFAChallengeID is the opaque
	// challenge token returned by /auth/login + accepted by /auth/mfa.
	// KeyMFAMethods is the array of supported factor names; SPAs render
	// UI per entry. KeyMFAMethod is the body field on /auth/mfa naming
	// which factor the caller is responding with.
	//
	// KeyMFAMethodData carries per-method server-issued challenge data
	// from providers that implement [spi.MFABeginner] — e.g. WebAuthn's
	// CredentialAssertion options + ceremony session id. Shape is
	// {method_name: {key: value}}; methods that don't need Begin
	// state are absent. Clients echo the relevant keys back into the
	// /auth/mfa params payload so the server can match ceremony state
	// during Verify.
	KeyMFAChallengeID = "mfa_challenge_id"
	KeyMFAMethods     = "mfa_methods"
	KeyMFAMethod      = "mfa_method"
	KeyMFAMethodData  = "mfa_method_data"

	// ScopeOpenID triggers OIDC ID Token issuance when an oidc.IDTokenIssuer
	// is wired (OIDC Core §3.1.2.1).
	ScopeOpenID = "openid"
)

// Stable error code strings returned to API callers.
const (
	ErrInvalidRequest            = "invalid_request"
	ErrInvalidCredentials        = "invalid_credentials"
	ErrAccountLocked             = "account_locked"
	ErrInvalidToken              = "invalid_token"
	ErrInvalidClient             = "invalid_client"
	ErrInvalidClientSecret       = "invalid_client_secret"
	ErrInvalidCallback           = "invalid_callback"
	ErrCallbackFailed            = "callback_failed"
	ErrUnsupportedProvider       = "unsupported_provider"
	ErrUnknownProvider           = "unknown_provider"
	ErrUnsupportedGrantType      = "unsupported_grant_type"
	ErrMissingToken              = "missing_token"
	ErrMissingClientID           = "missing_client_id"
	ErrUserNotFound              = "user_not_found"
	ErrClientNotFound            = "client_not_found"
	ErrInternal                  = "internal_error"
	ErrServerMisconfigured       = "server_misconfigured"
	ErrSessionMgrNotConfigured   = "session_manager_not_configured"
	ErrClientStoreNotConfigured  = "client_store_not_configured"
	ErrSessionIDOrBearerRequired = "session_id_or_bearer_required"
	ErrProviderAndTargetRequired = "provider_and_target_required"
	ErrProviderDoesNotSendCodes  = "provider_does_not_send_codes"
	ErrSendFailed                = "send_failed"
	ErrUnauthorized              = "unauthorized"
	ErrAuthenticatorNotAllowed   = "authenticator_not_allowed_for_client"
	ErrInactiveClient            = "inactive_client"
	ErrTenantMismatch            = "tenant_mismatch"
	ErrNoTokenStrategy           = "no_token_strategy"
	ErrNetPolicyNotConfigured    = "netpolicy_not_configured"
	ErrNetPolicyNotFound         = "netpolicy_not_found"
	ErrRiskDenied                = "risk_denied"
	ErrPayloadTooLarge           = "payload_too_large"

	// MFA orchestration. ErrMFARequired is the pending status returned
	// by /auth/login when the spi.RiskScorer decided RequireMFA and a
	// spi.MFAProvider is wired — the response carries mfa_challenge_id +
	// mfa_methods instead of tokens. ErrMFAInvalid is the single wire
	// response /auth/mfa returns for every failure (unknown / expired /
	// already-consumed challenge, unsupported method, wrong factor) per
	// the oracle-leak hardening contract.
	ErrMFARequired               = "mfa_required"
	ErrMFAInvalid                = "mfa_invalid"
	ErrInvalidGrant              = "invalid_grant"
	ErrInvalidRedirectURI        = "invalid_redirect_uri"
	ErrAuthCodeNotConfigured     = "authorization_code_not_configured"
	ErrUnsupportedResponseType   = "unsupported_response_type"
	ErrRefreshTokenNotConfigured = "refresh_token_not_configured"
	ErrInvalidScope              = "invalid_scope"
	ErrInvalidPKCEMethod         = "invalid_pkce_method"
	ErrPKCERequired              = "pkce_required"
	ErrInvalidTarget             = "invalid_target" // RFC 8707 §2
	ErrPARNotConfigured          = "par_not_configured"
	ErrInvalidRequestURI         = "invalid_request_uri" // RFC 9126 §2.2

	// RFC 8628 device authorization grant errors.
	ErrDeviceCodeNotConfigured = "device_code_not_configured"
	ErrAuthorizationPending    = "authorization_pending"
	ErrSlowDown                = "slow_down"
	ErrAccessDenied            = "access_denied"
	ErrExpiredToken            = "expired_token"

	// OIDC Core §3.1.2.6 authentication error responses returned
	// when a prompt parameter constrains the AS's ability to
	// surface the necessary interaction.
	ErrLoginRequired            = "login_required"
	ErrInteractionRequired      = "interaction_required"
	ErrConsentRequired          = "consent_required"
	ErrAccountSelectionRequired = "account_selection_required"

	// RFC 9449 §5.2 — invalid_dpop_proof is returned when the
	// `DPoP` header is present but fails verification (bad
	// signature, mismatched htm / htu / iat, replayed jti).
	ErrInvalidDPoPProof = "invalid_dpop_proof"

	// RFC 9449 §8 — use_dpop_nonce signals the client must include
	// a server-issued nonce claim in subsequent DPoP proofs. The
	// fresh nonce is delivered to the client via the `DPoP-Nonce`
	// response header; the client repeats the request with that
	// nonce embedded in the proof JWT's `nonce` claim.
	ErrUseDPoPNonce = "use_dpop_nonce"
)

// OIDC Core §3.1.2.1 prompt values. Space-separated combinations are
// allowed by the spec EXCEPT for "none" which MUST appear alone.
const (
	PromptNone          = "none"
	PromptLogin         = "login"
	PromptConsent       = "consent"
	PromptSelectAccount = "select_account"
)

// Status strings returned in successful responses.
const (
	StatusOK            = "ok"
	StatusLoggedOut     = "logged_out"
	StatusSent          = "sent"
	StatusAuthenticated = "authenticated"
)

// OAuth2 grant types accepted by /token.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	GrantClientCredentials = "client_credentials"
	GrantDeviceCode        = "urn:ietf:params:oauth:grant-type:device_code"
	GrantTokenExchange     = "urn:ietf:params:oauth:grant-type:token-exchange" // RFC 8693
)

// RFC 8693 token type URIs used by the token-exchange grant.
const (
	TokenTypeAccessToken  = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeSAML2        = "urn:ietf:params:oauth:token-type:saml2"
	TokenTypeJWT          = "urn:ietf:params:oauth:token-type:jwt"
)

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
)

// SupportedGrants is the canonical list returned for unsupported_grant_type errors.
var SupportedGrants = []string{
	GrantAuthorizationCode,
	GrantRefreshToken,
	GrantClientCredentials,
	GrantDeviceCode,
	GrantTokenExchange,
}
