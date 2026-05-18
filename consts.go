package sso

import "time"

// Endpoint paths registered by Server.Mount.
const (
	PathHealth         = "/health"
	PathLivez          = "/livez"
	PathReadyz         = "/readyz"
	PathLogin          = "/auth/login"
	PathSendCode       = "/auth/send-code"
	PathCallback       = "/auth/callback"
	PathToken          = "/token"
	PathIntrospect     = "/token/introspect"
	PathRevoke         = "/token/revoke"
	PathUserInfo       = "/userinfo"
	PathLogout         = "/logout"
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
)

// Stable error code strings returned to API callers.
const (
	ErrInvalidRequest            = "invalid_request"
	ErrInvalidCredentials        = "invalid_credentials"
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
	ErrInvalidGrant              = "invalid_grant"
	ErrInvalidRedirectURI        = "invalid_redirect_uri"
	ErrAuthCodeNotConfigured     = "authorization_code_not_configured"
	ErrUnsupportedResponseType   = "unsupported_response_type"
	ErrRefreshTokenNotConfigured = "refresh_token_not_configured"
	ErrInvalidScope              = "invalid_scope"
	ErrInvalidPKCEMethod         = "invalid_pkce_method"
	ErrPKCERequired              = "pkce_required"
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
	depTokenIssuer  = "tokenIssuer"
	depUserProvider = "userProvider"
	depClientStore  = "clientStore"
	depSessionMgr   = "sessionMgr"
)

// Defaults used by NewServer when the corresponding option is not supplied.
const (
	DefaultSessionDuration = 24 * time.Hour
	DefaultTokenTTL        = time.Hour
	DefaultAuthCodeTTL     = 10 * time.Minute
	DefaultRefreshTokenTTL = 30 * 24 * time.Hour
	DefaultIssuer          = "snaplink-sso"
)

// SupportedGrants is the canonical list returned for unsupported_grant_type errors.
var SupportedGrants = []string{
	GrantAuthorizationCode,
	GrantRefreshToken,
	GrantClientCredentials,
}
