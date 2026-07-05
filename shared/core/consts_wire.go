package core

// HTTP header names and well-known values.
const (
	HeaderAuthorization = "Authorization"
	// HeaderIdempotencyKey is the HTTP header clients set to enable
	// safe retry on the /token endpoint — the server caches the first
	// successful response under this key and returns it for repeat
	// requests, preventing duplicate token issuance on network retries.
	HeaderIdempotencyKey       = "Idempotency-Key"
	HeaderContentType          = "Content-Type"
	HeaderRequestID            = "X-Request-Id"
	HeaderTraceID              = "X-Trace-Id"
	HeaderTraceparent          = "Traceparent"
	HeaderParentSpanID         = "X-Parent-Span-Id"
	HeaderAccessControlOrigin  = "Access-Control-Allow-Origin"
	HeaderAccessControlMethods = "Access-Control-Allow-Methods"
	HeaderAccessControlHeaders = "Access-Control-Allow-Headers"
	// HeaderRetryAfter tells a client how long (seconds) to wait before
	// retrying — sent on the degraded-service 503 so a caller backs off for the
	// failover window instead of hammering a shedding replica.
	HeaderRetryAfter = "Retry-After"

	// HeaderAcceptVersion is the opt-in request header a client sets to
	// negotiate a specific API version (see interfaces/middleware.AcceptVersion,
	// ADR-0008). Only consulted when WithAPIVersioning configured a non-empty
	// supported-version list; an absent header or absent config leaves the
	// request unaffected — additive by construction.
	HeaderAcceptVersion = "Accept-Version"
	// HeaderDeprecation is the response header (draft-ietf-httpapi-deprecation-header
	// convention) marking an endpoint or the whole API as deprecated: "true",
	// or an HTTP-date naming when the deprecation began. See
	// interfaces/middleware.Deprecation.
	HeaderDeprecation = "Deprecation"
	// HeaderSunset is the RFC 8594 response header naming the HTTP-date a
	// deprecated resource stops being available. See
	// interfaces/middleware.Deprecation.
	HeaderSunset = "Sunset"
	// HeaderLink carries the RFC 8288 sunset migration-guide URL alongside
	// HeaderSunset, e.g. `Link: <https://...>; rel="sunset"`.
	HeaderLink = "Link"

	BearerPrefix    = "Bearer "
	TokenTypeBearer = "Bearer"
	ContentTypeJSON = "application/json"

	CORSAllowedMethods = "GET, POST, OPTIONS"
	CORSAllowedHeaders = "Content-Type, Authorization"
	CORSAllowAllOrigin = "*"

	// Mesh ext_authz identity response headers. On a 200 ALLOW the
	// ext_authz HTTP endpoint stamps these so the sidecar injects them
	// into the upstream request — the "validate the token at the sidecar,
	// inject identity to the upstream" mesh pattern. They are DERIVED from
	// the validated access token, never trusted from the inbound request;
	// the mesh MUST strip any client-supplied X-Auth-* at ingress (same
	// "edge must strip untrusted headers" model as X-Forwarded-* and
	// security.mtls.backend: header).
	HeaderAuthSubject  = "X-Auth-Subject"
	HeaderAuthClientID = "X-Auth-Client-Id"
	HeaderAuthScopes   = "X-Auth-Scopes"
	HeaderAuthExpires  = "X-Auth-Expires"
	HeaderAuthRoles    = "X-Auth-Roles"
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
	// KeyServingRegion names the region deployment that served the login
	// response (multi-region / data-residency layer). DISTINCT from
	// geo's "region" (an ISO 3166-2 client-IP subdivision) — this is WHICH
	// deployment served, not WHERE the client is.
	KeyServingRegion   = "serving_region"
	KeyCode            = "code"
	KeyState           = "state"
	KeyRedirectURI     = "redirect_uri"
	KeyIssuedTokenType = "issued_token_type" // RFC 8693 token-exchange response key

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
	KeyTenantID  = "tenant_id"
	KeyStrategy  = "token_strategy_used"
	// KeyClientName / KeyScopes are presentational fields in the consent_required
	// response — the app's display name and the per-scope description list.
	KeyClientName = "client_name"
	KeyScopes     = "scopes"

	// RFC 9068 §2.2 access-token claim keys also surfaced on
	// introspection responses per RFC 7662 §2.2.
	KeyJTI      = "jti"
	KeyAuthTime = "auth_time"
	KeyACR      = "acr"
	KeyAMR      = "amr"

	// RFC 7662 §2.2 / RFC 8705 §3.3 / RFC 9449 §7 confirmation member —
	// introspection echoes the token's `cnf` so a resource server can enforce
	// sender-constraint binding (mTLS x5t#S256 / DPoP jkt).
	KeyCnf        = "cnf"
	KeyCnfX5TS256 = "x5t#S256"
	KeyCnfJKT     = "jkt"

	// OIDC response key for the ID Token (OIDC Core §3.1.3.3).
	KeyIDToken = "id_token"

	// KeyDeviceSecret is the /token response key carrying the Native SSO
	// device secret (OpenID Connect Native SSO 1.0 §3.1).
	KeyDeviceSecret = "device_secret"
	// KeyDsHash is the id_token claim binding the device_secret — the
	// base64url left-half hash of the secret, same construction as at_hash.
	KeyDsHash = "ds_hash"

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

	// KeyConsentChallengeID is the opaque server-issued token returned in a
	// consent_required response. The SPA must present it back (unchanged) in
	// the next /auth/login call to prove the server computed the need for
	// consent before the approval arrived. Without it, any client could bypass
	// the consent screen by fabricating consent_approved.
	KeyConsentChallengeID = "consent_challenge_id"

	// SPIFFE JWT-SVID audit metadata keys — written via audit.SetMeta on
	// the spiffe_jwt_svid_accepted event (internal). Mesh-workload
	// identity dimensions a SIEM pivots on.
	KeySPIFFETrustDomain    = "spiffe_trust_domain"
	KeySPIFFENamespace      = "spiffe_namespace"
	KeySPIFFEServiceAccount = "spiffe_service_account"

	// ScopeOpenID triggers OIDC ID Token issuance when an oidc.IDTokenIssuer
	// is wired (OIDC Core §3.1.2.1).
	ScopeOpenID = "openid"

	// ScopeDeviceSSO triggers a device_secret in the /token response (and a
	// ds_hash claim in the id_token) for OpenID Connect Native SSO 1.0. Like
	// openid it is a protocol trigger, not a resource scope — it bypasses the
	// per-client AllowedScopes gate.
	ScopeDeviceSSO = "device_sso"
)

// Status strings returned in successful responses.
const (
	StatusOK            = "ok"
	StatusLoggedOut     = "logged_out"
	StatusSent          = "sent"
	StatusAuthenticated = "authenticated"
)

// Netpolicy response keys.
const (
	KeyNetPolicies = "policies"
	KeyNetClass    = "class"
	KeyNetPolicy   = "policy"
)

// Permission endpoint response keys + errors.
const (
	KeyPermissions = "permissions"
	KeyRoles       = "roles"
	KeyMenus       = "menus"
	KeyClient      = "client_id"

	ErrPermissionProviderNotConfigured = "permission_provider_not_configured"
	ErrPermissionLookupFailed          = "permission_lookup_failed"
)

// Token Portfolio governance route paths (Phase 3 of token governance).
// Relocated from consts.go to keep that file within the per-file line budget
// while shared/core stays at its frozen file count. Group-relative on the
// /api/v1 router group; admin-gated (GET admin:read, POST admin:write).
const (
	PathAdminTokenPortfolio  = "/admin/tokens/portfolio"
	PathAdminTokenSubject    = "/admin/tokens/subjects/:subject"
	PathAdminTokenSuspicious = "/admin/tokens/suspicious"
	PathAdminTokenRevoke     = "/admin/tokens/revoke"
)

// PathAPIVersionPreview is the ADR-0008 v2alpha proof-of-mechanism route: a
// single read-only capability probe (GET) demonstrating that a "/api/v2alpha"
// path-prefix CAN be routed, without committing to a full v2 API surface.
// Full path (not group-relative — it deliberately sits OUTSIDE the stable
// /api/v1 group). Only mounted when WithAPIVersionPreview is wired
// (byte-identical off otherwise). Relocated here (not consts.go) because
// consts.go is at its per-file line budget.
const PathAPIVersionPreview = "/api/v2alpha/version"
