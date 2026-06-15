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
	PathForgotPassword = "/auth/forgot-password"
	PathResetPassword  = "/auth/reset-password"
	// PathSignup is the opt-in unauthenticated self-service registration
	// endpoint (POST {username, password, email}). Distinct from /register
	// (RFC 7591 Dynamic CLIENT Registration). Default-off — open signup is an
	// abuse surface most enterprise deployments don't want (they provision via
	// SCIM/admin); enable deliberately for B2C.
	PathSignup          = "/auth/register"
	PathCallback        = "/auth/callback"
	PathToken           = "/token"
	PathIntrospect      = "/token/introspect"
	PathRevoke          = "/token/revoke"
	PathRevokeAll       = "/token/revoke-all"
	PathDeviceCode      = "/device/code"
	PathDeviceVerify    = "/device/verify"
	PathUserInfo        = "/userinfo"
	PathLogout          = "/logout"
	PathEndSession      = "/end_session"
	PathPAR             = "/par"                        // RFC 9126 Pushed Authorization Requests
	PathBackchannelAuth = "/backchannel-authentication" // OIDC CIBA Core 1.0 §7
	PathAPIPrefix       = "/api/v1"
	PathClientByID      = "/clients/:id"
	PathAuditEvents     = "/audit/events"
	PathAuditEventByID  = "/audit/events/:id"
	PathAuditFacets     = "/audit/facets"

	PathMyPermissions = "/permissions/me"
	PathMyMenus       = "/menus/me"
	PathMyRoles       = "/roles/me"
	PathMySessions    = "/sessions/me"
	PathMySessionByID = "/sessions/me/:id"
	PathMyConsents    = "/consents/me"
	PathMyConsentByID = "/consents/me/:client_id"

	// PathBranding is the public, unauthenticated tenant-branding lookup the
	// hosted login SPA fetches (by client_id) to white-label the sign-in page.
	// Returns only non-sensitive presentation data (brand name, color, logo).
	PathBranding = "/branding"

	// PathProtectedResourceMetadata serves the RFC 9728 OAuth 2.0 Protected
	// Resource Metadata document, letting clients (notably MCP / AI-agent
	// clients) discover which authorization server issues tokens for this
	// resource. Opt-in via WithProtectedResourceMetadata.
	PathProtectedResourceMetadata = "/.well-known/oauth-protected-resource"

	// PathMe is the authenticated self-service account overview: the bearer's
	// own profile plus active-session and granted-app counts. The entry point
	// a self-service portal lands on.
	PathMe = "/me"

	// PathMyPassword is the authenticated self-service password change
	// (POST). Verifies the current password, then sets a new one.
	PathMyPassword = "/me/password"

	// PathMyMFA lists the authenticated user's registered second factors (GET);
	// PathMyMFAByID unbinds one (DELETE).
	PathMyMFA     = "/me/mfa"
	PathMyMFAByID = "/me/mfa/:id"

	// PathMyEmailChange begins a verified email change (POST {new_email}): a
	// token is sent to the NEW address. PathMyEmailVerify completes it (POST
	// {token}): the token is consumed and the email committed. Both authenticated
	// — the verification flow PATCH /me routes email edits through.
	PathMyEmailChange = "/me/email/change"
	PathMyEmailVerify = "/me/email/verify"

	// PathMyDataExport is the authenticated GDPR Art. 15 self-service data
	// export: the bearer downloads a portable bundle of their OWN data (GET).
	// The admin-gated /api/v1/compliance path exports an arbitrary subject;
	// this one is scoped to the caller. Mounted only when an exporter is wired.
	PathMyDataExport = "/me/data-export"

	// PathMyAccountErase is the authenticated GDPR Art. 17 self-service erasure
	// (POST): the bearer deletes their OWN account (sessions + refresh tokens +
	// user record). Requires a confirmation matching the subject; supports
	// {dry_run} to preview. Opt-in + irreversible. Mounted only when wired.
	PathMyAccountErase = "/me/account/erase"

	// PathMyMFATOTPBegin mints a fresh TOTP secret + otpauth URI (POST);
	// PathMyMFATOTPConfirm verifies a code against that secret and commits the
	// factor (POST). Self-service TOTP enrollment — the write-half of /me/mfa.
	PathMyMFATOTPBegin   = "/me/mfa/totp/begin"
	PathMyMFATOTPConfirm = "/me/mfa/totp/confirm"

	// PathMyWebAuthnRegisterBegin / Finish are AUTHENTICATED self-service passkey
	// registration (POST). Unlike the signup ceremony (/webauthn/registration/*,
	// username from the body), these bind the new credential to the BEARER
	// subject — so a user can only add a passkey to their OWN account. The
	// registered passkey then appears in GET /me/mfa via the WebAuthn adapter.
	PathMyWebAuthnRegisterBegin  = "/me/mfa/webauthn/begin"
	PathMyWebAuthnRegisterFinish = "/me/mfa/webauthn/finish"

	// PathMeshExtAuthz is the default mount point for the opt-in
	// Envoy/Istio ext_authz HTTP-mode authorization endpoint (cluster C1
	// mesh data-plane, the HTTP variant). A mesh sidecar calls it per
	// request: a 2xx response = ALLOW (and the sidecar injects this
	// endpoint's chosen X-Auth-* response headers into the upstream
	// request), any other status = DENY. Only mounted when
	// WithMeshExtAuthz is wired; the path is operator-overridable. It is
	// MESH-INTERNAL — only the trusted sidecar may reach it (operator
	// network policy), and the mesh MUST strip any client-supplied
	// X-Auth-* at ingress (same edge-strip trust model as X-Forwarded-*).
	PathMeshExtAuthz = "/mesh/ext-authz"

	// PathAuthzPolicyBundle is the read-only admin export of the
	// permissions role-DEFINITION model as a portable bundle a service-mesh
	// sidecar pulls to enforce authorization locally (no per-request
	// Authorizer RPC). Full path (not group-relative) so it can be mounted
	// on the SSO router directly and gated by AdminMiddleware via the
	// /api/v1/admin/ prefix.
	PathAuthzPolicyBundle = "/api/v1/admin/authz/policy-bundle"

	// PathStorageHealth is the read-only admin per-store health report:
	// for every wired store (identity / oauth / audit / tenant / …) it
	// reports reachability (Ping), schema version (migrate namespace ->
	// version), and Ping latency. Distinct from /readyz, which is a
	// pass/fail aggregate — this is the detailed view operators need for
	// DR drills + rolling-upgrade safety (which store is on which schema,
	// which is slow, which is down). Full path (not group-relative) so it
	// mounts on the SSO router directly and is gated by AdminMiddleware via
	// the /api/v1/admin/ prefix.
	PathStorageHealth = "/api/v1/admin/storage-health"

	// PathTenantUsage is the read-only admin per-tenant usage/metering
	// endpoint (GET /api/v1/admin/tenants/:id/usage?period=day|month&start=...).
	// Returns aggregated login / token-issuance / active-user / MFA counts
	// for the tenant over the requested period. Gated by AdminMiddleware
	// (admin:read). Only mounted when WithTenantUsageAggregator is wired.
	//
	// Group-relative: mounted on the /api/v1 router group, so the leading
	// segment is the group prefix (NOT repeated here). A full "/api/v1/..."
	// value would double-prefix to /api/v1/api/v1/... — unreachable at the
	// documented path AND outside the AdminMiddleware /api/v1/admin/ gate.
	PathTenantUsage = "/admin/tenants/:id/usage"

	// Admin/helpdesk management of a user's self-service state. All
	// group-relative (mounted on /api/v1, gated by AdminMiddleware via the
	// /api/v1/admin/ prefix: GET = admin:read, DELETE = admin:write).
	// PathAdminUserConsents lists a user's app authorizations; PathAdminUserConsentByID
	// revokes one (helpdesk "remove this user's access to app X").
	// PathAdminUserMFA lists a user's second factors; PathAdminUserMFAByID
	// unbinds one (helpdesk "user lost their phone — reset their MFA").
	PathAdminUserConsents    = "/admin/users/:id/consents"
	PathAdminUserConsentByID = "/admin/users/:id/consents/:client_id"
	PathAdminUserMFA         = "/admin/users/:id/mfa"
	PathAdminUserMFAByID     = "/admin/users/:id/mfa/:factor_id"

	// PathAdminUserPassword sets a user's password on their behalf (POST,
	// admin:write) — the helpdesk "reset this user's password" flow. Body:
	// {new_password}. Group-relative; gated by AdminMiddleware. Mounted only
	// when a PasswordCredentialStore is wired.
	PathAdminUserPassword = "/admin/users/:id/password"

	// PathAdminUserDeviceSecrets revokes ALL of a user's Native SSO device-secret
	// bindings (DELETE, admin:write) — the "lost/compromised device, cut off
	// Native SSO token minting now" lockout. Group-relative. Mounted only when a
	// DeviceSecretStore that implements DeviceSecretRevoker is wired.
	PathAdminUserDeviceSecrets = "/admin/users/:id/device-secrets"

	// PathAdminUserPasswordResetTokens / PathAdminUserEmailChangeTokens revoke
	// ALL of a user's pending forgot-password / email-change verification tokens
	// (DELETE, admin:write) — helpdesk invalidation when a token was sent to the
	// wrong address, leaked, or is disputed. Group-relative; gated by
	// AdminMiddleware. Mounted only when the respective store is wired; 501 when
	// the wired store doesn't implement the Revoker extension.
	PathAdminUserPasswordResetTokens = "/admin/users/:id/password-reset-tokens"
	PathAdminUserEmailChangeTokens   = "/admin/users/:id/email-change-tokens"

	// PathAdminUserEmail force-sets a user's email (POST, admin:write) — the
	// operational recovery path (onboarding typo, domain migration) that bypasses
	// the user-facing verified email-change flow. Group-relative; gated by
	// AdminMiddleware. Mounted only when a UserProvider is wired.
	PathAdminUserEmail = "/admin/users/:id/email"

	// PathAdminAccountLockoutClear clears a brute-force account lockout (POST,
	// admin:write) so a legitimately-locked user can retry before the auto-unlock
	// duration elapses. Body: {client_id, identifier}. NOT under /users/:id — the
	// lockout is keyed on <client_id>:<identifier> (the authenticated credential),
	// not the userID. Mounted only when an AccountLockout is wired.
	PathAdminAccountLockoutClear = "/admin/account-lockout/clear"

	// PathAdminConnections / PathAdminConnectionByID manage B2B enterprise
	// connections at runtime (list/get/upsert/delete) so operators can onboard a
	// new org's upstream IdP without a redeploy (config seeding only runs at
	// boot). GET ?tenant_id= lists a tenant's connections; admin:read for GET,
	// admin:write for POST/DELETE. Mounted only when a connection store is wired.
	PathAdminConnections    = "/admin/connections"
	PathAdminConnectionByID = "/admin/connections/:id"

	// PathAdminTenantMembers / PathAdminTenantMemberByID manage a tenant's org
	// roster (B2B membership, distinct from SCIM app roles). GET lists the roster
	// (admin:read); PUT upserts a member's role + DELETE removes (admin:write).
	// Mounted only when a TenantUserStore is wired.
	PathAdminTenantMembers    = "/admin/tenants/:id/members"
	PathAdminTenantMemberByID = "/admin/tenants/:id/members/:user_id"

	// PathMyOrganizations / PathMyOrganizationByID are the self-service org views:
	// GET lists the orgs the bearer subject belongs to; DELETE leaves one. Mounted
	// only when a TenantUserStore is wired.
	PathMyOrganizations    = "/me/organizations"
	PathMyOrganizationByID = "/me/organizations/:tenant_id"

	// PathSSFReceive is the default mount point for the opt-in OpenID
	// Shared Signals (CAEP/SSF) push-delivery RECEIVER (RFC 8935) — the
	// inbound half of Shared Signals. A CONFIGURED trusted upstream
	// transmitter POSTs a signed Security Event Token (a compact JWS,
	// Content-Type application/secevent+jwt) here; the receiver validates
	// it fail-closed (trusted-iss allowlist + signature against that
	// transmitter's JWKS + aud-binding + exp + jti-replay) and, for a
	// PRECISELY-mapped local subject, revokes that subject's local access.
	// Only mounted when WithCAEPReceiver is wired (byte-identical off).
	PathSSFReceive = "/ssf/receive"

	// PathFederationEntityConfig is the OpenID Federation 1.0 §9 well-known
	// endpoint serving THIS server's self-signed Entity Configuration — an
	// Entity Statement (§3) with iss == sub == issuer, signed by the OP's
	// own JWKS signing key (so a verifier validates it against a key it
	// already trusts) and typ "entity-statement+jwt". It advertises the OP
	// as a federation ENTITY: its public keys (inline jwks), its
	// openid_provider metadata (derived from the discovery doc), and its
	// authority_hints (the superiors whose trust chains it participates in).
	// Only mounted when WithFederationEntity is wired (byte-identical off);
	// public metadata (Cache-Control public, max-age — NOT a credential
	// endpoint). Trust-chain VALIDATION (resolving authority_hints up to a
	// trust anchor) is a separate slice and is NOT performed here.
	PathFederationEntityConfig = "/.well-known/openid-federation"

	// PathFederationFetch is the OpenID Federation 1.0 §8 Federation Fetch
	// endpoint. When this server is configured as a federation SUPERIOR /
	// INTERMEDIATE (one or more subordinate entities configured), it serves a
	// SIGNED Subordinate Statement about a requested subordinate here:
	// GET <fetch>?sub=<subordinate entity id> (optional iss = this server's
	// entity id). The response is a compact JWS (typ "entity-statement+jwt",
	// media type application/entity-statement+jwt) with iss == this server,
	// sub == the subordinate, and jwks == the subordinate's OPERATOR-CONFIGURED
	// keys this server vouches for (NOT request input — the request only
	// supplies sub, which is looked up). A missing sub → 400 invalid_request; an
	// unknown/unregistered sub → 404 not_found (the §8 federation error JSON).
	// Advertised in this server's Entity Configuration as
	// metadata.federation_entity.federation_fetch_endpoint ONLY when
	// subordinates are configured; only mounted when subordinates are configured
	// (byte-identical off otherwise). Public metadata (Cache-Control public,
	// max-age — NOT a credential endpoint).
	PathFederationFetch = "/fetch"

	PathNetPolicies        = "/netpolicy/policies"
	PathNetPolicyByName    = "/netpolicy/policies/:name"
	PathNetPolicyClassify  = "/netpolicy/classify"
	PathNetPolicyResolveMe = "/netpolicy/resolve-me"

	// SAML 2.0 (cluster: external/forked SAML module). These name the
	// canonical mount points an operator's SAML handler-set occupies when
	// wired through the cmd samlHandlerRegistry. They are DEFAULTS exposed
	// for docs / client code; the SAML module owns the actual handlers and
	// may mount elsewhere. The core module ships NO SAML/XML dependency —
	// these are plain path literals only (see AGENTS.md: zero-external-dep
	// invariant). PathSAMLMetadata serves the IdP entity descriptor (SP
	// metadata consumers fetch it); PathSAMLSSO is the IdP-side SSO
	// receiver (AuthnRequest in); PathSAMLSSOCallback is the SP-side
	// Assertion Consumer Service the IdP POSTs the assertion back to.
	//
	// Single Logout (SLO): PathSAMLSLO is the IdP-side SLO receiver — a
	// downstream SP POSTs/redirects a (signed) LogoutRequest here and the
	// IdP terminates the matching subject session, replying with a signed
	// LogoutResponse to the SP's registered SLO URL. PathSAMLSPSLO is the
	// SP-side SLO receiver — the UPSTREAM IdP redirects a (signed)
	// LogoutRequest here and this server terminates its own local session,
	// replying with a signed LogoutResponse to the IdP. Both are distinct
	// from the SSO mounts so an operator can route them independently.
	//
	// PathSAMLSLOContinue is the IdP-side FRONT-channel SLO chain resume
	// endpoint: in the browser-redirect SLO chain (SAML Bindings HTTP-Redirect)
	// the IdP redirects the user-agent sequentially through each front-channel
	// SP's SLO URL; each SP, after terminating its local session, redirects the
	// browser BACK here with a signed LogoutResponse + the chain-state id as
	// RelayState, and the IdP advances to the next SP (or returns to the
	// initiator). It is the response-side counterpart to PathSAMLSLO (the
	// request-side receiver) — a distinct path so the SP's LogoutResponse target
	// is unambiguous (it is PathSAMLSLO + "/continue").
	PathSAMLMetadata    = "/saml/metadata"
	PathSAMLSSO         = "/saml/sso"
	PathSAMLSSOCallback = "/auth/saml/callback"
	PathSAMLSLO         = "/saml/slo"
	PathSAMLSLOContinue = "/saml/slo/continue"
	PathSAMLSPSLO       = "/auth/saml/slo"
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

// Stable error code strings returned to API callers.
const (
	ErrInvalidRequest            = "invalid_request"
	ErrInvalidCredentials        = "invalid_credentials"
	ErrAccountLocked             = "account_locked"
	ErrInvalidToken              = "invalid_token"
	ErrInvalidClient             = "invalid_client"
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
	// Data-residency governance signals (multi-region layer). Like
	// tenant_mismatch (the 403 that reveals a client's tenant binding),
	// these are governance signals, NOT credential oracles: they reveal a
	// tenant's data-residency binding, which the operator already controls,
	// so they carry no anti-enumeration concern. region_not_allowed = the
	// serving region is outside the tenant's AllowedRegions;
	// residency_violation = a write would land outside the residency
	// boundary. Enforcement that returns these is a later layer.
	ErrRegionNotAllowed       = "region_not_allowed"
	ErrResidencyViolation     = "residency_violation"
	ErrNoTokenStrategy        = "no_token_strategy"
	ErrNetPolicyNotConfigured = "netpolicy_not_configured"
	ErrNetPolicyNotFound      = "netpolicy_not_found"
	ErrRiskDenied             = "risk_denied"
	ErrPayloadTooLarge        = "payload_too_large"

	// SAML 2.0 wire codes (cluster: external/forked SAML module). Declared
	// in core so the path/error literals stay centralized (AGENTS.md §8)
	// even though the SAML protocol handlers live in an operator's nested
	// module — the registry seam (cmd samlHandlerRegistry) hands the module
	// these as its canonical error vocabulary so SP/IdP failures map to a
	// stable shape. ErrSAMLAssertionInvalid = a returned assertion fails
	// validation (bad signature, wrong audience/issuer, expired, replayed);
	// ErrSAMLRequestInvalid = a malformed/forged AuthnRequest or relay
	// state; ErrSAMLNotConfigured = a SAML endpoint hit when no handler is
	// wired (cfg.saml.handler empty). The SAML module SHOULD collapse the
	// distinct assertion-validation failure causes onto the single
	// ErrSAMLAssertionInvalid to avoid an oracle (same hardening as the
	// OAuth single-use paths, AGENTS.md §2).
	//
	// ErrSAMLAssertionFailed is the IdP-side INTERNAL failure (500): the
	// server could not MINT/sign an assertion — e.g. the per-tenant signing
	// key can't drive XML-DSig (an Ed25519 issuer; goxmldsig has no EdDSA
	// method) or the signing operation errored. It is DISTINCT from
	// ErrSAMLRequestInvalid (a 400 client/request fault) so an SP can tell
	// "your request was bad" from "the IdP is misconfigured", and the IdP
	// FAILS CLOSED on it (never falls back to another tenant's key).
	ErrSAMLAssertionInvalid = "saml_assertion_invalid"
	ErrSAMLRequestInvalid   = "saml_request_invalid"
	ErrSAMLNotConfigured    = "saml_not_configured"
	ErrSAMLAssertionFailed  = "saml_assertion_failed"

	// MFA orchestration. ErrMFARequired is the pending status returned
	// by /auth/login when the spi.RiskScorer decided RequireMFA and a
	// spi.MFAProvider is wired — the response carries mfa_challenge_id +
	// mfa_methods instead of tokens. ErrMFAInvalid is the single wire
	// response /auth/mfa returns for every failure (unknown / expired /
	// already-consumed challenge, unsupported method, wrong factor) per
	// the oracle-leak hardening contract.
	ErrMFARequired = "mfa_required"
	ErrMFAInvalid  = "mfa_invalid"
	// ErrResetInvalid is the single oracle-safe response for every
	// /auth/reset-password failure (unknown / expired / consumed token, user
	// gone, set-password error) — the cause lives only in the audit event.
	ErrResetInvalid = "reset_invalid"
	// ErrConfirmationRequired is returned by POST /me/account/erase when the
	// confirmation field is missing or does not match the bearer's subject —
	// a guard against accidental / CSRF-driven irreversible self-deletion.
	ErrConfirmationRequired = "confirmation_required"
	// ErrEmailChangeInvalid is the single oracle-safe response for every
	// POST /me/email/verify failure (unknown / expired / consumed token, or a
	// token belonging to a different user) — cause only in the audit event.
	ErrEmailChangeInvalid = "email_change_invalid"
	// ErrAccountExists is returned by POST /auth/register when the chosen
	// username already exists (signup never overwrites an existing account).
	ErrAccountExists = "account_exists"
	// ErrTOTPInvalidCode is the single oracle-safe response for every TOTP
	// enrollment-confirm failure (bad base32 secret, wrong/expired code) so a
	// caller cannot tell which input was at fault. ErrTOTPEnrollmentNotSupported
	// is returned when the wired MFAEnrollmentStore is not a TOTPEnrollmentWriter
	// (or no TOTP authenticator is wired for confirm verification).
	ErrTOTPInvalidCode            = "totp_invalid_code"
	ErrTOTPEnrollmentNotSupported = "totp_enrollment_not_supported"
	// ErrWebAuthnRegistration is the generic failure for self-service passkey
	// registration confirm (expired/unknown session, bad attestation, parse
	// error) — the operator-side cause lives in logs/audit, not the wire.
	ErrWebAuthnRegistration      = "webauthn_registration_failed"
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

	// ErrDeviceSecretNotConfigured is returned on /token when the device_sso
	// scope is requested but no DeviceSecretStore is wired (Native SSO 1.0).
	ErrDeviceSecretNotConfigured = "device_secret_not_configured"

	// RFC 8628 device authorization grant errors.
	ErrDeviceCodeNotConfigured = "device_code_not_configured"
	ErrAuthorizationPending    = "authorization_pending"
	ErrSlowDown                = "slow_down"
	ErrAccessDenied            = "access_denied"
	ErrExpiredToken            = "expired_token"

	// OIDC CIBA Core 1.0 backchannel authentication errors.
	// ErrCIBANotConfigured is returned by /backchannel-authentication
	// and grant_type=ciba when the CIBA store / transport are not
	// wired (opt-in via WithCIBA). ErrUnknownUserID is the §13
	// response when no hint resolves to a known user (collapsed for
	// anti-enumeration — see docs/error-codes.md). ErrMissingUserCode
	// is reserved for user-code mode (not implemented; poll mode only).
	ErrCIBANotConfigured = "ciba_not_configured"
	ErrUnknownUserID     = "unknown_user_id"
	ErrMissingUserCode   = "missing_user_code"

	// OIDC Core §3.1.2.6 authentication error responses returned
	// when a prompt parameter constrains the AS's ability to
	// surface the necessary interaction.
	ErrLoginRequired            = "login_required"
	ErrInteractionRequired      = "interaction_required"
	ErrConsentRequired          = "consent_required"
	ErrAccountSelectionRequired = "account_selection_required"

	// ErrInvalidPassword is returned by POST /me/password when the supplied
	// current password does not match. The caller is authenticated as their
	// own account (bearer), so naming the wrong-current-password case is not
	// an enumeration leak — the user needs to know their entry was wrong.
	ErrInvalidPassword = "invalid_password"

	// ErrUnmetAuthReqs is returned on /auth/login when the RP
	// supplied acr_values and the authenticator's AchievedACR is
	// either absent or not in that set.  OIDC Core §3.1.2.6 /
	// §5.5.1.1: the AS MUST return this code when it cannot
	// satisfy the requested Authentication Context Class.
	ErrUnmetAuthReqs = "unmet_authentication_requirements"

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

	// ErrNotFound is returned when a requested resource does not exist and
	// revealing its existence would be safe (not oracle-leaking). Used by
	// /sessions/me/:id and /consents/me/:client_id.
	ErrNotFound = "not_found"
	// ErrNotSupported is returned for features that are not implemented.
	ErrNotSupported = "not_supported"
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
	GrantCIBA              = "urn:openid:params:grant-type:ciba"               // OIDC CIBA Core 1.0 §10.1
)

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
}
