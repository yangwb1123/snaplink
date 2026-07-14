package core

// HTTP header names and well-known values.
const (
	HeaderAuthorization = "Authorization"
	// HeaderIdempotencyKey is the HTTP header clients set to enable
	// safe retry on the /token endpoint — the server caches the first
	// successful response under this key and returns it for repeat
	// requests, preventing duplicate token issuance on network retries.
	HeaderIdempotencyKey = "Idempotency-Key"
	HeaderContentType    = "Content-Type"
	// HeaderAccept is the request header a client sets to content-negotiate
	// an alternate response representation — e.g. RFC 9701-style signed JWT
	// introspection responses (Accept: application/token-introspection+jwt).
	HeaderAccept = "Accept"
	// HeaderContentDisposition marks the tenant-export response as a
	// downloadable attachment (see interfaces/admin's tenant export
	// handler) so a browser/admin UI saves it as a file rather than
	// rendering the JSON inline.
	HeaderContentDisposition   = "Content-Disposition"
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

	// HeaderAcceptLanguage is read ONLY by the opt-in i18n enrichment
	// (shared/i18n.PreferredLocale) to pick a locale for
	// error_description_localized — never for anything security- or
	// routing-relevant, so there is no X-Forwarded-*-style trust concern.
	HeaderAcceptLanguage = "Accept-Language"
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

	// ContentTypeTokenIntrospectionJWT is both the RFC 9701 §5 `Accept`
	// request header value an introspecting client sends to opt into a
	// JWT-formatted /token/introspect response, and the `Content-Type`
	// the response carries when the server honors it.
	ContentTypeTokenIntrospectionJWT = "application/token-introspection+jwt"
	// JWTTypIntrospection is the RFC 9701 §5.1 JOSE `typ` header value
	// stamped on a signed introspection-response JWT. Deliberately
	// DISTINCT from the generic "JWT" typ used for ID/metadata/userinfo
	// JWTs — §8 relies on it so a resource server (or an on-path
	// attacker) can never mistake this response for a bearer access
	// token by typ alone.
	JWTTypIntrospection = "token-introspection+jwt"

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

	// HeaderDeviceID is a client-supplied opaque device identifier (a mobile
	// app's persisted install UUID, a first-party browser cookie) that feeds
	// the zero-trust conditional-access engine's DeviceFingerprint lookup at
	// /auth/login. Deliberately NOT a trust boundary: an absent or spoofed
	// value only ever degrades the CAP engine's device-posture signal to
	// PostureUnknown (its already-conservative default), it is never treated
	// as a credential or an identity claim.
	HeaderDeviceID = "X-Device-Id"
)

// JSON response keys used across handlers.
const (
	KeyError            = "error"
	KeyErrorDescription = "error_description"
	// KeyErrorDescriptionLocalized is the OPT-IN additive field a Localizer
	// (shared/i18n) contributes alongside KeyErrorDescription — never
	// instead of it. Absent unless a Localizer is configured AND it has a
	// translation for this (code, locale) pair.
	KeyErrorDescriptionLocalized = "error_description_localized"
	// KeyTraceID is the optional error-envelope field carrying the
	// request's W3C trace ID (see TraceIDFromContext), so a client can
	// hand support the exact value that correlates to server-side
	// audit/trace records without having to capture response headers.
	KeyTraceID         = "trace_id"
	KeyStatus          = "status"
	KeyIssuer          = "issuer"
	KeyVersion         = "version"
	KeyVCSRevision     = "vcs_revision"
	KeyVCSTime         = "vcs_time"
	KeyProviders       = "providers"
	KeySupportedGrants = "supported_grants"
	KeySessionID       = "session_id"
	KeyAccessToken     = "access_token"
	KeyRefreshToken    = "refresh_token"
	KeyTokenType       = "token_type"
	KeyExpiresIn       = "expires_in"
	KeyScope           = "scope"
	KeyRevoked         = "revoked"
	KeyTokenStrategy   = "token_strategy"
	KeyRecommendedLang = "recommended_language"
	KeyCountryCode     = "country_code"
	// KeyServingRegion names the region deployment that served the login
	// response (multi-region / data-residency layer). DISTINCT from
	// geo's "region" (an ISO 3166-2 client-IP subdivision) — this is WHICH
	// deployment served, not WHERE the client is.
	KeyServingRegion   = "serving_region"
	KeyCode            = "code"
	KeyState           = "state"
	KeyRedirectURI     = "redirect_uri"
	KeyIssuedTokenType = "issued_token_type" // RFC 8693 token-exchange response key
	// KeySessionState is the OpenID Connect Session Management 1.0 §2
	// `session_state` authentication-response field — present only when
	// WithOIDCSessionManagement is wired AND the request carried the
	// `openid` scope (an RP with no session-management support just
	// ignores the extra field).
	KeySessionState = "session_state"

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
	KeySID      = "sid"

	// RFC 7662 §2.2 / RFC 8705 §3.3 / RFC 9449 §7 confirmation member —
	// introspection echoes the token's `cnf` so a resource server can enforce
	// sender-constraint binding (mTLS x5t#S256 / DPoP jkt).
	KeyCnf        = "cnf"
	KeyCnfX5TS256 = "x5t#S256"
	KeyCnfJKT     = "jkt"

	// KeyTokenIntrospection is the RFC 9701 §5.1 claim that nests the full
	// RFC 7662 introspection response inside the signed JWT wrapper. The
	// nesting (rather than flattening `active`/`sub`/`exp`/etc. onto the
	// JWT's own top-level claims) is the RFC's defense against a naive
	// verifier mistaking the introspection JWT for a bearer access token.
	KeyTokenIntrospection = "token_introspection"

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

	// Cross-tenant B2B collaboration audit metadata keys (domains/tenant)
	// — written via audit.SetMeta on the cross_tenant_token_exchange event.
	// original_subject/original_tenant are the SPEC-NAMED fields a SIEM traces
	// a guest action back to its home account with; guest_tenant_id completes
	// the picture with the tenant that granted the guest access.
	KeyOriginalSubject = "original_subject"
	KeyOriginalTenant  = "original_tenant"
	KeyGuestTenantID   = "guest_tenant_id"

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
	PathAdminTokenExpiring   = "/admin/tokens/expiring"
	PathAdminTokenSuspicious = "/admin/tokens/suspicious"
	PathAdminTokenRevoke     = "/admin/tokens/revoke"
)

// PathAdminTokenExchangeChain is the RFC 8693 token-exchange delegation-chain
// read endpoint (pure observability; WithTokenExchangeChainStore). Group-
// relative on the /api/v1 router group; admin-gated (GET admin:read).
const PathAdminTokenExchangeChain = "/admin/tokenexchange/chains/:jti"

// PathAdminFederationHealth is the read-only admin listing of federation
// peer metadata health: last fetch success/failure, consecutive failures,
// and last-observed TLS certificate expiry (+ a derived cert_expiring
// flag). Full path (not group-relative), gated by AdminMiddleware via the
// /api/v1/admin/ prefix — mirrors PathStorageHealth. Only mounted when a
// federation.ConnectionHealth store is wired (opt-in
// WithFederationConnectionHealth); pure observability, never consulted by
// trust-chain validation. Relocated from consts.go to keep that file within
// the per-file line budget while shared/core stays at its frozen file count.
const (
	PathAdminFederationHealth = "/api/v1/admin/federation/health"
)

// PathAdminCryptoKeys / PathAdminCryptoKeyCompromise back the
// cryptographic-material inventory (GET admin:read; POST admin:write) —
// see platform/lifecycle/cryptoinventory. Mounted only when
// WithCryptoInventory is wired. Relocated from consts.go for the same
// per-file budget reason as PathAdminFederationHealth above.
const (
	PathAdminCryptoKeys          = "/admin/crypto/keys"
	PathAdminCryptoKeyCompromise = "/admin/crypto/keys/:id/compromise"
)

// PathCheckSessionIframe is the OpenID Connect Session Management 1.0 §2
// check_session_iframe endpoint — the OP-hosted, RP-embeddable static page a
// hidden iframe uses to detect End-User login-state changes. Path segment
// name matches the discovery field name verbatim (spec convention: RPs
// discover it as `check_session_iframe`, not a generic "/session" path).
// Relocated from consts.go for the same per-file budget reason as the other
// consts in this file.
const (
	PathCheckSessionIframe = "/check_session_iframe"
)

// Generic event/webhook egress engine (platform/lifecycle/webhook, opt-in
// sso.WithWebhookEngine): admin subscription management + dead-letter-queue
// inspection/replay. Group-relative on the /api/v1 router group; GET is
// admin:read, POST/DELETE are admin:write via the default AdminMiddleware
// method-scope rule. Mounted only when an Engine is wired — byte-identical
// to a build without the feature.
const (
	PathAdminWebhookSubscriptions    = "/admin/webhooks/subscriptions"
	PathAdminWebhookSubscriptionByID = "/admin/webhooks/subscriptions/:id"
	PathAdminWebhookDeadLetters      = "/admin/webhooks/deadletters"
	PathAdminWebhookDeadLetterReplay = "/admin/webhooks/deadletters/:id/replay"
)

// Generic webhook egress engine response keys.
const (
	KeyWebhookSubscriptions = "subscriptions"
	KeyWebhookSubscription  = "subscription"
	KeyWebhookDeadLetters   = "dead_letters"
	KeyWebhookDeadLetter    = "dead_letter"
)

// ReBAC relationship-tuple engine (platform/lifecycle/rebac, opt-in
// sso.WithRebacEngine): a single operational-debugging admin:read endpoint
// over the Check engine. Mounted only when an Engine is wired —
// byte-identical to a build without the feature.
const (
	PathAdminRebacCheck = "/admin/rebac/check"
)

// Pluggable WASM authorization-decision engine (platform/lifecycle/wasmauthz,
// opt-in sso.WithWASMAuthzEngine): a single operational-debugging
// admin:read endpoint over the hosted policy module's Authorize call.
// POST (not GET, unlike PathAdminRebacCheck) because the request body has a
// richer, nested shape (a Context map) than fits cleanly into query
// parameters. Mounted only when an Engine is wired — byte-identical to a
// build without the feature.
const (
	PathAdminWASMAuthzCheck = "/admin/wasmauthz/check"
)

// WASM authz Check response keys.
const (
	KeyWASMAuthzAllowed = "allowed"
	KeyWASMAuthzReason  = "reason"
)

// ReBAC Check response keys.
const (
	KeyRebacAllowed  = "allowed"
	KeyRebacObject   = "object"
	KeyRebacRelation = "relation"
	KeyRebacSubject  = "subject"
)

// PathAdminChanges / PathAdminChangeByID / PathAdminChangeApprove /
// PathAdminChangeReject serve the generic change-approval workflow
// (platform/lifecycle/admingovernance). Relocated from consts.go for the same
// per-file budget reason as the other consts in this file.
const (
	PathAdminChanges       = "/admin/changes"
	PathAdminChangeByID    = "/admin/changes/:id"
	PathAdminChangeApprove = "/admin/changes/:id/approve"
	PathAdminChangeReject  = "/admin/changes/:id/reject"
)

// PathAPIVersionPreview is the ADR-0008 v2alpha proof-of-mechanism route: a
// single read-only capability probe (GET) demonstrating that a "/api/v2alpha"
// path-prefix CAN be routed, without committing to a full v2 API surface.
// Full path (not group-relative — it deliberately sits OUTSIDE the stable
// /api/v1 group). Only mounted when WithAPIVersionPreview is wired
// (byte-identical off otherwise). Relocated here (not consts.go) because
// consts.go is at its per-file line budget.
const PathAPIVersionPreview = "/api/v2alpha/version"

// B2B connections/tenant-membership/org-invitation/delegated-org-admin path
// consts, relocated from consts.go for the same per-file budget reason as
// the other consts in this file.
const (
	// PathAdminConnections / PathAdminConnectionByID manage B2B enterprise
	// connections at runtime (list/get/upsert/delete) so operators can onboard a
	// new org's upstream IdP without a redeploy (config seeding only runs at
	// boot). GET ?tenant_id= lists a tenant's connections; admin:read for GET,
	// admin:write for POST/DELETE. Mounted only when a connection store is wired.
	PathAdminConnections    = "/admin/connections"
	PathAdminConnectionByID = "/admin/connections/:id"

	// PathAdminConnectionDomains lists a connection's email-domain ownership
	// claims (admin:read) — each with its DNS-TXT challenge record + status.
	// PathAdminConnectionDomainVerify triggers a synchronous DNS-TXT check for
	// one claimed domain (admin:write): a verified claim by ANOTHER connection
	// blocks routing takeover, so a new claimant must prove DNS control here.
	PathAdminConnectionDomains      = "/admin/connections/:id/domains"
	PathAdminConnectionDomainVerify = "/admin/connections/:id/domains/:domain/verify"

	// PathAdminConnectionHealth returns a connection's last recorded probe
	// outcome — status/last-success/last-error (admin:read). Never triggers a
	// fresh probe itself. PathAdminConnectionProbe synchronously triggers ONE
	// (OIDC discovery fetch or SAML metadata fetch, per Connection.Type) and
	// persists the result (admin:write). Mounted only when a connection store
	// is wired.
	PathAdminConnectionHealth = "/admin/connections/:id/health"
	PathAdminConnectionProbe  = "/admin/connections/:id/probe"

	// PathAdminTenantMembers / PathAdminTenantMemberByID manage a tenant's org
	// roster (B2B membership, distinct from SCIM app roles). GET lists the roster
	// (admin:read); PUT upserts a member's role + DELETE removes (admin:write).
	// Mounted only when a TenantUserStore is wired.
	PathAdminTenantMembers    = "/admin/tenants/:id/members"
	PathAdminTenantMemberByID = "/admin/tenants/:id/members/:user_id"

	// PathAdminTenantExport triggers + downloads a coherent offboarding/
	// migration bundle for one tenant (clients, roster, connections,
	// permissions, session + audit summaries — see
	// protocols/compliance.TenantExporter). POST, admin:write — deliberately
	// above the GET-default admin:read like PathBackup, since assembling this
	// bundle is a heavier, more sensitive operation than the roster/connection
	// GETs. Mounted only when a TenantUserStore is wired (see mountAdminB2B).
	PathAdminTenantExport = "/admin/tenants/:id/export"

	// PathMyOrganizations / PathMyOrganizationByID are the self-service org views:
	// GET lists the orgs the bearer subject belongs to; DELETE leaves one. Mounted
	// only when a TenantUserStore is wired.
	PathMyOrganizations    = "/me/organizations"
	PathMyOrganizationByID = "/me/organizations/:tenant_id"

	// PathAdminTenantInvitations sends (POST {email, role}) + lists (GET) pending
	// org invitations for a tenant. admin:write / admin:read. Mounted only when an
	// InvitationStore is wired.
	PathAdminTenantInvitations = "/admin/tenants/:id/invitations"

	// PathAdminTenantInvitationByEmail revokes (DELETE) every pending org
	// invitation for a recipient email. admin:write. Mounted only when an
	// InvitationStore is wired.
	PathAdminTenantInvitationByEmail = "/admin/tenants/:id/invitations/:email"

	// PathMyInvitationAccept redeems an org invitation token (POST {token}): the
	// authenticated subject joins the invited tenant at the invited role. Mounted
	// only when an InvitationStore AND a TenantUserStore are wired.
	PathMyInvitationAccept = "/me/invitations/accept"

	// Delegated org-admin surface (w2.11). A TenantRoleAdmin of :tenant_id manages
	// ONLY that org's roster + invitations via the SUBJECT bearer, WITHOUT holding
	// the platform-wide admin scope. These hang off the /me self-service tree (not
	// /api/v1/admin, which is unconditionally gated by the global admin scope) and
	// are authorized by tenant-admin MEMBERSHIP; :tenant_id comes from the path
	// only. Mounted only when a TenantUserStore is wired (invitation sub-block also
	// needs an InvitationStore).
	//
	// PathOrgAdminMembers / PathOrgAdminMemberByID: GET the roster; PUT changes an
	// EXISTING member's role (invite-only growth — non-member target is a 404, not
	// a direct add); DELETE removes a member.
	PathOrgAdminMembers    = "/me/organizations/:tenant_id/members"
	PathOrgAdminMemberByID = "/me/organizations/:tenant_id/members/:user_id"

	// PathOrgAdminInvitations sends (POST {email, role}) + lists (GET, never the
	// token) pending invitations for the admin's own org.
	PathOrgAdminInvitations = "/me/organizations/:tenant_id/invitations"

	// PathOrgAdminInvitationByEmail revokes (DELETE) every pending invitation for a
	// recipient email in the admin's own org.
	PathOrgAdminInvitationByEmail = "/me/organizations/:tenant_id/invitations/:email"
)

// Threat-policy admin path constants (Active ITDR detection-to-response bridge).
// Group-relative on the /api/v1 router group; GET is admin:read, PUT/DELETE are
// admin:write via the default AdminMiddleware method-scope rule. Mounted only when
// a ThreatPolicyStore is wired — byte-identical to a build without the feature.
const (
	PathAdminThreatPolicies   = "/admin/threat-policies"
	PathAdminThreatPolicyByID = "/admin/threat-policies/:name"
)
