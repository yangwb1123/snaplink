package core
// Endpoint paths registered by Server.Mount.
const (
	PathHealth         = "/health"
	PathLivez          = "/livez"
	PathReadyz         = "/readyz"
	PathMetrics        = "/metrics"
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
	// PathMeSessions*, PathMeSessionByID, and PathMeSessionsRevokeAll are the
	// /me/*-namespace variants of the /sessions/me* paths. These follow the
	// self-service /me/* convention (cf. PathMe, PathMyMFA) and provide a
	// single discoverable prefix for the self-service portal SPA.
	PathMeSessions          = "/me/sessions"
	PathMeSessionByID       = "/me/sessions/:id"
	PathMeSessionsRevokeAll = "/me/sessions/revoke-all"
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
	// PathOAuthAuthorizationServerMetadata is the RFC 8414 §3 well-known
	// path for OAuth 2.0 Authorization Server Metadata. Served by the SAME
	// handler as the OIDC discovery document — that document is a compatible
	// superset of RFC 8414 §2 metadata (clients ignore unknown fields), so
	// pure-OAuth clients (notably MCP agents, which resolve this suffix
	// rather than openid-configuration) can discover the AS without OIDC.
	PathOAuthAuthorizationServerMetadata = "/.well-known/oauth-authorization-server"
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
	// PathVerifyEmail is the unauthenticated endpoint for completing signup
	// email verification (POST {token}). Consumes the token and atomically
	// creates the user. Only mounted when signup with require_verification is
	// enabled.
	PathVerifyEmail = "/auth/verify-email"
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
	// PathMyMFARecoveryCodes is self-service MFA recovery-code management:
	// POST regenerates the batch (revoke-then-generate), returning the
	// plaintext codes exactly once; GET returns the remaining count only
	// (never the codes). Mounted only when a RecoveryCodeStore is wired.
	PathMyMFARecoveryCodes = "/me/mfa/recovery-codes"
	// PathMyDevices lists the authenticated user's trusted (MFA-skip) devices
	// (GET); PathMyDeviceByID revokes one (DELETE). PathMyDevicesTrust marks
	// the CURRENT device trusted (POST) — gated on the caller's bearer token
	// having completed MFA THIS session (amr contains "mfa"), so a stolen
	// session that never stepped up can never mint a skip grant.
	PathMyDevices       = "/me/devices"
	PathMyDeviceByID    = "/me/devices/:id"
	PathMyDevicesTrust      = "/me/devices/trust"
	PathMyDeviceTrustByID   = "/me/devices/:id/trust"
	PathMyDeviceActivity    = "/me/devices/:id/activity"
	PathMyDeviceLost      = "/me/devices/:id/lost"
	PathMyDeviceSessions  = "/me/devices/:id/sessions"
	PathMyLoginHistory       = "/me/login-history"
	PathMySecurityActivity   = "/me/security/activity"
	PathMeSessionsEnriched   = "/me/sessions/enriched"
	PathLoginUIMetadata      = "/login-ui/metadata"
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
	// PathBackup is the admin backup trigger endpoint
	// (POST /api/v1/admin/backup). Runs VACUUM INTO on each registered
	// BackupSource and lists the backup results. Gated by AdminMiddleware
	// (admin:write).
	//
	// Group-relative: mounted on the /api/v1 router group (see the
	// PathTenantUsage comment below for the double-prefix regression a
	// full "/api/v1/..." value causes — this constant previously had
	// that bug, which made the endpoint permanently unreachable).
	PathBackup = "/admin/backup"
	// BackupFilePrefix names admin-triggered backup files
	// (<prefix><source>-<utc-stamp>.db); the retention pruner filters on
	// it so unrelated files sharing the destination dir are never deleted.
	BackupFilePrefix = "sso-backup-"
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
	// PathAdminTopTenants is the read-only admin top-tenants usage leaderboard
	// (GET /api/v1/admin/usage/top-tenants?period=day|month&start=...&limit=N).
	// Returns the N tenants with the most successful logins in the period,
	// with the same aggregated counters as PathTenantUsage. Gated by
	// AdminMiddleware (admin:read). Only mounted when
	// WithTenantUsageAggregator is wired.
	//
	// Group-relative: mounted on the /api/v1 router group — see the
	// PathTenantUsage comment for the double-prefix regression a full
	// "/api/v1/..." value causes.
	PathAdminTopTenants = "/admin/usage/top-tenants"
	// PathAdminTokenUsage is the read-only admin token-usage telemetry
	// endpoint (GET /api/v1/admin/tokens/usage?client_id=&since=&until=).
	// Returns per-minute aggregated (client, kind, endpoint) buckets from
	// the opt-in token-usage store — the operator question "which clients
	// are issuing/introspecting which token kinds, how much" that raw
	// audit events don't answer at scale. Gated by AdminMiddleware
	// (admin:read). Only mounted when WithTokenUsageRecorder is wired.
	//
	// Group-relative: mounted on the /api/v1 router group — see the
	// PathTenantUsage comment for the double-prefix regression a full
	// "/api/v1/..." value causes.
	PathAdminTokenUsage = "/admin/tokens/usage"
	// PathAdminTokenPolicies is the read-only admin token-policy governance
	// view (GET /api/v1/admin/token-policies): the active token-policy rule
	// set in force on this replica — max_ttl / max_refresh_depth /
	// max_active_sessions / require_renew / block_scope_combos. Governance
	// metadata only (client/scope selectors + numeric limits, no secrets).
	// Gated by AdminMiddleware (admin:read); only mounted when
	// WithTokenPolicy is wired.
	//
	// Group-relative: mounted on the /api/v1 router group — see the
	// PathTenantUsage comment for the double-prefix regression a full
	// "/api/v1/..." value causes.
	PathAdminTokenPolicies = "/admin/token-policies"
	// PathAdminAccessPolicies is the read-only zero-trust conditional-access
	// (CAP) policy governance view (GET /api/v1/admin/access-policies). It
	// returns the wired policies ordered by evaluation precedence so an
	// operator sees exactly the order the engine resolves them in. Gated by
	// AdminMiddleware (admin:read). Only mounted when WithConditionalAccess is
	// wired.
	PathAdminAccessPolicies = "/admin/access-policies"
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
	// PathAdminUserLifecycle is the user-lifecycle state-machine endpoint: GET
	// (admin:read) returns the account's current lifecycle state, the moves
	// legal from it, and its transition history; POST (admin:write) requests a
	// transition validated against the legal-transition table. Group-relative;
	// gated by AdminMiddleware. Mounted only when a userlifecycle.Store AND a
	// UserProvider are wired.
	PathAdminUserLifecycle = "/admin/users/:id/lifecycle"
	// PathAdminUserRecoveryCodes is the helpdesk MFA recovery reset (POST,
	// admin:write): it revokes ALL of a user's remaining recovery codes and
	// NEVER returns codes to the operator (the user regenerates their own via
	// PathMyMFARecoveryCodes). Mounted only when a RecoveryCodeStore is wired.
	PathAdminUserRecoveryCodes = "/admin/users/:id/mfa/recovery-codes"
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
	// PathAdminUserRefreshTokens revokes ALL of a user's outstanding OAuth 2.0
	// refresh tokens across EVERY client (DELETE, admin:write) — the helpdesk
	// "compromised account, log out everywhere right now" lockout. Complements
	// the self-service /token/revoke-all and /me/sessions/revoke-all, which only
	// reach the AUTHENTICATED caller's own tokens; this reaches an arbitrary
	// user on an admin's behalf. Group-relative. Mounted only when the wired
	// RefreshTokenStore implements the optional RefreshTokenSubjectIndex
	// extension (else 501).
	PathAdminUserRefreshTokens = "/admin/users/:id/refresh-tokens"
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
	// PathAdminEndpoints serves the runtime endpoint inventory (GET,
	// admin:read): every route this replica registered, its method, and the
	// FeatureGates surface it belongs to. Group-relative; gated by
	// AdminMiddleware like the rest of /api/v1/admin/. Always mounted
	// whenever the admin surface itself is (AdminAPI on) — an operator asking
	// "what's actually exposed" should never itself require guessing a flag.
	PathAdminEndpoints = "/admin/endpoints"
	// PathAdminTokens lists active admin bearer tokens (GET, admin:read).
	// PathAdminTokenByID revokes a single admin token (DELETE, admin:write).
	// Group-relative; gated by AdminMiddleware. Mounted only when an
	// AdminTokenStore is wired.
	PathAdminTokens    = "/admin/tokens"
	PathAdminTokenByID = "/admin/tokens/:id"
	// PathAdminLogout revokes the admin bearer token used in the current
	// request (POST, admin:write). Mounted only when an AdminTokenStore
	// is wired. The token ID is extracted from the request context via
	// auth middleware; on success the caller should discard the token.
	PathAdminLogout = "/admin/logout"
	// Break-glass (emergency support) admin sessions. POST creates a
	// bounded, audited on-behalf-of grant (admin:write; reason mandatory);
	// GET lists pending + active grants (admin:read); DELETE revokes one
	// and cascades destruction of its impersonation sessions (admin:write);
	// POST .../approve activates a pending grant — the approver MUST
	// differ from the creator. Group-relative; gated by AdminMiddleware.
	// Mounted only when a BreakGlassStore is wired.
	PathAdminBreakGlass        = "/admin/break-glass"
	PathAdminBreakGlassByID    = "/admin/break-glass/:id"
	PathAdminBreakGlassApprove = "/admin/break-glass/:id/approve"
	// PathAdminBreakGlassImpersonate mints the live-impersonation bearer for an
	// active+approved impersonate/escalate grant (admin:write). The bearer
	// authenticates as the TARGET user under the target's own permission
	// boundary and expires no later than the grant window.
	PathAdminBreakGlassImpersonate = "/admin/break-glass/:id/impersonate"
	// PathAdminSessions lists all active user sessions (GET, admin:read).
	// Returns the full session list from SessionManager.ListAll. Mounted
	// only when a SessionManager is wired. The admin SPA calls this to
	// render the active-sessions overview.
	PathAdminSessions = "/admin/sessions"
	// PathAdminUserSessions lists the active sessions of ONE user (GET,
	// admin:read) — complements PathAdminSessions (which lists EVERYONE's
	// sessions) with the per-user view the admin console needs to show "user
	// X's active logins" without the operator filtering the global list.
	// Mounted only when a SessionManager is wired. The gRPC equivalent is
	// TokenAdminService.ListSessions with UserId set.
	PathAdminUserSessions = "/admin/users/:id/sessions"
	// PathAdminCredentials is the read-only admin inventory of every
	// credential class registered with the platform/rotation Scheduler (GET,
	// admin:read): type, version, lifecycle status, created_at, and next
	// rotation due — GOVERNANCE data only, NEVER the secret material itself
	// (mirrors PathStorageHealth: observability without a trust-boundary
	// crossing). Group-relative; gated by AdminMiddleware. Mounted only when
	// WithCredentialRotation is wired.
	PathAdminCredentials = "/admin/credentials"
	// PathAdminCredentialCompromise is the emergency compromise-response
	// endpoint (POST, admin:write): declare a credential class leaked to
	// force an off-schedule rotation with NO overlap window — the leaked
	// version is retired instantly. Returns the new version's GOVERNANCE
	// metadata only, NEVER the secret material. Group-relative; gated by
	// AdminMiddleware. Mounted only when WithCredentialCompromise is wired.
	PathAdminCredentialCompromise = "/admin/credentials/:type/compromise"
	// PathAdminEventsStream is the realtime admin event source (GET,
	// admin:read, text/event-stream — see platform/sse). Group-relative;
	// gated by AdminMiddleware via the /api/v1/admin/ prefix like every
	// other admin path here. Mounted only when a Broker is wired
	// (WithSSEBroker) — byte-identical to a build without it.
	PathAdminEventsStream = "/admin/events/stream"
	// The B2B connections/tenant-membership/org-invitation/delegated-org-admin
	// path block (PathAdminConnections..PathOrgAdminInvitationByEmail) moved to
	// consts_wire.go to keep this file within the per-file line budget.
	// PathAdminConnectionHealth/PathAdminConnectionProbe and
	// PathAdminTenantExport live there too, alongside PathAdminConnectionDomains
	// and PathAdminTenantMembers respectively.
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
	PathSSFConfig  = "/.well-known/ssf-configuration"
	PathSSFStreams    = "/ssf/streams"
	PathSSFStreamByID = "/ssf/streams/:id"
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
	// PathFederationResolve is the OpenID Federation 1.0 §8.3 resolve endpoint.
	// Returns a JSON trust chain for a given entity identifier
	// (GET ?sub=<entity_id>) — leaf configuration → subordinate statements →
	// anchor configuration, leaf-first. Missing sub → 400; unresolvable → 404
	// (oracle-safe). Only mounted with trust anchors configured; no-store cache.
	PathFederationResolve       = "/.well-known/openid-federation-resolve"
	PathFederationTrustMarkStatus = "/.well-known/openid-federation-trust-mark-status"
	// PathFederationList is the OpenID Federation 1.0 §8.2 Federation Listing
	// endpoint. When this server is configured as a federation SUPERIOR (one or
	// more subordinates in federation.Config), it serves a JSON array listing
	// the configured subordinate entities with their entity identifiers and
	// metadata. Only mounted when subordinates are configured; public metadata
	// (Cache-Control public, max-age).
	PathFederationList = "/.well-known/openid-federation-list"
	PathNetPolicies        = "/netpolicy/policies"
	PathNetPolicyByName    = "/netpolicy/policies/:name"
	PathNetPolicyClassify  = "/netpolicy/classify"
	PathNetPolicyResolveMe = "/netpolicy/resolve-me"
	// SAML 2.0 canonical mount points for the external/forked SAML module.
	// PathSAMLMetadata serves the IdP entity descriptor; PathSAMLSSO is the
	// IdP-side SSO receiver (AuthnRequest in); PathSAMLSSOCallback is the
	// SP-side ACS. PathSAMLSLO is the IdP-side SLO receiver (LogoutRequest
	// from a downstream SP); PathSAMLSPSLO is the SP-side SLO receiver
	// (LogoutRequest from the upstream IdP). PathSAMLSLOContinue is the
	// IdP-side front-channel SLO chain resume endpoint — the browser returns
	// here after each SP terminates its local session. The core module ships
	// NO SAML/XML dependency — these are plain path literals only.
	PathSAMLMetadata    = "/saml/metadata"
	PathSAMLSSO         = "/saml/sso"
	PathSAMLSSOCallback = "/auth/saml/callback"
	PathSAMLSLO         = "/saml/slo"
	PathSAMLSLOContinue = "/saml/slo/continue"
	PathSAMLSPSLO       = "/auth/saml/slo"
	// PathStatus is the unauthenticated runtime server status endpoint.
	// Returns version, uptime, and module health. Public (no auth required).
	PathStatus = "/api/v1/status"
	// PathAdminConfigRunning / PathAdminConfigApplied / PathAdminConfigDiff /
	// PathAdminConfigHistory serve the runtime-configuration-audit admin API
	// (GET, admin:read): the server's CURRENT effective config snapshot, the
	// config captured at STARTUP, an RFC 6902 JSON Patch between the two, and
	// the persisted config_history change log. Every snapshot/patch value is
	// redacted (secret/password/dsn/token/key-shaped fields become "***").
	// Mounted only when a config-snapshot source is wired
	// (sso.WithConfigSnapshots); the history endpoint additionally requires
	// sso.WithConfigAuditStore.
	PathAdminConfigRunning     = "/admin/config/running"
	PathAdminConfigApplied     = "/admin/config/applied"
	PathAdminConfigDiff        = "/admin/config/diff"
	PathAdminConfigHistory     = "/admin/config/history"
	PathAdminConfigClusterDiff = "/admin/config/cluster-diff" // POST, admin:read override; see platform/configaudit.HandleClusterDiff
)
