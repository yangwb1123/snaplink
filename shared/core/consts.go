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
	PathMeSessions         = "/me/sessions"
	PathMeSessionByID      = "/me/sessions/:id"
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

	// PathStatus is the unauthenticated runtime server status endpoint.
	// Returns version, uptime, and module health. Public (no auth required).
	PathStatus = "/api/v1/status"
)
