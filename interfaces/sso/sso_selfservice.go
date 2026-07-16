package sso

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/identitylink"
	"github.com/snaplink/sso/domains/metering"
	"github.com/snaplink/sso/domains/userlifecycle"
	"github.com/snaplink/sso/platform/lifecycle/cryptoinventory"
	"github.com/snaplink/sso/platform/lifecycle/rotation"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/selfservice"
	"github.com/snaplink/sso/protocols/selfservice/selfservicecore"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// ConsentChallengeStore is the pluggable backend for the consent-gate's
// single-use challenge nonce (Issue on the consent-required /auth/login,
// Consume on the approve re-POST). The default in-process consent.ChallengeStore
// is single-replica; a cluster-shared impl (redis) with the SAME method set
// keeps the issue/approve round-trip working behind a no-affinity load balancer.
// Signatures match consent.ChallengeStore, which satisfies this structurally.
type ConsentChallengeStore interface {
	// Issue binds a challenge to (userID, clientID, scopes,
	// authorizationDetails) and returns an opaque challenge ID.
	Issue(userID, clientID string, scopes []string, authorizationDetails json.RawMessage) string
	// Consume validates and atomically removes the challenge. Returns true
	// only when all four bound fields match exactly and the challenge has
	// not expired. The authorizationDetails binding prevents a client from
	// changing RAR payload between the consent prompt and the re-POST.
	Consume(id, userID, clientID string, scopes []string, authorizationDetails json.RawMessage) bool
}

// selfServiceState holds consent, signup, password-reset, email-change, MFA enrollment, data export/erasure, invitations, usage, JWKS body cache, and SPA-FS fields.
type selfServiceState struct {
	// consentStore persists end-user consent decisions (WithConsentStore).
	// When nil all consent checks are skipped — behavior is byte-identical
	// to a build without the feature.
	consentStore ConsentStore

	// backupSources holds the SQLite stores that support online backup
	// via VACUUM INTO. The admin endpoint POST /api/v1/admin/backup
	// enumerates these sources and streams each to the operator.
	backupSources []core.BackupSource

	// backupDir overrides where admin-triggered backups land
	// (WithBackupDir). Empty = os.TempDir(), preserving the
	// pre-config behavior of writing under the OS temp dir.
	backupDir string
	// backupKeep bounds retained backup files per source
	// (WithBackupRetention). 0 = keep everything.
	backupKeep int

	// adminTokenStore persists admin bearer token metadata for
	// lifecycle management (list, revoke). Without this store,
	// admin tokens can only be revoked by clearing the underlying
	// credential store.
	adminTokenStore core.AdminTokenStore

	// adminSessionTTL sets an idle timeout for admin bearer tokens
	// (WithAdminSessionTTL). When non-zero, the admin middleware
	// rejects requests from tokens idle longer than this duration.
	// 0 means no idle timeout (default).
	adminSessionTTL time.Duration

	// breakGlassStore persists break-glass (emergency support) admin
	// sessions (WithBreakGlassStore) — bounded, audited on-behalf-of grants
	// for SOC 2 CC6.1/CC6.2, PCI DSS 7.2, HIPAA §164.312(a) support
	// workflows. Nil ⇒ the /api/v1/admin/break-glass* routes are NOT
	// mounted — byte-identical to a build without the feature.
	breakGlassStore core.BreakGlassStore

	// consentMaxTTL is the hard server-level ceiling on consent grant
	// lifetime (WithConsentTTL). When >0, every recorded consent has
	// ExpiresAt = GrantedAt + consentMaxTTL. After that, GetConsent
	// returns ErrNoConsentGrant — the user must re-authorize. 0 (default)
	// means no server-enforced expiry (consent lives until revoked).
	consentMaxTTL time.Duration

	// authzRequestTimeout is the per-login handler wall-clock deadline
	// (WithAuthorizeRequestTimeout). When >0, handleLogin cancels the
	// request context after this duration and returns interaction_required.
	// 0 (default) means no server-enforced deadline.
	authzRequestTimeout time.Duration

	// scopeDescriptions maps a scope name to an operator-defined human
	// description (WithScopeDescriptions). Surfaced in the consent_required
	// response so the consent UI can render meaningful text for custom scopes
	// instead of the raw name. Nil/empty ⇒ no descriptions emitted.
	scopeDescriptions map[string]string

	// tenantUserStore persists explicit B2B org membership (WithTenantUserStore).
	// Nil ⇒ the admin roster + self-service /me/organizations endpoints are NOT
	// mounted — byte-identical to a build without it.
	tenantUserStore TenantUserStore

	// jitMembership opts into auto-provisioning org membership on login
	// (WithJITMembership): a user logging in via a tenant-bound client who isn't
	// yet on that tenant's roster is added as a member. Requires tenantUserStore.
	jitMembership bool

	// invitationStore persists single-use org-invitation tokens
	// (WithInvitationStore); invitationSender delivers them (WithInvitationSender).
	// The send + list endpoints mount only with the store; accept also requires a
	// tenantUserStore (the redeemed invite grants membership). Nil ⇒ none mounted.
	invitationStore  InvitationStore
	invitationSender spi.InvitationSender

	// passwordCredentialStore backs POST /me/password (WithPasswordCredentialStore).
	// Nil ⇒ the route is NOT mounted — byte-identical to a build without it.
	passwordCredentialStore PasswordCredentialStore

	// Forgot-password / account-recovery flow (POST /auth/forgot-password +
	// /auth/reset-password). All wired via WithPasswordReset*; the routes mount
	// only when passwordResetStore AND passwordCredentialStore are both set —
	// byte-identical to a build without them.
	passwordResetStore            PasswordResetStore
	passwordResetTTL              time.Duration
	passwordResetResolver         spi.PasswordResetResolver
	passwordResetDeliveryResolver spi.PasswordResetDeliveryResolver
	passwordResetSender           spi.PasswordResetSender

	// dataExporter backs GET /me/data-export — GDPR Art. 15 self-service export
	// of the bearer's OWN data (WithSelfServiceDataExport). Nil ⇒ not mounted.
	dataExporter *compliance.Exporter

	// accountEraser backs POST /me/account/erase — GDPR Art. 17 self-service
	// erasure of the bearer's OWN account (WithSelfServiceAccountErasure).
	// Irreversible; nil ⇒ not mounted (default-off — self-deletion is a
	// deliberate operator choice, not always desirable for managed accounts).
	accountEraser *compliance.Eraser

	// Verified email change (POST /me/email/change + /me/email/verify). Mounts
	// only when the store + sender + a UserProvider are all wired.
	emailChangeStore  EmailChangeStore
	emailChangeTTL    time.Duration
	emailChangeSender spi.EmailChangeSender

	// Signup email verification. emailVerificationStore persists verification
	// tokens (SHA-256 hashed); emailVerificationSender delivers them.
	// signupRequireVerification gates mandatory verification mode (Mode B);
	// emailVerificationTTL bounds token validity (default 15 min).
	emailVerificationStore    core.EmailVerificationStore
	emailVerificationSender   spi.EmailVerificationSender
	signupRequireVerification bool
	emailVerificationTTL      time.Duration

	// signupEnabled gates POST /auth/register (opt-in self-service signup).
	// Mounts only when also a UserProvider + PasswordCredentialStore are wired
	// (signup creates the user + sets the password). Default-off.
	signupEnabled bool

	// registrationGates holds zero or more spi.RegistrationGate instances
	// wired via WithRegistrationGates. Each gate is checked in order during
	// self-service signup, before the user is created. When none are wired
	// (the default), registration behaviour is unchanged (backward compat).
	// All gate errors collapse to a single 403 registration_denied response
	// (anti-enumeration).
	registrationGates []spi.RegistrationGate

	// signupRateLimiter is an optional per-IP rate limiter for POST /auth/register
	// (WithSelfServiceSignupRateLimiter). When non-nil, the handler checks the
	// caller's IP before processing the signup and returns 429 rate_limited when
	// the bucket is exhausted. Nil (the default) means no signup-specific rate
	// limiting — full backward compatibility.
	signupRateLimiter selfservicecore.RateLimiter

	// mfaEnrollmentStore backs GET/DELETE /me/mfa (WithMFAEnrollmentStore).
	// Nil ⇒ the routes are NOT mounted — byte-identical to a build without it.
	mfaEnrollmentStore MFAEnrollmentStore

	// recoveryCodeStore backs POST/GET /me/mfa/recovery-codes + the admin reset
	// (WithRecoveryCodeStore). Nil ⇒ those routes are NOT mounted —
	// byte-identical to a build without it.
	recoveryCodeStore RecoveryCodeStore

	// trustedDeviceStore backs the self-service GET/POST/DELETE /me/devices*
	// "remember this device" surface AND the /auth/login step-up-skip check
	// (WithTrustedDeviceStore). Nil ⇒ the self-service routes are NOT mounted
	// and a login NEVER skips a risk-scorer-demanded MFA challenge —
	// byte-identical to a build without this feature.
	trustedDeviceStore TrustedDeviceStore

	// trustedDeviceTTL bounds how long a single Trust grant can skip MFA
	// (WithTrustedDeviceStore's ttl argument). <= 0 ⇒ falls back to
	// core.DefaultTrustedDeviceTTL at read time (TrustedDeviceTTL()).
	trustedDeviceTTL time.Duration

	// totpEnroller backs POST /me/mfa/totp/{begin,confirm} (WithTOTPEnroller).
	// The enrollment routes mount only when this AND an mfaEnrollmentStore that
	// implements TOTPEnrollmentWriter are both wired — byte-identical off.
	totpEnroller TOTPEnroller

	// webauthnRegistrar backs POST /me/mfa/webauthn/{begin,finish} (authenticated
	// self-service passkey registration, WithWebAuthnRegistrar). Nil ⇒ routes
	// not mounted (byte-identical off).
	webauthnRegistrar WebAuthnRegistrar

	// selfEditableAttrs is the operator allowlist of User.Attributes keys a
	// user MAY change via PATCH /me (WithSelfEditableProfileAttributes). Empty
	// (the default) ⇒ PATCH /me may edit the display name only; any attributes
	// in the request are ignored. The allowlist is the escalation guard: it
	// keeps users from writing authz-relevant attribute keys (roles, tenant,
	// risk flags) the operator stores alongside presentation data.
	selfEditableAttrs map[string]struct{}

	// consentChallenges holds server-issued single-use consent challenge tokens
	// bound to (UserID, ClientID, Scopes), expiring after consent.ChallengeTTL.
	// Default is the in-process consent.ChallengeStore (single-replica);
	// WithConsentChallengeStore swaps in a cluster-shared backend (redis) so the
	// issue/approve round-trip survives a no-affinity load balancer.
	consentChallenges ConsentChallengeStore

	// usageAggregator backs GET /api/v1/admin/tenants/:id/usage
	// (WithTenantUsageAggregator). Nil ⇒ the route is NOT mounted —
	// byte-identical to a build without it.
	usageAggregator metering.Aggregator

	// credentialRegistry backs GET /api/v1/admin/credentials
	// (WithCredentialRotation) — the governance inventory (type, version,
	// status, next rotation due) of every credential class registered with
	// the platform/rotation Scheduler. NEVER exposes secret material. Nil ⇒
	// the route is NOT mounted — byte-identical to a build without it. The
	// Scheduler itself is started/stopped by the composition root (cmd), same
	// lifecycle discipline as the signing-key rotation loop — the Server only
	// reads the registry's snapshot.
	credentialRegistry *rotation.Registry

	// credentialScheduler backs POST /api/v1/admin/credentials/{type}/compromise
	// (WithCredentialCompromise) — the emergency compromise-response path. It is
	// the SAME rotation.Scheduler that drives scheduled rotation (it owns the
	// status store + dependent-party notifier the compromise fan-out reuses).
	// Nil ⇒ the route is NOT mounted — byte-identical to a build without it.
	credentialScheduler *rotation.Scheduler

	// cryptoInventory backs GET /api/v1/admin/crypto/keys and POST
	// /api/v1/admin/crypto/keys/:id/compromise (WithCryptoInventory) — the
	// cryptographic-material governance catalog (platform/lifecycle/
	// cryptoinventory): signing keys, JWE keys, KMS-backed keys, and any
	// manually-registered trust anchors, each with id/algorithm/purpose/
	// created_at/status/backing store. NEVER exposes key material. Nil ⇒
	// neither route is mounted — byte-identical to a build without the
	// feature.
	cryptoInventory cryptoinventory.Inventory

	// adminConsoleFS, when non-nil, serves the hosted admin console SPA from
	// an embedded or OS filesystem at /admin/. The console is a standalone
	// single-page app — it communicates with the server only via the standard
	// /api/v1/admin/* REST endpoints, which require a Bearer token with
	// admin:read or admin:write scope. Nil (the default) leaves /admin/
	// unmounted — byte-identical to a build without the console.
	adminConsoleFS fs.FS

	// hostedLoginFS, when non-nil, serves the hosted-login SPA from an
	// embedded or OS filesystem at /login/. The SPA calls /auth/login over
	// JSON — zero protocol changes to the OAuth/OIDC surface. Nil (the
	// default) leaves /login/ unmounted — byte-identical to a build without
	// it. Typically wired by the operator's cmd binary via go:embed.
	hostedLoginFS fs.FS

	// portalFS, when non-nil, serves the end-user self-service portal SPA from
	// an embedded or OS filesystem at /portal/. The portal is a standalone
	// browser client that calls /me, /sessions/me, /consents/me, /me/password
	// and /me/mfa with the end-user's own Bearer token. Nil (the default)
	// leaves /portal/ unmounted — byte-identical to a build without it.
	portalFS fs.FS

	// developerPortalFS, when non-nil, serves the developer-portal SPA from
	// an embedded or OS filesystem at /developer/. Unlike adminConsoleFS/
	// portalFS above, this SPA authenticates an ANONYMOUS third-party
	// developer, not an admin or logged-in end user: it calls POST
	// /register (RFC 7591 DCR) to self-register a client, then GET/PUT/
	// DELETE /register/:client_id (RFC 7592), authenticated by the
	// registration_access_token issued at registration. Nil (the default)
	// leaves /developer/ unmounted — byte-identical to a build without it.
	developerPortalFS fs.FS

	// apiDocsUIHandler and apiDocsSpecHandler, when non-nil, serve the
	// opt-in embedded API-documentation viewer (WithAPIDocsUI) at GET
	// .../admin/docs (self-contained HTML) and GET .../admin/docs/openapi.json
	// (the same document as plain JSON). Both hang off the AdminMiddleware-
	// gated /api/v1/admin/ group (mountAPIDocsUI, server_routes.go) — unlike
	// adminConsoleFS/hostedLoginFS/portalFS above, which are open static SPA
	// shells served OUTSIDE the router entirely, the full endpoint + schema
	// inventory this viewer exposes is operationally sensitive. Nil (the
	// default) leaves both routes unmounted — byte-identical to a build
	// without this option.
	apiDocsUIHandler   HandlerFunc
	apiDocsSpecHandler HandlerFunc

	// passwordPolicyValidator checks proposed passwords against operator-
	// configured complexity rules (WithPasswordPolicy). Nil (the default)
	// means no password policy is enforced — behavior is byte-identical to a
	// build without the feature.
	passwordPolicyValidator spi.PasswordPolicyValidator

	// passwordHistoryStore rejects password reuse at change time, when
	// PasswordPolicyConfig.MaxHistory > 0 (WithPasswordHistoryStore). A
	// SEPARATE mechanism from passwordPolicyValidator above — see that
	// option's doc for why. Nil (the default) means no history is enforced.
	passwordHistoryStore core.PasswordHistoryStore

	// adminRateLimitRate and adminRateLimitBurst configure admin-wide rate
	// limiting (WithAdminRateLimit). When wired, the admin middleware limits
	// total requests to rate tokens/sec with the given burst. 0 (default)
	// disables admin rate limiting.
	adminRateLimit struct {
		rate  float64
		burst int
	}

	// idempotentCache provides idempotency-key semantics for /token
	// (WithIdempotentStore). When non-nil, the token handler checks for
	// an Idempotency-Key header and caches successful responses.
	idempotentCache core.IdempotentCache

	// userLifecycleStore backs the user-lifecycle state-machine admin endpoints
	// (GET/POST /api/v1/admin/users/:id/lifecycle) and the auto-deprovisioning
	// sweep (WithUserLifecycle). Nil ⇒ neither is mounted nor run —
	// byte-identical to a build without the feature. A user with no record reads
	// as ACTIVE (the implicit default), so wiring the store alone changes nothing.
	userLifecycleStore userlifecycle.Store

	// userLifecycleActivity supplies the "last active" dormancy signal the
	// auto-deprovisioning sweep compares against userDeprovision.DormantAfter
	// (WithUserAutoDeprovision). Nil ⇒ the sweep is inert.
	userLifecycleActivity userlifecycle.LastActiveSource

	// userDeprovision gates the auto-deprovisioning sweep (WithUserAutoDeprovision).
	// The zero value is OFF: RunUserAutoDeprovision is a no-op, so existing
	// behavior is unchanged unless an operator BOTH wires it AND starts the loop.
	userDeprovision userlifecycle.DeprovisionConfig

	// identityLinkStore backs the self-service identity-linking surface
	// (GET/DELETE /me/identities, WithIdentityLinkStore). Nil ⇒ neither route
	// is mounted — byte-identical to a build without the feature. See
	// domains/identitylink.
	identityLinkStore identitylink.Store

	// identityMergePolicy is the operator's chosen conflict-resolution
	// strategy for identitylink.Resolve (WithIdentityMergePolicy) — an
	// extension point a CUSTOM login/authenticator integration retrieves via
	// Server.IdentityMergePolicy(); the stock /auth/login handler does not
	// call it (see the domains/identitylink package doc for why). Nil means
	// "use identitylink.RejectPolicy{}" once Resolve is actually invoked —
	// NOT "feature off"; identitylink.Resolve documents this deliberately
	// safe-by-default nil handling.
	identityMergePolicy identitylink.MergePolicy

	// dataRetention gates the automated data-retention sweep
	// (WithDataRetentionSweep, server_backup.go) — session-TTL cleanup,
	// dormant-account flagging/erasure, and an audit-retention report. The
	// zero value (Enabled == false) is OFF: byte-identical to a build without
	// the feature. Even when configured, the operator must start
	// Server.RunDataRetentionSweep in a goroutine, same discipline as
	// RunBreakGlassSweeper.
	dataRetention compliance.RetentionConfig
}

// mountOrgAdminSelfService registers the DELEGATED org-admin surface
// (/me/organizations/:tenant_id/*). Despite living beside the admin-API
// registrars in server_routes_admin.go historically, these routes hang off
// s.router DIRECTLY — NOT the /api/v1 admin group — because they are
// subject-bearer self-service endpoints authorized by tenant-admin
// MEMBERSHIP (requireTenantAdmin), not by the global admin scope
// AdminMiddleware enforces. Gated on the tenant-user store (the membership
// gate); the invitation sub-block additionally needs the invitation store.
// Byte-identical to a build without those stores. Relocated here (from
// server_routes_admin.go, which was at the line budget) since this is the
// self-service surface file.
func (s *Server) mountOrgAdminSelfService() {
	if s.tenantUserStore == nil {
		return
	}
	s.router.GET(PathOrgAdminMembers, s.handleOrgAdminListMembers)
	s.router.PUT(PathOrgAdminMemberByID, s.handleOrgAdminPutMember)
	s.router.DELETE(PathOrgAdminMemberByID, s.handleOrgAdminRemoveMember)
	if s.invitationStore != nil {
		s.router.POST(PathOrgAdminInvitations, s.handleOrgAdminSendInvitation)
		s.router.GET(PathOrgAdminInvitations, s.handleOrgAdminListInvitations)
		s.router.DELETE(PathOrgAdminInvitationByEmail, s.handleOrgAdminRevokeInvitation)
	}
}

// Delegated org-admin self-service endpoints (/me/organizations/:tenant_id/*).
// Subject-bearer, authorized by tenant-admin MEMBERSHIP (not the global admin
// scope) — logic + audit live in selfserviceaccount/orgadmin.go. Relocated
// from server_admin_handlers.go (which was at the line budget) to sit
// beside mountOrgAdminSelfService.
func (s *Server) handleOrgAdminListMembers(ctx HandlerContext) {
	selfservice.HandleOrgAdminListMembers(s, ctx)
}
func (s *Server) handleOrgAdminPutMember(ctx HandlerContext) {
	selfservice.HandleOrgAdminPutMember(s, ctx)
}
func (s *Server) handleOrgAdminRemoveMember(ctx HandlerContext) {
	selfservice.HandleOrgAdminRemoveMember(s, ctx)
}
func (s *Server) handleOrgAdminSendInvitation(ctx HandlerContext) {
	selfservice.HandleOrgAdminSendInvitation(s, ctx)
}
func (s *Server) handleOrgAdminListInvitations(ctx HandlerContext) {
	selfservice.HandleOrgAdminListInvitations(s, ctx)
}
func (s *Server) handleOrgAdminRevokeInvitation(ctx HandlerContext) {
	selfservice.HandleOrgAdminRevokeInvitation(s, ctx)
}

// pathDeveloperPortalPrefix is the developer-portal SPA's mount prefix.
// Held as a const (mirroring pathAdminConsolePrefix/pathHostedLoginPrefix/
// pathPortalPrefix in server_routes.go, which is at its line budget — this
// one lives here instead) so mountDeveloperPortalSPA's mux.Handle and
// StripPrefix uses cannot drift apart.
const pathDeveloperPortalPrefix = "/developer/"

// WithDeveloperPortalFS serves the developer-portal SPA at /developer/ from
// the provided filesystem (placed here rather than options_passwd.go,
// which is at its line budget). Unlike WithAdminConsoleFS/
// WithSelfServicePortalFS, this SPA authenticates an ANONYMOUS third-party
// developer: it calls POST /register (RFC 7591 DCR) to self-register a
// client, then GET/PUT/DELETE /register/:client_id (RFC 7592) with the
// registration_access_token issued at registration — no admin bearer, no
// end-user login. Typically wired by embedding web/developer with a
// go:embed directive in the operator's cmd binary.
//
// Nil (the default) leaves /developer/ unmounted — byte-identical to a
// build without the portal.
func WithDeveloperPortalFS(developerFS fs.FS) Option {
	return func(s *Server) { s.developerPortalFS = developerFS }
}

// mountDeveloperPortalSPA registers the developer-portal SPA's static file
// server onto mux when wired, exactly mirroring the adminConsoleFS/
// hostedLoginFS/portalFS mounts in server_routes.go's buildProbeMux (which
// calls this — that file is at its line budget, so the conditional itself
// lives here). No-op (byte-identical to a build without the feature) when
// developerPortalFS is nil; reachability of an actually-mounted entry is
// gated LIVE by the WebSPA flag (core.GateHTTPHandler), matching the other
// three SPA mounts, so it hot-toggles without a re-Mount.
func (s *Server) mountDeveloperPortalSPA(mux *http.ServeMux) {
	if s.developerPortalFS == nil {
		return
	}
	mux.Handle(pathDeveloperPortalPrefix, core.GateHTTPHandler(s.webSPAGateOn, s.wrapSecurityHeaders(http.StripPrefix(pathDeveloperPortalPrefix, http.FileServerFS(s.developerPortalFS)))))
}
