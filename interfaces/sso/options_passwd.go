package sso

import (
	"github.com/snaplink/sso/domains/identitylink"
	"github.com/snaplink/sso/domains/metering"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/selfservice/selfservicecore"
	"time"

	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

func WithPasswordResetStore(store PasswordResetStore, ttl time.Duration) Option {
	return func(srv *Server) {
		srv.passwordResetStore = store
		if ttl > 0 {
			srv.passwordResetTTL = ttl
		}
	}
}

// WithPasswordResetResolver wires the operator seam mapping a submitted login
// identifier (username/email) to the stable userID. Deployment-specific (same
// mapping the login authenticator does); no default.
func WithPasswordResetResolver(fn spi.PasswordResetResolver) Option {
	return func(srv *Server) { srv.passwordResetResolver = fn }
}

// WithPasswordResetDeliveryResolver wires the operator seam mapping a resolved
// userID to the out-of-band delivery target (email/phone) the reset token is
// sent to.
func WithPasswordResetDeliveryResolver(fn spi.PasswordResetDeliveryResolver) Option {
	return func(srv *Server) { srv.passwordResetDeliveryResolver = fn }
}

// WithPasswordResetSender wires the out-of-band delivery of the reset token
// (email link, SMS code). Required for forgot-password to deliver anything.
func WithPasswordResetSender(sender spi.PasswordResetSender) Option {
	return func(srv *Server) { srv.passwordResetSender = sender }
}

// WithSelfServiceDataExport mounts GET /me/data-export — the GDPR Art. 15
// self-service export of the authenticated bearer's OWN data, assembled by the
// supplied compliance.Exporter (the same one the admin /api/v1/compliance route
// uses, but scoped to the caller's subject). Nil ⇒ not mounted, byte-identical.
func WithSelfServiceDataExport(e *compliance.Exporter) Option {
	return func(srv *Server) { srv.dataExporter = e }
}

// WithSelfServiceAccountErasure mounts POST /me/account/erase — the GDPR
// Art. 17 self-service erasure of the authenticated bearer's OWN account
// (sessions + refresh tokens + user record), assembled by the supplied
// compliance.Eraser scoped to the caller's subject. IRREVERSIBLE and
// default-off: self-deletion is a deliberate operator choice (often undesirable
// for org-managed accounts). The handler requires a confirmation matching the
// subject before erasing. Nil ⇒ not mounted, byte-identical.
func WithSelfServiceAccountErasure(e *compliance.Eraser) Option {
	return func(srv *Server) { srv.accountEraser = e }
}

// WithEmailChangeStore wires the single-use token store for verified email
// change (POST /me/email/change + /me/email/verify). ttl bounds a token's life
// (0 = DefaultEmailChangeTTL). The routes mount only when this AND an
// EmailChangeSender AND a UserProvider are all wired. Nil ⇒ byte-identical.
func WithEmailChangeStore(store EmailChangeStore, ttl time.Duration) Option {
	return func(srv *Server) {
		srv.emailChangeStore = store
		if ttl > 0 {
			srv.emailChangeTTL = ttl
		}
	}
}

// WithEmailChangeSender wires delivery of the email-change verification token to
// the user's NEW address (proving they control it). Required for the flow.
func WithEmailChangeSender(sender spi.EmailChangeSender) Option {
	return func(srv *Server) { srv.emailChangeSender = sender }
}

// WithSignupRequireVerification enables mandatory email verification for
// self-service signup (Mode B). When true, POST /auth/register requires an
// email field, issues a verification token, and returns 201 {"status":"pending"}
// without creating the user. The user completes signup via POST /auth/verify-email.
// Requires WithEmailVerificationStore and WithEmailVerificationSender to be wired
// as well. Default false (Mode A — optional verification, backward compatible).
func WithSignupRequireVerification(require bool) Option {
	return func(srv *Server) { srv.signupRequireVerification = require }
}

// WithEmailVerificationStore wires the single-use token store for signup email
// verification (POST /auth/verify-email). ttl bounds a token's life (0 = 15 min).
// The route mounts only when signup is enabled AND require_verification is true.
// Nil ⇒ byte-identical.
func WithEmailVerificationStore(store core.EmailVerificationStore, ttl time.Duration) Option {
	return func(srv *Server) {
		srv.emailVerificationStore = store
		if ttl > 0 {
			srv.emailVerificationTTL = ttl
		}
	}
}

// WithEmailVerificationSender wires delivery of the signup email verification
// token to the target address. Required for mandatory verification (Mode B) and
// optional ?send_verification=true support (Mode A).
func WithEmailVerificationSender(sender spi.EmailVerificationSender) Option {
	return func(srv *Server) { srv.emailVerificationSender = sender }
}

// WithSelfServiceSignup enables the opt-in UNAUTHENTICATED self-service
// registration endpoint POST /auth/register (creates a user + sets a password,
// reusing the wired UserProvider + PasswordCredentialStore). DEFAULT-OFF: open
// signup is an abuse surface most enterprise deployments don't want (they
// provision via SCIM/admin). The endpoint is rate-limited by the standard
// middleware; operators wanting CAPTCHA / domain-allowlist / email-verification
// gating should use WithRegistrationGates. Mounts only when a UserProvider AND
// a PasswordCredentialStore are also wired.
func WithSelfServiceSignup() Option {
	return func(srv *Server) { srv.signupEnabled = true }
}

// WithSelfServiceSignupRateLimiter wires an optional per-IP rate limiter
// to POST /auth/register. When non-nil, the handler checks the caller's
// IP against the limiter before processing the request and returns 429
// rate_limited when the bucket is exhausted. This is independent of the
// global WithRateLimit middleware — it protects signup specifically with
// a separate bucket, so operators can set tight limits (e.g. 3 per minute
// per IP) without affecting login or other paths.
//
// Nil (the default) means no signup-specific rate limiting — full backward
// compatibility with existing deployments that do not set this option.
//
// Pre-built limiters from interfaces/ratelimit:
//
//	ratelimit.NewMemoryLimiter(3.0/60, 3) // 3 signups / min, burst 3
func WithSelfServiceSignupRateLimiter(limiter selfservicecore.RateLimiter) Option {
	return func(srv *Server) { srv.signupRateLimiter = limiter }
}

// WithRegistrationGates wires zero or more self-service registration abuse-
// protection gates. Each gate implements spi.RegistrationGate and is checked
// in order during POST /auth/register, after the standard checks (rate limit,
// validation) but BEFORE the user is created. If any gate returns an error,
// the handler responds with 403 registration_denied (oracle-safe: the caller
// cannot tell which gate blocked them, preventing domain/rule enumeration).
//
// Pre-built implementations live in domains/authenticators:
//   - DomainAllowlistGate – allow specific email domains only
//   - CaptchaGate – verify a captcha token via spi.CaptchaVerifier
//
// When no gates are wired (the default), registration behaviour is unchanged
// (full backward compatibility).
func WithRegistrationGates(gates ...spi.RegistrationGate) Option {
	return func(srv *Server) { srv.registrationGates = gates }
}

// WithMFAEnrollmentStore wires a store for the self-service MFA management
// endpoints (GET /me/mfa to list registered factors, DELETE /me/mfa/:id to
// unbind one). An operator implements it over their concrete factor backends
// (TOTP secrets, WebAuthn credentials). When nil (the default), the routes are
// not mounted — byte-identical to a build without this feature.
func WithMFAEnrollmentStore(s MFAEnrollmentStore) Option {
	return func(srv *Server) { srv.mfaEnrollmentStore = s }
}

// WithRecoveryCodeStore wires the single-use MFA recovery-code store. It mounts
// the self-service endpoints POST/GET /me/mfa/recovery-codes (regenerate +
// remaining-count) and the admin reset POST
// /api/v1/admin/users/:id/mfa/recovery-codes. When nil (the default), those
// routes are not mounted — byte-identical to a build without this feature.
//
// Redemption at /auth/mfa is separate: pass the SAME store to
// defaultimpl.NewRecoveryMFAProvider(store) and compose it into WithMFAProvider
// (via defaultimpl.NewMultiMFAProvider) so "recovery" surfaces in mfa_methods
// and a code can be spent as a second factor.
func WithRecoveryCodeStore(store RecoveryCodeStore) Option {
	return func(srv *Server) { srv.recoveryCodeStore = store }
}

// WithTrustedDeviceStore moved to server_me.go (which had room), beside
// mountTrustedDeviceRoutes and the trusted-device handlers it feeds.

// WithTOTPEnroller wires the seam the self-service TOTP enrollment endpoints
// (POST /me/mfa/totp/begin + /confirm) use to mint/encode/decode secrets, build
// the otpauth provisioning URI, and verify the confirm code. Use
// authenticators.NewTOTPEnroller(totpAuth) so the SAME authenticator (and skew
// window) that backs TOTP login also backs enrollment — a newly enrolled factor
// then verifies identically at login. The routes mount ONLY when this is wired
// AND the MFAEnrollmentStore (WithMFAEnrollmentStore) implements
// TOTPEnrollmentWriter; otherwise the build is byte-identical (routes absent).
func WithTOTPEnroller(e TOTPEnroller) Option {
	return func(srv *Server) { srv.totpEnroller = e }
}

// WithWebAuthnRegistrar wires AUTHENTICATED self-service passkey registration
// (POST /me/mfa/webauthn/{begin,finish}). Use webauthn.NewRegistrar(helper)
// with the SAME Helper backing the /webauthn/* ceremony so the registered
// passkey shares one store and surfaces in GET /me/mfa. The registration binds
// to the BEARER subject (not request input), so a user can only add a passkey
// to their own account — unlike the unauthenticated signup ceremony. Nil (the
// default) leaves the routes unmounted — byte-identical to a build without it.
func WithWebAuthnRegistrar(r WebAuthnRegistrar) Option {
	return func(srv *Server) { srv.webauthnRegistrar = r }
}

// WithTenantUsageAggregator wires the per-tenant metering Aggregator and
// mounts GET /api/v1/admin/tenants/:id/usage (admin:read). The endpoint
// returns aggregated login / token-issuance / active-user / MFA-challenge
// counts for the requested tenant over a day or month window.
//
// Nil ⇒ the route is NOT mounted — behavior is byte-identical to a build
// without it.
func WithTenantUsageAggregator(a metering.Aggregator) Option {
	return func(s *Server) { s.usageAggregator = a }
}

// WithTrustedProxies configures a trusted-proxy CIDR allowlist gating every
// forwarded-header consumer on the DIRECT peer (RemoteAddr). When set: the
// rate-limiter IP key (ratelimit.KeyByClientIP via middleware.RealClientIP)
// walks the XFF chain right-to-left only for a trusted peer (untrusted ⇒
// RemoteAddr); base-URL derivation (issuer/discovery/registration URIs/DPoP
// htu) honors X-Forwarded-Proto/Host only from a trusted peer (untrusted ⇒
// direct Host/TLS); the mesh ext_authz endpoint derives identity only for a
// trusted peer (untrusted ⇒ the same 401 invalid_token as an invalid bearer).
//
// cidrs lists the trusted proxy tiers (e.g. ["10.0.0.0/8"]); hops=0 means
// "trust at most len(cidrs) proxy hops". Errors on any unparseable CIDR so
// misconfigured deployments fail loudly at startup.
//
// Without WithTrustedProxies, every forwarded-header consumer trusts the raw
// header unconditionally — safe ONLY behind an edge that strips and re-adds
// those headers. An internet-facing deployment without such an edge MUST use
// this option, or an attacker forges X-Forwarded-For: <trusted-IP> to bypass
// IP rate limiting (or X-Forwarded-Host to steer the derived issuer).
func WithTrustedProxies(cidrs []string, hops int) (Option, error) {
	tp, err := middleware.NewTrustedProxies(cidrs, hops)
	if err != nil {
		return nil, err
	}
	return func(s *Server) { s.trustedProxies = tp }, nil
}

// WithSelfEditableProfileAttributes allowlists the User.Attributes keys an
// end user MAY change through PATCH /me. The display name is always self-
// editable; this option additionally permits the named presentation
// attributes (e.g. "locale", "zoneinfo", "picture"). Keys NOT in the list are
// silently ignored on PATCH, so a user can never set an attribute the operator
// uses for authorization (roles, tenant, entitlements). Empty/unset ⇒ name
// only. Identity-critical fields (id, external_id, provider, email) are never
// self-editable regardless of this list — email changes need a verification
// flow that lives outside self-service.
func WithSelfEditableProfileAttributes(keys ...string) Option {
	return func(s *Server) {
		if len(keys) == 0 {
			return
		}
		s.selfEditableAttrs = make(map[string]struct{}, len(keys))
		for _, k := range keys {
			s.selfEditableAttrs[k] = struct{}{}
		}
	}
}

// WithConsentStore wires a persistent consent record store. When set,
// /auth/login records the user's consent decision and enforces the
// prompt=consent parameter (re-prompting even when a grant already exists).
// When the requested scopes are not fully covered by an existing grant,
// consent_required is returned (HTTP 200) so the SPA can surface a
// consent screen. When nil (the default), all consent enforcement is skipped
// — behavior is byte-identical to a build without this feature.
func WithConsentStore(cs ConsentStore) Option {
	return func(s *Server) { s.consentStore = cs }
}

// WithIdentityLinkStore wires the self-service identity-linking store (see
// domains/identitylink): when set, GET/DELETE /me/identities let the
// authenticated user list and unlink their own external identities. When nil
// (the default), neither route is mounted — byte-identical to a build
// without the feature.
func WithIdentityLinkStore(store identitylink.Store) Option {
	return func(s *Server) { s.identityLinkStore = store }
}

// WithIdentityMergePolicy wires the operator's chosen conflict-resolution
// strategy for the "external identity already linked to a different
// account" collision (identitylink.MergePolicy). This is an EXTENSION
// POINT: the stock /auth/login handler does not consult it — a custom
// Authenticator/login integration retrieves it via Server.IdentityMergePolicy
// and Server.IdentityLinkStore to call identitylink.Resolve itself (see the
// domains/identitylink package doc). Unwired (nil) is equivalent to
// identitylink.RejectPolicy{} once such an integration calls Resolve — the
// safe default, never a silent allow.
func WithIdentityMergePolicy(policy identitylink.MergePolicy) Option {
	return func(s *Server) { s.identityMergePolicy = policy }
}

// WithConsentTTL sets a hard server-level ceiling on consent grant
// lifetime. When >0, every recorded consent grant has an expiration
// window of GrantedAt + maxTTL — after which GetConsent returns
// ErrNoConsentGrant and the user must re-authorize. 0 (the default)
// means no server-enforced expiry (consent lives until explicitly
// revoked by the user or an admin).
//
// This is a HARD ceiling: the per-client ConsentRefreshInterval can
// force re-consent earlier, but can NOT extend beyond this ceiling.
// Combine with WithConsentStore to activate.
func WithConsentTTL(maxTTL time.Duration) Option {
	return func(s *Server) {
		if maxTTL > 0 {
			s.consentMaxTTL = maxTTL
		}
	}
}

// WithConsentChallengeStore overrides the in-process consent-gate challenge store
// with a cluster-shared backend (e.g. redis). Without it, the single-use consent
// nonce lives in the issuing replica's memory, so on a no-affinity load balancer
// the approve re-POST lands on a different replica, Consume misses, and the gate
// re-issues forever — an infinite consent loop that blocks first-time
// third-party authorization. nil store leaves the in-process default.
func WithConsentChallengeStore(store ConsentChallengeStore) Option {
	return func(s *Server) {
		if store != nil {
			s.consentChallenges = store
		}
	}
}

// WithScopeDescriptions registers operator-defined human descriptions for OAuth
// scopes (scope -> description). They are surfaced in the consent_required
// response (alongside the client's display name) so a consent UI can show
// meaningful text for custom scopes instead of the bare scope name. Purely
// presentational — it does not affect scope authorization. Nil/empty (the
// default) emits no descriptions (byte-identical).
func WithScopeDescriptions(d map[string]string) Option {
	return func(s *Server) { s.scopeDescriptions = d }
}

// WithTenantUserStore wires explicit B2B org membership (core.TenantUserStore)
// and mounts the admin roster endpoints (/api/v1/admin/tenants/:id/members) plus
// the self-service /me/organizations list + leave. Membership is independent of
// SCIM groups (which model client-scoped app roles, not org belonging). Nil/unset
// = none of those routes are mounted (byte-identical).
func WithTenantUserStore(store TenantUserStore) Option {
	return func(s *Server) { s.tenantUserStore = store }
}

// WithJITMembership auto-provisions org membership on login: a user
// authenticating through a tenant-bound client (Client.TenantID set) who isn't
// yet on that tenant's roster is added as a member. Requires WithTenantUserStore.
// Best-effort + idempotent (existing members keep their role); never blocks
// login. Off by default (byte-identical).
func WithJITMembership() Option {
	return func(s *Server) { s.jitMembership = true }
}

// WithInvitationStore persists single-use org-invitation tokens and mounts the
// admin send/list endpoints plus the self-service POST /me/invitations/accept.
// Accept grants membership, so it also requires WithTenantUserStore; send
// requires WithInvitationSender to deliver the token. Nil/unset = none mounted.
func WithInvitationStore(store InvitationStore) Option {
	return func(s *Server) { s.invitationStore = store }
}

// WithInvitationSender wires delivery of the invitation token to the invited
// email address. Without it, the admin send endpoint returns 501 (the token must
// never be returned in the response). SDK-only — operators provide the transport.
func WithInvitationSender(sender spi.InvitationSender) Option {
	return func(s *Server) { s.invitationSender = sender }
}

// WithPasswordCredentialStore wires a per-user password store and mounts the
// self-service POST /me/password endpoint. The store is keyed by UserID, so an
// operator can also build their login authenticator over it (resolve username
// -> UserID -> VerifyPassword) to keep the changed credential and the login
// credential the same. When nil (the default), /me/password is not mounted —
// byte-identical to a build without this feature.
func WithPasswordCredentialStore(s PasswordCredentialStore) Option {
	return func(srv *Server) { srv.passwordCredentialStore = s }
}

// WithSecurityHeaders enables a global HTTP middleware that adds browser-security
// response headers to every SSO router endpoint AND the opt-in SPA bundles
// (admin console, hosted login, self-service portal — see WithAdminConsoleFS /
// WithHostedLoginFS / WithSelfServicePortalFS):
//
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - Referrer-Policy: no-referrer
//   - Content-Security-Policy: handler.DefaultSecurityHeadersPolicy's
//     conservative default, with a fresh cryptographically random nonce
//     appended to script-src on every request. The same nonce is stashed in
//     the request context (core.CSPNonceFromContext) so an HTML renderer
//     downstream — the OIDC form_post / JARM auto-submit pages — can stamp a
//     matching nonce="..." attribute on an inline <script>.
//   - Permissions-Policy: camera/microphone/geolocation/payment/usb denied
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains (TLS only)
//
// Headers already set by inner handlers are NOT overwritten (existing per-handler
// X-Frame-Options: DENY on form_post/jarm survive). Cache-Control: no-store set
// by credential endpoints is also preserved. HSTS is only emitted when the request
// arrived over TLS to avoid breaking the dev HTTP workflow.
//
// This ALSO gates Clear-Site-Data on POST /logout and POST /me/account/erase —
// see ClearSiteData's doc — since both represent a definitive end to the
// session on this origin.
//
// Probe endpoints (/livez, /readyz, /metrics) remain header-free (served
// outside the middleware chain, per Handler's doc).
//
// Off by default (byte-identical to a build without the feature). Use
// WithSecurityHeadersPolicy to override the CSP directives / Permissions-Policy
// instead of the SDK's conservative default.
func WithSecurityHeaders() Option {
	return func(s *Server) { s.securityHeadersEnabled = true }
}

// WithSecurityHeadersPolicy is WithSecurityHeaders with an operator-supplied
// policy overriding the SDK's default CSP directives / Permissions-Policy. A
// zero-value field in policy still falls back to the default (nil
// CSPDirectives -> handler.DefaultSecurityHeadersPolicy's directives; empty
// PermissionsPolicy -> its default value), so an operator can override just
// one of the two.
func WithSecurityHeadersPolicy(policy handler.SecurityHeadersPolicy) Option {
	return func(s *Server) {
		s.securityHeadersEnabled = true
		s.securityHeadersPolicy = &policy
	}
}

// WithMaxSessionsPerUser sets a per-user limit on concurrent active sessions.
// When a user already has >= n active sessions and a new login creates another,
// the OLDEST session is silently evicted (rolling eviction) before the new one
// is persisted — the user stays logged in on the new device, and the oldest
// session is revoked.
//
// 0 (the default) means unlimited, preserving full backward compatibility for
// existing deployments that never set a limit.
//
// This is NOT a security boundary: a user who deliberately exceeds the limit
// gets their oldest session kicked off, but is never denied login. Hard session
// caps should be enforced at the store level paired with this option.
func WithMaxSessionsPerUser(n int) Option {
	return func(s *Server) { s.maxSessionsPerUser = n }
}
