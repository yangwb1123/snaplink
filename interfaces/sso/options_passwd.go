package sso

import (
	"github.com/snaplink/sso/domains/metering"
	"github.com/snaplink/sso/interfaces/middleware"
	"io/fs"
	"time"

	"github.com/snaplink/sso/protocols/compliance"
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

// WithSelfServiceSignup enables the opt-in UNAUTHENTICATED self-service
// registration endpoint POST /auth/register (creates a user + sets a password,
// reusing the wired UserProvider + PasswordCredentialStore). DEFAULT-OFF: open
// signup is an abuse surface most enterprise deployments don't want (they
// provision via SCIM/admin). The endpoint is rate-limited by the standard
// middleware; operators wanting CAPTCHA / domain-allowlist / email-verification
// gating should front or extend it. Mounts only when a UserProvider AND a
// PasswordCredentialStore are also wired.
func WithSelfServiceSignup() Option {
	return func(srv *Server) { srv.signupEnabled = true }
}

// WithMFAEnrollmentStore wires a store for the self-service MFA management
// endpoints (GET /me/mfa to list registered factors, DELETE /me/mfa/:id to
// unbind one). An operator implements it over their concrete factor backends
// (TOTP secrets, WebAuthn credentials). When nil (the default), the routes are
// not mounted — byte-identical to a build without this feature.
func WithMFAEnrollmentStore(s MFAEnrollmentStore) Option {
	return func(srv *Server) { srv.mfaEnrollmentStore = s }
}

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

// WithTrustedProxies configures a trusted-proxy CIDR allowlist for
// X-Forwarded-For validation. When set, all X-Forwarded-For consumers
// (rate-limiter IP key via ratelimit.KeyByClientIP) use the validated real
// client IP derived by middleware.RealClientIP — which walks the XFF chain
// from right to left and stops at the first hop that is NOT in a trusted
// CIDR — rather than reading the raw header unconditionally.
//
// cidrs is a list of CIDR strings (e.g. ["10.0.0.0/8", "172.16.0.0/12"])
// identifying the IP ranges belonging to trusted proxy tiers. hops=0 means
// "trust at most len(cidrs) proxy hops" — the safe default for most
// deployments. Returns an error if any CIDR fails to parse so
// misconfigured deployments fail loudly at startup.
//
// Without WithTrustedProxies, every XFF consumer trusts the raw header
// unconditionally — safe only behind an edge that strips and re-adds XFF.
// An internet-facing deployment without such an edge MUST use this option
// to prevent an attacker from forging X-Forwarded-For: <trusted-IP> to
// bypass IP-based rate limiting.
func WithTrustedProxies(cidrs []string, hops int) (Option, error) {
	tp, err := middleware.NewTrustedProxies(cidrs, hops)
	if err != nil {
		return nil, err
	}
	return func(s *Server) { s.trustedProxies = tp }, nil
}

// WithAdminConsoleFS serves the admin console SPA at /admin/ from the
// provided filesystem. The SPA is a standalone browser client that
// communicates with the server via the existing /api/v1/admin/* REST
// endpoints using a Bearer token with admin:read or admin:write scope.
//
// Typically wired by embedding the web/admin directory with go:embed in
// the operator's cmd binary and passing the sub-filesystem here. Index
// file (index.html) is served for the /admin/ root; all sub-paths fall
// through to the filesystem.
//
// Nil (the default) leaves /admin/ unmounted — byte-identical to a build
// without the console.
func WithAdminConsoleFS(adminFS fs.FS) Option {
	return func(s *Server) { s.adminConsoleFS = adminFS }
}

// WithHostedLoginFS serves the hosted-login SPA at /login/ from the provided
// filesystem. The SPA calls /auth/login over JSON — no protocol changes to
// the OAuth/OIDC surface. Typically wired by embedding web/login with an
// embed directive in the operator's cmd binary.
//
// Nil (the default) leaves /login/ unmounted — byte-identical to a build
// without the hosted login UI.
func WithHostedLoginFS(loginFS fs.FS) Option {
	return func(s *Server) { s.hostedLoginFS = loginFS }
}

// WithSelfServicePortalFS serves the end-user self-service portal SPA at
// /portal/ from the provided filesystem. The portal is a standalone browser
// client that calls the existing /me, /sessions/me, /consents/me, /me/password
// and /me/mfa endpoints with the end-user's own Bearer token — no protocol
// changes. Typically wired by embedding web/portal with an embed directive in
// the operator's cmd binary.
//
// Nil (the default) leaves /portal/ unmounted — byte-identical to a build
// without the portal UI.
func WithSelfServicePortalFS(portalFS fs.FS) Option {
	return func(s *Server) { s.portalFS = portalFS }
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

func WithConsentStore(cs ConsentStore) Option {
	return func(s *Server) { s.consentStore = cs }
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

// WithPasswordResetStore wires the single-use reset-token store backing the
// UNAUTHENTICATED forgot-password flow (POST /auth/forgot-password +
// /auth/reset-password). ttl bounds a token's life (0 = DefaultPasswordResetTTL).
// The routes mount only when this AND a PasswordCredentialStore are both wired
// (the reset must SetPassword on success). Nil ⇒ byte-identical to a build
// without the flow. The resolver + sender (below) are also required for
// forgot-password to actually resolve + deliver — without them the endpoint
// still returns 200 (anti-enumeration) but does nothing.
