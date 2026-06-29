package sso

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/tracing"
	"github.com/snaplink/sso/protocols/oauth"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func (s *Server) RegisterAuthenticator(a Authenticator) {
	s.authenticators[a.Name()] = a
}

// Handle mounts an extra route on the SSO router so embedders can
// serve extension endpoints (e.g. WebAuthn ceremony begin/finish
// handlers from authenticators/webauthn) from the same listener +
// middleware stack the built-in SSO endpoints use. Must be called
// after Mount or Handler — the router has to exist.
//
// method is one of GET/POST/PUT/PATCH/DELETE (case-insensitive). Unknown
// methods return an error rather than silently routing. PATCH is included
// for partial-update surfaces such as SCIM 2.0 (RFC 7644 §3.5.2).
func (s *Server) Handle(method, path string, handler http.HandlerFunc) error {
	if s.router == nil {
		return fmt.Errorf("sso: Mount() must be called before Handle()")
	}
	wrap := func(ctx HandlerContext) { handler(ctx.ResponseWriter(), ctx.Request()) }
	switch strings.ToUpper(method) {
	case http.MethodGet:
		s.router.GET(path, wrap)
	case http.MethodPost:
		s.router.POST(path, wrap)
	case http.MethodPut:
		s.router.PUT(path, wrap)
	case http.MethodPatch:
		s.router.PATCH(path, wrap)
	case http.MethodDelete:
		s.router.DELETE(path, wrap)
	default:
		return fmt.Errorf("sso: unsupported method %q", method)
	}
	return nil
}

// Mount registers all SSO endpoints on the router. The registration is grouped
// into focused registrar helpers (middleware -> core protocol -> self-service
// -> cluster/federation -> admin API); the mount order and every per-store
// conditional are preserved, so the registered route set is byte-identical to
// the previous inline assembly.
func (s *Server) Mount() {
	s.mountMiddleware()
	s.mountCoreOAuthOIDC()
	s.mountSelfServiceProfile()
	s.mountSelfServiceCredentials()
	s.mountClusterEndpoints()
	s.mountFederationEndpoints()
	api := s.router.Group(PathAPIPrefix)
	s.mountAdminAPIObservability(api)
	s.mountAdminUserState(api)
	s.mountAdminB2B(api)
}

// mountMiddleware lazily creates the router and installs the global middleware
// chain (request-id/tracing, tenant, geo, region) in the order the audit
// enrichment pipeline expects.
func (s *Server) mountMiddleware() {
	if s.router == nil {
		s.router = NewStdRouter()
	}
	if s.requestIDMW {
		s.router.Use(TracingMiddleware())
	}
	if s.tenantStore != nil {
		// Tenant resolves before geo so the audit enrichment
		// pipeline sees both — geo enrichment doesn't need
		// tenant, but tenant enrichment doesn't need geo either,
		// and putting tenant first matches the conceptual
		// "which tenant am I serving" → "where is the user
		// coming from" reading order.
		s.router.Use(TenantMiddleware(s.tenantStore, s.tenantMiddlewareOpts))
	}
	if s.geoProvider != nil {
		s.router.Use(GeoMiddleware(s.geoProvider, s.geoMiddlewareOpts))
	}
	// Region resolves right after geo: serving region is a deployment-level
	// routing/governance signal, independent of the client's geo. Gated on a
	// wired resolver so a server without WithRegionMiddleware installs nothing
	// (nil-default byte-identical, matching geo's discipline).
	if s.regionResolver != nil {
		s.router.Use(region.Middleware(s.regionResolver, s.regionMiddlewareOpts))
	}
}

// mountCoreOAuthOIDC registers the always-present OAuth 2.0 / OIDC protocol
// endpoints plus the conditional unauthenticated password-reset and self-
// service signup routes.
func (s *Server) mountCoreOAuthOIDC() {
	s.router.GET(PathHealth, s.handleHealth)
	s.router.GET(PathJWKS, s.handleJWKS)
	s.router.GET(PathOIDCDiscovery, s.handleOIDCDiscovery)
	s.router.POST(PathLogin, s.handleLogin)
	s.router.POST(PathMFAComplete, s.handleMFAComplete)
	s.router.POST(PathSendCode, s.handleSendCode)
	s.router.GET(PathCallback, s.handleCallback)
	// Unauthenticated forgot-password flow. Requires the reset-token store AND
	// the credential store (reset must SetPassword on success) — byte-identical
	// without both.
	if s.passwordResetStore != nil && s.passwordCredentialStore != nil {
		s.router.POST(PathForgotPassword, s.handleForgotPassword)
		s.router.POST(PathResetPassword, s.handleResetPassword)
	}
	// Opt-in self-service signup. Needs a UserProvider (create) + credential
	// store (set password). Default-off — byte-identical when not enabled.
	if s.signupEnabled && s.userProvider != nil && s.passwordCredentialStore != nil {
		// Mode B (mandatory verification) requires the store + sender; without
		// them the handler nil-derefs on EmailVerificationStore.Issue(). Suppress
		// the route rather than panic at request time.
		if !s.signupRequireVerification || (s.emailVerificationStore != nil && s.emailVerificationSender != nil) {
			s.router.POST(PathSignup, s.handleSelfRegister)
		}
		// Verification endpoint: Mode B needs store + sender (both required for
		// the register route above). Mode A opt-in (?send_verification=true) only
		// needs the store — the sender was already invoked at register time.
		// Mount whenever the store is wired so Mode A opt-in verify does not 404.
		if s.emailVerificationStore != nil {
			s.router.POST(PathVerifyEmail, s.handleVerifyEmail)
		}
	}
	s.router.POST(PathToken, s.handleToken)
	s.router.POST(PathIntrospect, s.handleIntrospect)
	s.router.POST(PathRevoke, s.handleRevoke)
	s.router.POST(PathRevokeAll, s.handleRevokeAll)
	s.router.POST(PathDeviceCode, s.handleDeviceCode)
	s.router.GET(PathDeviceVerify, s.handleDeviceVerifyPage)
	s.router.POST(PathDeviceVerify, s.handleDeviceVerify)
	s.router.POST(PathPAR, s.handlePAR)
	s.router.POST(PathBackchannelAuth, s.handleBackchannelAuth)
	s.router.POST(oauth.PathRegister, s.handleRegister)
	s.router.GET(oauth.PathRegisterByID, s.handleRegistrationGet)
	s.router.PUT(oauth.PathRegisterByID, s.handleRegistrationPut)
	s.router.DELETE(oauth.PathRegisterByID, s.handleRegistrationDelete)
	s.router.GET(PathUserInfo, s.handleUserInfo)
	s.router.POST(PathLogout, s.handleLogout)
	s.router.GET(PathEndSession, s.handleEndSession)
}

// mountSelfServiceProfile registers the authenticated /me* self-service
// endpoints for permissions/menus/roles, sessions, consents, org membership,
// and profile — each gated on its backing store.
func (s *Server) mountSelfServiceProfile() {
	s.router.GET(PathMyPermissions, s.handleMyPermissions)
	s.router.GET(PathMyMenus, s.handleMyMenus)
	s.router.GET(PathMyRoles, s.handleMyRoles)
	if s.sessionMgr != nil {
		s.router.GET(PathMySessions, s.handleMySessions)
		s.router.DELETE(PathMySessions, s.handleRevokeMySessions)
		s.router.DELETE(PathMySessionByID, s.handleDeleteMySession)
	}
	if s.consentStore != nil {
		s.router.GET(PathMyConsents, s.handleMyConsents)
		s.router.DELETE(PathMyConsentByID, s.handleDeleteMyConsent)
	}
	// Self-service B2B org membership: list my orgs + leave one.
	if s.tenantUserStore != nil {
		s.router.GET(PathMyOrganizations, s.handleMyOrganizations)
		s.router.DELETE(PathMyOrganizationByID, s.handleLeaveMyOrganization)
		// Accept an invitation (joins an org) — needs both stores.
		if s.invitationStore != nil {
			s.router.POST(PathMyInvitationAccept, s.handleAcceptInvitation)
		}
	}
	// Self-service account overview. Mounted with a user directory (the
	// profile is its core); byte-identical without one.
	if s.userProvider != nil {
		s.router.GET(PathMe, s.handleMe)
		s.router.PATCH(PathMe, s.handlePatchMe)
	}
	// Self-service password change. Mounted only with a password credential
	// store; byte-identical without one.
	if s.passwordCredentialStore != nil {
		s.router.POST(PathMyPassword, s.handleChangeMyPassword)
	}
}

// mountSelfServiceCredentials registers the authenticated /me* credential +
// privacy endpoints (MFA factors, passkey registration, GDPR export/erasure,
// verified email change) and the public per-host branding lookup.
func (s *Server) mountSelfServiceCredentials() {
	// Self-service MFA factor management. Mounted only with an enrollment
	// store; byte-identical without one.
	if s.mfaEnrollmentStore != nil {
		s.router.GET(PathMyMFA, s.handleMyMFAFactors)
		s.router.DELETE(PathMyMFAByID, s.handleDeleteMyMFAFactor)
		// Self-service TOTP enrollment (the write-half). Mounted only when the
		// enrollment store can persist a TOTP factor AND a TOTP enroller is
		// wired to verify the confirm code — byte-identical otherwise.
		if _, ok := s.mfaEnrollmentStore.(TOTPEnrollmentWriter); ok && s.totpEnroller != nil {
			s.router.POST(PathMyMFATOTPBegin, s.handleTOTPEnrollBegin)
			s.router.POST(PathMyMFATOTPConfirm, s.handleTOTPEnrollConfirm)
		}
	}
	// Self-service passkey registration (authenticated, bearer-bound). Mounts
	// independently of the enrollment store: the registered credential lands in
	// the WebAuthn store the Registrar wraps and surfaces in /me/mfa via the
	// WebAuthn adapter. Byte-identical when no registrar is wired.
	if s.webauthnRegistrar != nil {
		s.router.POST(PathMyWebAuthnRegisterBegin, s.handleMyWebAuthnRegisterBegin)
		s.router.POST(PathMyWebAuthnRegisterFinish, s.handleMyWebAuthnRegisterFinish)
	}
	// GDPR Art. 15 self-service data export of the bearer's own data.
	if s.dataExporter != nil {
		s.router.GET(PathMyDataExport, s.handleMyDataExport)
	}
	// GDPR Art. 17 self-service account erasure (opt-in, irreversible).
	if s.accountEraser != nil {
		s.router.POST(PathMyAccountErase, s.handleMyAccountErase)
	}
	// Verified email change. Needs the token store + sender (deliver to the new
	// address) + a UserProvider (commit the new email). Byte-identical without.
	if s.emailChangeStore != nil && s.emailChangeSender != nil && s.userProvider != nil {
		s.router.POST(PathMyEmailChange, s.handleMyEmailChange)
		s.router.POST(PathMyEmailVerify, s.handleMyEmailVerify)
	}
	// Public per-host branding lookup for the hosted login SPA. Only mounted
	// with a tenant store (Domain.Branding is its source) — byte-identical to
	// a single-tenant build without it.
	if s.tenantStore != nil {
		s.router.GET(PathBranding, s.handleBranding)
	}
}

// mountClusterEndpoints registers the full-path admin/cluster endpoints
// (authz policy bundle, storage health, mesh ext_authz, CAEP/SSF receiver),
// each opt-in and gated on its wiring.
func (s *Server) mountClusterEndpoints() {
	// Authorization policy bundle export (decentralized authz). Full
	// path (not group-relative) registered directly on the router; its
	// /api/v1/admin/ prefix means AdminMiddleware gates it as admin:read.
	// Only mounted when a permissions provider is wired — the bundle is
	// the role-DEFINITION half of that model.
	if s.permissions != nil {
		s.router.GET(PathAuthzPolicyBundle, s.handleAuthzPolicyBundle)
	}

	// Per-store storage-health report (opt-in WithStorageHealth). Full-path
	// admin endpoint gated by AdminMiddleware via the /api/v1/admin/ prefix.
	// Only mounted when at least one source is wired — byte-identical to a
	// build without it.
	if len(s.storageHealthSources) > 0 {
		s.router.GET(PathStorageHealth, s.handleStorageHealth)
	}

	// Mesh ext_authz HTTP endpoint (opt-in, cluster C1). The sidecar may
	// call it with the original request method, so register both GET and
	// POST at the configured path. Not mounted unless WithMeshExtAuthz is
	// wired — byte-identical to a build without it.
	if s.meshExtAuthz {
		path := s.meshExtAuthzPath
		if path == "" {
			path = PathMeshExtAuthz
		}
		s.router.GET(path, s.handleMeshExtAuthz)
		s.router.POST(path, s.handleMeshExtAuthz)
	}

	// CAEP/SSF push-delivery RECEIVER (opt-in, the inbound half of OpenID
	// Shared Signals). A trusted upstream transmitter POSTs a signed SET
	// here; the receiver validates it fail-closed and revokes the mapped
	// subject's local access. Not mounted unless WithCAEPReceiver is wired —
	// byte-identical to a build without it.
	if s.caepReceiver != nil {
		s.router.POST(PathSSFReceive, s.handleSSFReceive)
	}
}

// mountFederationEndpoints registers the RFC 9728 protected-resource metadata,
// the OpenID Federation 1.0 entity configuration (+ §8 fetch when this server
// is a superior), and the B2B home-realm discovery routes — each opt-in.
func (s *Server) mountFederationEndpoints() {
	// OpenID Federation 1.0 entity configuration (opt-in). Serves the OP's
	// self-signed Entity Statement at the well-known endpoint so the OP is
	// discoverable as a federation ENTITY. Not mounted unless
	// RFC 9728 Protected Resource Metadata (opt-in). Public discovery doc;
	// unmounted when not wired (byte-identical).
	if s.protectedResourceMetadata != nil {
		s.router.GET(PathProtectedResourceMetadata, s.handleProtectedResourceMetadata)
	}
	// WithFederationEntity is wired — byte-identical to a build without it.
	if s.federationEntity != nil {
		s.router.GET(PathFederationEntityConfig, s.handleFederationEntityConfig)
		// OpenID Federation 1.0 §8 Federation Fetch endpoint — mounted ONLY when
		// this server is configured as a SUPERIOR (≥1 subordinate). It issues
		// SIGNED Subordinate Statements about configured subordinates so a
		// resolver can climb THROUGH this server. With no subordinates the route
		// is NOT mounted AND the entity config advertises no
		// federation_fetch_endpoint — byte-identical to the slice-1 leaf OP.
		if s.federationEntity.HasSubordinates() {
			s.router.GET(PathFederationFetch, s.handleFederationFetch)
		}
	}

	// Home-realm discovery (opt-in B2B). Given a login identifier (email) it
	// returns the enterprise connection serving that domain so the login UI
	// routes the user to the right upstream IdP. Not mounted unless
	// WithConnectionStore is wired — byte-identical to a build without it.
	if s.connectionStore != nil {
		s.router.GET(PathHomeRealm, s.handleHomeRealm)
		s.router.POST(PathHomeRealm, s.handleHomeRealm)
	}
}

// Handler returns the http.Handler for the server.
//
// Middleware wiring (outermost → innermost):
//
//	metrics      record count + duration on every request (incl 429s)
//	  ratelimit    reject brute-force traffic before hitting the router
//	    bodylimit    cap request size before allocating buffers
//	      router       the SSO handler stack registered by Mount()
//
// Operational endpoints served OUTSIDE the entire middleware stack
// (never rate-limited, never counted in HTTP metrics, never body-
// capped):
//
//	/livez     process is alive — always 200 when the handler runs
//	/readyz    composite readiness — aggregates [WithReadyCheck]
//	/metrics   Prometheus scrape (when [WithMetrics] is set)
//
// Kubelet probes MUST hit /livez and /readyz, not /health. The
// /health route stays registered inside the router for backward
// compatibility but goes through middleware (including rate limiting),
// which is the wrong shape for cluster probes.
//
// Omitting all four optional middlewares + checks returns the bare
// router behind the mux — zero overhead inside, mux only routes
// /livez, /readyz, and `/` (so the mux cost is negligible).
func (s *Server) Handler() http.Handler {
	s.Mount()
	inner := s.buildMiddlewareChain(s.router)
	return s.buildProbeMux(inner)
}

// buildMiddlewareChain wraps the router (innermost) with the optional CORS,
// body-limit, rate-limit, trusted-proxies, metrics, and tracing middlewares in
// the documented outermost->innermost order. trustedProxies MUST wrap before
// rate limiting so the limiter keys on the validated real client IP.
func (s *Server) buildMiddlewareChain(inner http.Handler) http.Handler {
	// Security headers wrap the router innermost so they fire during
	// response writing — after inner handlers have set their own headers
	// (Cache-Control: no-store, X-Frame-Options: DENY, etc). The
	// headerOnceResponseWriter pattern prevents overwriting already-set
	// headers. Probe endpoints (/livez, /readyz, /metrics) are served by
	// buildProbeMux outside this chain and are NOT affected.
	if s.securityHeadersEnabled {
		inner = handler.SecurityHeaders(inner)
	}
	if s.corsPolicy != nil {
		// CORS sits innermost (just outside the router) so preflight
		// 204s don't traverse routing, but still get counted by metrics
		// and rate-limited like any other request — defensive against
		// preflight floods.
		inner = cors.Middleware(*s.corsPolicy)(inner)
	}
	if s.bodyLimit > 0 || len(s.bodyLimitByPath) > 0 {
		inner = bodyLimitMiddleware(s.bodyLimit, s.bodyLimitByPath)(inner)
	}
	if s.rateLimitPolicy != nil {
		inner = ratelimit.Middleware(*s.rateLimitPolicy)(inner)
	}
	if s.trustedProxies != nil {
		// TrustedProxies sits just outside the rate limiter so that
		// KeyByClientIP — called inside the rate-limit middleware — sees
		// the validated real client IP from the request context rather than
		// the raw X-Forwarded-For header. It must wrap BEFORE rate limiting;
		// placing it after would let the limiter bucket on an unvalidated
		// (forgeable) IP value.
		inner = s.trustedProxies.Middleware(inner)
	}
	if s.metrics != nil {
		inner = metrics.Middleware(s.metrics)(inner)
	}
	if s.tracingOperation != "" {
		// Tracing wraps outermost so the span covers the full request
		// lifecycle including time spent in metrics / ratelimit /
		// bodyLimit middlewares — useful when debugging "where did the
		// 200ms go" on a slow request.
		inner = tracing.Middleware(s.tracingOperation)(inner)
	}
	return inner
}

// SPA mount prefixes served by buildProbeMux outside the SSO router. Held as
// consts so each prefix's mux.Handle and StripPrefix uses cannot drift apart.
const (
	pathAdminConsolePrefix = "/admin/"
	pathHostedLoginPrefix  = "/login/"
	pathPortalPrefix       = "/portal/"
)

// buildProbeMux serves the operational probe endpoints (/livez, /readyz,
// /metrics) and the opt-in SPA bundles OUTSIDE the middleware stack, routing
// everything else to inner. See Handler's doc for why probes bypass middleware.
func (s *Server) buildProbeMux(inner http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(PathLivez, s.handleLivez)
	mux.HandleFunc(PathReadyz, s.handleReadyz)
	if s.metrics != nil {
		mux.Handle(PathMetrics, promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}))
	}
	// Admin console SPA (opt-in). Served from /admin/ so the browser client
	// has a stable origin to call back to /api/v1/admin/* from. The
	// http.FileServerFS + StripPrefix pattern means /admin/index.html is
	// reachable as /admin/ and the browser can navigate without path leakage
	// into the SSO routing layer. Not wired by default — byte-identical to a
	// build without the console when adminConsoleFS is nil.
	if s.adminConsoleFS != nil {
		mux.Handle(pathAdminConsolePrefix, http.StripPrefix(pathAdminConsolePrefix, http.FileServerFS(s.adminConsoleFS)))
	}
	// Hosted login SPA (opt-in). Served from /login/ so the browser can
	// reach the SPA while the JSON /auth/login endpoint remains at its
	// existing path (no overlap). Zero protocol changes — the SPA calls
	// /auth/login over JSON like any other client. Not wired by default —
	// byte-identical to a build without the UI when hostedLoginFS is nil.
	if s.hostedLoginFS != nil {
		mux.Handle(pathHostedLoginPrefix, http.StripPrefix(pathHostedLoginPrefix, http.FileServerFS(s.hostedLoginFS)))
	}
	// End-user self-service portal SPA (opt-in). Served from /portal/; it calls
	// the /me* endpoints over JSON with the user's own bearer. Not wired by
	// default — byte-identical when portalFS is nil.
	if s.portalFS != nil {
		mux.Handle(pathPortalPrefix, http.StripPrefix(pathPortalPrefix, http.FileServerFS(s.portalFS)))
	}
	mux.Handle("/", inner)
	return mux
}

// handleLivez returns 200 unconditionally — the handler running at
// all is itself the liveness signal. Cheap; no allocations beyond
// the response.
