package sso

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/middleware"
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
	s.mountBrandingEndpoint()
	s.mountClusterEndpoints()
	s.mountFederationEndpoints()
	s.mountAdminSurface()
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
	s.router.GET(PathStatus, s.handleStatus)
	s.router.GET(PathJWKS, s.handleJWKS)
	s.mountDiscovery()
	s.router.POST(PathLogin, s.handleLogin)
	s.router.POST(PathMFAComplete, s.handleMFAComplete)
	s.router.POST(PathSendCode, s.handleSendCode)
	s.router.GET(PathCallback, s.handleCallback)
	// Unauthenticated forgot-password flow. Requires the reset-token store AND
	// the credential store (reset must SetPassword on success) — byte-identical
	// without both.
	if s.passwordResetStore != nil && s.passwordCredentialStore != nil && s.selfServiceGateOn() {
		s.router.POST(PathForgotPassword, s.handleForgotPassword)
		s.router.POST(PathResetPassword, s.handleResetPassword)
	}
	// Opt-in self-service signup. Needs a UserProvider (create) + credential
	// store (set password). Default-off — byte-identical when not enabled.
	if s.signupEnabled && s.userProvider != nil && s.passwordCredentialStore != nil && s.selfServiceGateOn() {
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
	s.mountCIBAEndpoint()
	s.router.POST(oauth.PathRegister, s.handleRegister)
	s.router.GET(oauth.PathRegisterByID, s.handleRegistrationGet)
	s.router.PUT(oauth.PathRegisterByID, s.handleRegistrationPut)
	s.router.DELETE(oauth.PathRegisterByID, s.handleRegistrationDelete)
	s.mountOIDCUserEndpoints()
	s.router.POST(PathLogout, s.handleLogout)
}

// gateOn resolves a single FeatureGates field: nil (unset) or an explicit
// true both mean ON — only an explicit false turns a surface off. This is
// what makes an operator's own opt-in config (e.g. WithCAEPReceiver) keep a
// gate effectively on even when FeatureGates never mentions it, per the
// FeatureGates doc.
func gateOn(explicit *bool) bool {
	return explicit == nil || *explicit
}

// The seven gate-check methods below are the single source of truth Mount()
// and the endpoint inventory (server_routes_admin.go) both consult — keeping
// them as named methods (rather than inlining gateOn(s.featureGates.X) at
// each call site) means the inventory can never drift from what Mount()
// actually decided.
func (s *Server) oidcGateOn() bool        { return gateOn(s.featureGates.OIDC) }
func (s *Server) cibaGateOn() bool        { return gateOn(s.featureGates.CIBA) }
func (s *Server) caepGateOn() bool        { return gateOn(s.featureGates.CAEP) }
func (s *Server) federationGateOn() bool  { return gateOn(s.featureGates.Federation) }
func (s *Server) selfServiceGateOn() bool { return gateOn(s.featureGates.SelfService) }
func (s *Server) adminAPIGateOn() bool    { return gateOn(s.featureGates.AdminAPI) }
func (s *Server) webSPAGateOn() bool      { return gateOn(s.featureGates.WebSPA) }

// mountOIDCUserEndpoints registers the OIDC-specific /userinfo and
// /end_session routes. Split out of mountCoreOAuthOIDC (which sits at the
// function-length budget) so the OIDC gate check lives in exactly one place.
func (s *Server) mountOIDCUserEndpoints() {
	if !s.oidcGateOn() {
		return
	}
	s.router.GET(PathUserInfo, s.handleUserInfo)
	s.router.GET(PathEndSession, s.handleEndSession)
}

// mountCIBAEndpoint registers POST /backchannel-authentication. Before
// FeatureGates existed this route was mounted unconditionally (the handler
// itself 501s without a CIBA store) — the gate is the first way to hide it
// from a probe entirely rather than let it 501.
func (s *Server) mountCIBAEndpoint() {
	if s.cibaGateOn() {
		s.router.POST(PathBackchannelAuth, s.handleBackchannelAuth)
	}
}

// mountSelfServiceProfile registers the authenticated /me* self-service
// endpoints for permissions/menus/roles, sessions, consents, org membership,
// and profile — each gated on its backing store, and all of them behind the
// SelfService feature gate (a deployment that never wants an end-user-facing
// self-service surface hides the whole group).
func (s *Server) mountSelfServiceProfile() {
	if !s.selfServiceGateOn() {
		return
	}
	s.router.GET(PathMyPermissions, s.handleMyPermissions)
	s.router.GET(PathMyMenus, s.handleMyMenus)
	s.router.GET(PathMyRoles, s.handleMyRoles)
	if s.sessionMgr != nil {
		s.router.GET(PathMySessions, s.handleMySessions)
		s.router.DELETE(PathMySessions, s.handleRevokeMySessions)
		s.router.DELETE(PathMySessionByID, s.handleDeleteMySession)
		// /me/sessions* self-service endpoints follow the /me/* naming
		// convention used by the rest of the self-service API surface.
		s.router.GET(PathMeSessions, s.handleMeSessions)
		s.router.DELETE(PathMeSessionByID, s.handleDeleteMeSession)
		s.router.POST(PathMeSessionsRevokeAll, s.handleMeSessionsRevokeAll)
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
// verified email change), gated on both their backing store and the
// SelfService feature gate. The public per-host branding lookup used to live
// here too; it moved to mountBrandingEndpoint (gated by WebSPA instead — it
// serves the hosted login SPA, not an authenticated self-service action).
func (s *Server) mountSelfServiceCredentials() {
	if !s.selfServiceGateOn() {
		return
	}
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
}

// mountBrandingEndpoint registers the public per-host branding lookup the
// hosted login SPA consumes. Gated by WebSPA (not SelfService) and a tenant
// store (Domain.Branding is its source) — byte-identical to a build without
// either.
func (s *Server) mountBrandingEndpoint() {
	if s.tenantStore != nil && s.webSPAGateOn() {
		s.router.GET(PathBranding, s.handleBranding)
	}
}

// mountClusterEndpoints and mountFederationEndpoints (cluster/mesh/CAEP-
// receiver and OpenID Federation + B2B home-realm route registration) moved
// to server_federation.go, alongside federationMeshState (the fields they
// gate on) and the federation handlers — this file was at the line budget.

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
	inner = s.wrapInnerMiddlewares(inner)
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
	inner = s.wrapPanicRecovery(inner)
	return inner
}

// wrapInnerMiddlewares applies the innermost slice of the chain in the exact
// order it ran inline in buildMiddlewareChain: request/response debug logging,
// then security headers, CORS, compression, and body limiting.
//
// Security headers wrap the router innermost so they fire during response
// writing — after inner handlers have set their own headers (Cache-Control:
// no-store, X-Frame-Options: DENY, etc). The headerOnceResponseWriter pattern
// prevents overwriting already-set headers. Probe endpoints (/livez, /readyz,
// /metrics) are served by buildProbeMux outside this chain and are NOT
// affected. CORS sits just outside the router so preflight 204s don't
// traverse routing, but still get counted by metrics and rate-limited like
// any other request — defensive against preflight floods.
func (s *Server) wrapInnerMiddlewares(inner http.Handler) http.Handler {
	if s.debugRequestLogging {
		inner = middleware.RequestLogger(s.logger, false)(inner)
	}
	if s.securityHeadersEnabled {
		inner = handler.SecurityHeaders(inner)
	}
	if s.corsPolicy != nil {
		inner = cors.Middleware(*s.corsPolicy)(inner)
	}
	inner = s.wrapCompression(inner)
	if s.bodyLimit > 0 || len(s.bodyLimitByPath) > 0 {
		inner = bodyLimitMiddleware(s.bodyLimit, s.bodyLimitByPath)(inner)
	}
	return inner
}

// wrapPanicRecovery conditionally wraps the handler chain with panic
// recovery as the outermost layer — see buildMiddlewareChain for the
// full ordering rationale.
func (s *Server) wrapPanicRecovery(inner http.Handler) http.Handler {
	if s.panicRecovery {
		return middleware.Recover(s.logger)(inner)
	}
	return inner
}

// wrapCompression conditionally wraps the handler chain with gzip
// response compression for large JSON payloads.
func (s *Server) wrapCompression(inner http.Handler) http.Handler {
	if s.compressionEnabled {
		return middleware.Compress(inner)
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
	// build without the console when adminConsoleFS is nil (or WebSPA is off).
	if s.adminConsoleFS != nil && s.webSPAGateOn() {
		mux.Handle(pathAdminConsolePrefix, http.StripPrefix(pathAdminConsolePrefix, http.FileServerFS(s.adminConsoleFS)))
	}
	// Hosted login SPA (opt-in). Served from /login/ so the browser can
	// reach the SPA while the JSON /auth/login endpoint remains at its
	// existing path (no overlap). Zero protocol changes — the SPA calls
	// /auth/login over JSON like any other client. Not wired by default —
	// byte-identical to a build without the UI when hostedLoginFS is nil (or
	// WebSPA is off).
	if s.hostedLoginFS != nil && s.webSPAGateOn() {
		mux.Handle(pathHostedLoginPrefix, http.StripPrefix(pathHostedLoginPrefix, http.FileServerFS(s.hostedLoginFS)))
	}
	// End-user self-service portal SPA (opt-in). Served from /portal/; it calls
	// the /me* endpoints over JSON with the user's own bearer. Not wired by
	// default — byte-identical when portalFS is nil (or WebSPA is off).
	if s.portalFS != nil && s.webSPAGateOn() {
		mux.Handle(pathPortalPrefix, http.StripPrefix(pathPortalPrefix, http.FileServerFS(s.portalFS)))
	}
	mux.Handle("/", inner)
	return mux
}

// handleLivez returns 200 unconditionally — the handler running at
// all is itself the liveness signal. Cheap; no allocations beyond
// the response.
