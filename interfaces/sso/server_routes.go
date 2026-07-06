package sso

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/snaplink/sso/docs"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/apidocs"
	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/platform/lifecycle/wasmauthz"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/tracing"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Route-path re-exports (relocated from aliases.go to keep that file within
// the per-file line budget). Beside Mount, which consumes them.
const (
	PathMeshExtAuthz       = core.PathMeshExtAuthz
	PathNetPolicies        = core.PathNetPolicies
	PathNetPolicyByName    = core.PathNetPolicyByName
	PathNetPolicyClassify  = core.PathNetPolicyClassify
	PathNetPolicyResolveMe = core.PathNetPolicyResolveMe
	PathPAR                = core.PathPAR
	PathBackchannelAuth    = core.PathBackchannelAuth
	PathReadyz             = core.PathReadyz
	PathMetrics            = core.PathMetrics
	PathStatus             = core.PathStatus
	PathRevoke             = core.PathRevoke
	PathRevokeAll          = core.PathRevokeAll
	PathSAMLMetadata       = core.PathSAMLMetadata
	PathSAMLSSO            = core.PathSAMLSSO
	PathSAMLSSOCallback    = core.PathSAMLSSOCallback
	PathSAMLSLO            = core.PathSAMLSLO
	PathSAMLSLOContinue    = core.PathSAMLSLOContinue
	PathSAMLSPSLO          = core.PathSAMLSPSLO
	PathSendCode           = core.PathSendCode
	PathToken              = core.PathToken
	PathUserInfo           = core.PathUserInfo
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
	s.mountOrgAdminSelfService()
	s.mountClusterEndpoints()
	s.mountFederationEndpoints()
	s.mountAdminSurface()
	s.mountAPIVersionPreview()
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
// and the endpoint inventory (server_routes_admin.go) both consult. Two of
// them — adminAPIGateOn/webSPAGateOn — read a LIVE flag (sso_wiring.go's
// adminAPILive/webSPALive) instead of s.featureGates: those are the
// hot-reloadable gates (accessors.go's SetAdminAPIGateEnabled/
// SetWebSPAGateEnabled); the rest stay boot-time-only.
func (s *Server) oidcGateOn() bool        { return gateOn(s.featureGates.OIDC) }
func (s *Server) cibaGateOn() bool        { return gateOn(s.featureGates.CIBA) }
func (s *Server) caepGateOn() bool        { return gateOn(s.featureGates.CAEP) }
func (s *Server) federationGateOn() bool  { return gateOn(s.featureGates.Federation) }
func (s *Server) selfServiceGateOn() bool { return gateOn(s.featureGates.SelfService) }
func (s *Server) adminAPIGateOn() bool    { return s.adminAPILive.Load() }
func (s *Server) webSPAGateOn() bool      { return s.webSPALive.Load() }

// mountOIDCUserEndpoints registers the OIDC-specific /userinfo,
// /end_session, and (session-management-gated) /check_session_iframe
// routes. Defined in server_userinfo.go — out of this file, which sits at
// the line budget — beside the handlers it mounts.

// mountCIBAEndpoint registers POST /backchannel-authentication. Before
// FeatureGates existed this route was mounted unconditionally (the handler
// itself 501s without a CIBA store) — the gate is the first way to hide it
// from a probe entirely rather than let it 501.
func (s *Server) mountCIBAEndpoint() {
	if s.cibaGateOn() {
		s.router.POST(PathBackchannelAuth, s.handleBackchannelAuth)
	}
}

// mountClusterEndpoints and mountFederationEndpoints (cluster/mesh/CAEP-
// receiver and OpenID Federation + B2B home-realm route registration) moved
// to server_federation.go, alongside federationMeshState (the fields they
// gate on) and the federation handlers — this file was at the line budget.
// mountSelfServiceCredentials (the /me* credential + privacy endpoints,
// including MFA recovery codes) lives in server_me.go for the same reason.

// Opt-in embedded API-docs viewer route paths (WithAPIDocsUI). Unexported
// and local to this file — like pathAdminConsolePrefix et al. above, they
// are pure internal wiring detail, not part of the SDK's public surface —
// rather than re-exported core.Path* consts, since shared/core/consts.go
// is at its own line budget and nothing outside this package needs them.
const (
	pathAdminAPIDocs     = "/admin/docs"
	pathAdminAPIDocsSpec = "/admin/docs/openapi.json"
)

// mountAPIDocsUI registers the opt-in embedded API-documentation viewer
// (WithAPIDocsUI): GET .../docs (self-contained HTML) + GET
// .../docs/openapi.json (the same spec as parsed JSON, for tooling).
// Unlike the OPEN static SPA bundles buildProbeMux serves below (admin
// console, hosted login, portal — generic UI shells with no sensitive
// content), these two routes hang off the AdminMiddleware-gated
// /api/v1/admin/ group mountAdminSurface builds, because the full live
// endpoint + schema inventory they expose IS operationally sensitive.
// Not mounted without the option — byte-identical to a build without it.
func (s *Server) mountAPIDocsUI(api Router) {
	if s.apiDocsUIHandler == nil {
		return
	}
	api.GET(pathAdminAPIDocs, s.apiDocsUIHandler)
	api.GET(pathAdminAPIDocsSpec, s.apiDocsSpecHandler)
}

// Pluggable WASM authorization-decision engine (platform/lifecycle/wasmauthz)
// admin debug route: a single POST, so unlike the webhook/netpolicy blocks
// there is no separate mutation handler to delegate — see the package doc
// for why POST (a JSON body) rather than rebac's GET+query-params shape.
// Placed here (rather than beside mountRebacAdminAPI in handlers.go, which
// is at its directory's frozen file-count ceiling) beside mountAPIDocsUI,
// the other opt-in admin-mount function this file already hosts.
func (s *Server) handleWASMAuthzCheck(ctx HandlerContext) { wasmauthz.HandleCheck(s, ctx) }

// PathAdminWASMAuthzCheck route-path re-export — aliases.go is at its line
// budget, same reason as the Token Portfolio / crypto-inventory / rebac consts.
const PathAdminWASMAuthzCheck = core.PathAdminWASMAuthzCheck

// mountWASMAuthzAdminAPI registers the opt-in WASM authz engine's ONE
// operational-debugging route (opt-in WithWASMAuthzEngine). Not mounted
// without an engine — byte-identical to a build without the feature. This
// is deliberately the ONLY wasmauthz route: the package is a primitive an
// operator consults from their own integration code, not a full admin CRUD
// surface (see the package doc).
func (s *Server) mountWASMAuthzAdminAPI(api Router) {
	if s.wasmAuthzEngine == nil {
		return
	}
	api.POST(PathAdminWASMAuthzCheck, s.handleWASMAuthzCheck)
}

// WithAPIDocsUI mounts a read-only, self-contained API-documentation
// viewer for docs/openapi.yaml at GET /api/v1/admin/docs (+ its
// machine-readable GET /api/v1/admin/docs/openapi.json companion). Both
// hang off the /api/v1/admin/ prefix, so AdminMiddleware gates them
// exactly like every other admin route (admin:read) — the full endpoint +
// schema inventory is operationally sensitive, not public. See
// interfaces/apidocs's package doc for what the viewer is (and is not: no
// CDN script, no vendored Swagger-UI/Redoc bundle). Relocated from
// options_httpstack.go (which was at the line budget) to sit beside
// mountAPIDocsUI, the route registration it feeds.
//
// nil (the default, i.e. this option never called) leaves both routes
// unmounted — byte-identical to a build without this feature: the spec
// stays a static file in docs/, never served over HTTP.
func WithAPIDocsUI() Option {
	return func(s *Server) {
		ui, spec, err := apidocs.New(docs.OpenAPISpec)
		if err != nil {
			// Only reachable with a hand-corrupted embedded spec (CI's
			// `make docs-validate` guards the committed file) — fail safe by
			// leaving the feature off rather than mounting a broken page.
			return
		}
		s.apiDocsUIHandler, s.apiDocsSpecHandler = ui, spec
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
	inner = s.wrapInnerMiddlewares(inner)
	if s.degradation != nil {
		// DR gate sits just inside rate limiting (flood protection still applies
		// to a shedding replica) and just outside body-limit (a refused write
		// short-circuits before the body is read). Metrics still counts the 503.
		inner = s.degradationGate()(inner)
	}
	if s.rateLimitPolicy != nil {
		// A PolicyStore (rather than baking the resolved Policy straight
		// into the closure) lets SetRateLimitPolicy swap the live limiters
		// later — e.g. from a SIGHUP config reload — without rebuilding
		// this middleware chain. See ratelimit.DynamicMiddleware's doc.
		s.rateLimitStore = ratelimit.NewPolicyStore(s.resolvedRateLimitPolicy())
		inner = ratelimit.DynamicMiddleware(s.rateLimitStore)(inner)
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

// SetRateLimitPolicy atomically swaps the live rate-limit Policy — the
// runtime hook config/reload uses to apply a security.rate_limit.* change
// without a restart. Applies the SAME Metrics/TenantKeyFunc defaulting
// resolvedRateLimitPolicy applies at boot, so a caller passing a bare
// ratelimit.Policy (e.g. from serverbuildplatform.BuildRateLimitPolicy)
// still gets metrics + per-tenant rejection labeling wired automatically.
//
// Returns false as a no-op when rate limiting was never enabled at boot (no
// WithRateLimit option) — there is no already-installed middleware slot to
// swap into, mirroring feature_gates' "can't add a gate after boot"
// limitation. Only the NUMBERS inside an already-enabled policy can be made
// live; turning rate limiting on/off entirely still needs a restart.
func (s *Server) SetRateLimitPolicy(p ratelimit.Policy) bool {
	if s.rateLimitStore == nil {
		return false
	}
	if p.Metrics == nil {
		p.Metrics = s.metrics
	}
	if p.TenantKeyFunc == nil && s.tenantStore != nil {
		store, opts := s.tenantStore, s.tenantMiddlewareOpts
		p.TenantKeyFunc = func(r *http.Request) string {
			return tenant.ResolveTenantID(r.Context(), store, opts, r)
		}
	}
	s.rateLimitStore.Set(p)
	return true
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
		inner = handler.SecurityHeaders(s.resolvedSecurityHeadersPolicy())(inner)
	}
	if s.corsPolicy != nil {
		inner = cors.Middleware(*s.corsPolicy)(inner)
	}
	inner = s.wrapCompression(inner)
	if s.bodyLimit > 0 || len(s.bodyLimitByPath) > 0 {
		inner = bodyLimitMiddleware(s.bodyLimit, s.bodyLimitByPath)(inner)
	}
	// Accept-Version negotiation + Sunset/Deprecation headers (ADR-0008):
	// outermost of this cluster so an unsupported requested version is
	// rejected before body-limit/compression/CORS/security-headers run.
	// wrapPanicRecovery/wrapCompression live in sso_wiring.go (beside the
	// fields they read) — this file is at the line budget; wrapAPIVersioning
	// joins them there for the same reason.
	inner = s.wrapAPIVersioning(inner)
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
	// has a stable origin to call back to /api/v1/admin/* from. Mounted
	// whenever adminConsoleFS is wired, REGARDLESS of the WebSPA gate's
	// current value — core.GateHTTPHandler gates reachability LIVE, per
	// request, instead of at this boot-time mount decision, so
	// SetWebSPAGateEnabled can hot-toggle it without a re-Mount. Nil FS
	// (never wired via WithAdminConsoleFS) still means no mux entry at all.
	if s.adminConsoleFS != nil {
		mux.Handle(pathAdminConsolePrefix, core.GateHTTPHandler(s.webSPAGateOn, s.wrapSecurityHeaders(http.StripPrefix(pathAdminConsolePrefix, http.FileServerFS(s.adminConsoleFS)))))
	}
	// Hosted login SPA (opt-in). Served from /login/ so the browser can
	// reach the SPA while the JSON /auth/login endpoint remains at its
	// existing path. Same live-gate treatment as the admin console above.
	if s.hostedLoginFS != nil {
		mux.Handle(pathHostedLoginPrefix, core.GateHTTPHandler(s.webSPAGateOn, s.wrapSecurityHeaders(http.StripPrefix(pathHostedLoginPrefix, http.FileServerFS(s.hostedLoginFS)))))
	}
	// End-user self-service portal SPA (opt-in). Served from /portal/; it
	// calls /me* over JSON with the user's own bearer. Same live-gate
	// treatment as the admin console above.
	if s.portalFS != nil {
		mux.Handle(pathPortalPrefix, core.GateHTTPHandler(s.webSPAGateOn, s.wrapSecurityHeaders(http.StripPrefix(pathPortalPrefix, http.FileServerFS(s.portalFS)))))
	}
	s.mountDeveloperPortalSPA(mux)
	mux.Handle("/", inner)
	return mux
}

// handleLivez returns 200 unconditionally — the handler running at
// all is itself the liveness signal. Cheap; no allocations beyond
// the response.
