package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/tenant"
	"github.com/snaplink/sso/tracing"
)

// Server is the core SSO orchestrator.
type Server struct {
	authenticators       map[string]Authenticator
	tokenIssuers         map[string]TokenIssuer // strategy name -> issuer
	defaultTokenStrategy string
	userProvider         UserProvider
	clientStore          ClientStore
	sessionMgr           SessionManager
	router               Router
	middleware           []MiddlewareFunc
	logger               Logger
	auditor              *audit.Recorder
	auditAPI             bool
	requestIDMW          bool
	permissions          permissions.Provider
	embedPermissions     bool
	netStore             netpolicy.Store
	netClassifier        *netpolicy.Classifier
	netAPI               bool
	geoProvider          geo.Provider
	geoMiddlewareOpts    GeoMiddlewareOptions
	tenantStore          tenant.Store
	tenantMiddlewareOpts TenantMiddlewareOptions
	riskScorer           RiskScorer
	metrics              *metrics.Metrics
	rateLimitPolicy      *ratelimit.Policy
	bodyLimit            int64
	readyChecks          []namedReadyCheck
	tracingOperation     string
	issuer               string
	sessionTTL           time.Duration
	tokenTTL             time.Duration
	baseURL              string
}

// Option configures the Server.
type Option func(*Server)

// NewServer creates a new SSO server.
func NewServer(opts ...Option) *Server {
	s := &Server{
		authenticators: make(map[string]Authenticator),
		tokenIssuers:   make(map[string]TokenIssuer),
		issuer:         DefaultIssuer,
		sessionTTL:     DefaultSessionDuration,
		tokenTTL:       DefaultTokenTTL,
		logger:         NopLogger{},
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithRouter sets the HTTP router.
func WithRouter(r Router) Option {
	return func(s *Server) { s.router = r }
}

// WithAuthenticator registers an authentication method.
func WithAuthenticator(a Authenticator) Option {
	return func(s *Server) { s.authenticators[a.Name()] = a }
}

// WithTokenIssuer registers a TokenIssuer under the given strategy name.
// Clients select among registered strategies via Client.TokenStrategy.
// If no client-level strategy is set, the Server's default strategy is used.
func WithTokenIssuer(name string, ti TokenIssuer) Option {
	return func(s *Server) { s.tokenIssuers[name] = ti }
}

// WithDefaultTokenStrategy names the strategy used when a Client does not
// specify its own.
func WithDefaultTokenStrategy(name string) Option {
	return func(s *Server) { s.defaultTokenStrategy = name }
}

// WithUserProvider sets the user data store.
func WithUserProvider(up UserProvider) Option {
	return func(s *Server) { s.userProvider = up }
}

// WithClientStore sets the client application store.
func WithClientStore(cs ClientStore) Option {
	return func(s *Server) { s.clientStore = cs }
}

// WithSessionManager sets the session manager.
func WithSessionManager(sm SessionManager) Option {
	return func(s *Server) { s.sessionMgr = sm }
}

// WithLogger sets the logger.
func WithLogger(l Logger) Option {
	return func(s *Server) { s.logger = l }
}

// WithIssuer sets the token issuer name.
func WithIssuer(issuer string) Option {
	return func(s *Server) { s.issuer = issuer }
}

// WithSessionTTL sets the session lifetime.
func WithSessionTTL(ttl time.Duration) Option {
	return func(s *Server) { s.sessionTTL = ttl }
}

// WithTokenTTL sets the token lifetime.
func WithTokenTTL(ttl time.Duration) Option {
	return func(s *Server) { s.tokenTTL = ttl }
}

// WithBaseURL sets the base URL of this SSO server.
func WithBaseURL(url string) Option {
	return func(s *Server) { s.baseURL = url }
}

// WithAuditRecorder enables audit-event recording. The Server will emit
// login/logout/code-send/etc. events to r. Without this option, audit calls
// are silent no-ops.
func WithAuditRecorder(r *audit.Recorder) Option {
	return func(s *Server) { s.auditor = r }
}

// WithAuditAPI mounts the audit query endpoints
// (GET /api/v1/audit/events, GET /api/v1/audit/events/:id). Requires a
// recorder to also be set. Endpoints are unauthenticated by default — gate
// them with middleware or a reverse proxy if exposed beyond localhost.
func WithAuditAPI() Option {
	return func(s *Server) { s.auditAPI = true }
}

// WithTracingMiddleware installs TracingMiddleware ahead of all routes.
// It propagates W3C Traceparent (trace_id + span chaining) and X-Request-Id
// (single-hop correlation) so audit events automatically pick them up.
func WithTracingMiddleware() Option {
	return func(s *Server) { s.requestIDMW = true }
}

// WithRequestIDMiddleware is a back-compat alias for WithTracingMiddleware.
// New code should call WithTracingMiddleware directly.
func WithRequestIDMiddleware() Option { return WithTracingMiddleware() }

// WithPermissionProvider enables the per-user permission/role/menu lookup
// endpoints. Without this option, those endpoints respond 501.
func WithPermissionProvider(p permissions.Provider) Option {
	return func(s *Server) { s.permissions = p }
}

// WithEmbedPermissionsInLogin attaches a user's roles, permissions, and menu
// tree to the /auth/login response — convenient for SPAs that want the
// authorization surface immediately, instead of an extra round trip.
func WithEmbedPermissionsInLogin() Option {
	return func(s *Server) { s.embedPermissions = true }
}

// WithNetworkPolicy enables the network-classification control plane. store
// is required; classifier is optional — when nil, the /classify and
// /resolve-me endpoints respond 501.
//
// Pair with WithNetworkPolicyAPI() to expose the REST endpoints under
// /api/v1/netpolicy/...; otherwise only the Server's internal callers
// (Mount routes that need to know the request's network class) use it.
func WithNetworkPolicy(store netpolicy.Store, classifier *netpolicy.Classifier) Option {
	return func(s *Server) {
		s.netStore = store
		s.netClassifier = classifier
	}
}

// WithNetworkPolicyAPI mounts the netpolicy REST endpoints
// (GET/POST /api/v1/netpolicy/policies[/:name], DELETE on :name,
// GET /api/v1/netpolicy/classify + /resolve-me). Requires WithNetworkPolicy.
// The endpoints are unauthenticated by default — gate them with middleware
// or a reverse proxy if exposed beyond localhost.
func WithNetworkPolicyAPI() Option {
	return func(s *Server) { s.netAPI = true }
}

// WithGeoProvider enables IP → geo enrichment on the auth path.
// During Mount, the Server installs GeoMiddleware ahead of all
// routes so handlers (and through them, AuthResult) can read the
// recommended language + country code via GeoFromHandlerContext.
//
// A nil provider is a no-op so callers may pass the result of a
// disabled-by-config factory unconditionally.
func WithGeoProvider(p geo.Provider) Option {
	return func(s *Server) { s.geoProvider = p }
}

// WithGeoMiddlewareOptions tunes how the geo middleware extracts
// the client IP and bounds the lookup. Optional — the middleware
// has sane defaults (XFF first hop → X-Real-IP → RemoteAddr,
// 200ms timeout, no error reporter). Pass a custom Extractor when
// the deployment doesn't trust forwarded headers (no edge proxy).
func WithGeoMiddlewareOptions(opts GeoMiddlewareOptions) Option {
	return func(s *Server) { s.geoMiddlewareOpts = opts }
}

// WithTenantStore enables multi-tenant + multi-domain routing.
// During Mount, the Server installs TenantMiddleware ahead of all
// routes so handlers (and audit enrichment) can read the resolved
// *Tenant + *Domain via TenantFromHandlerContext. A nil store is
// a no-op so callers may pass the result of a disabled-by-config
// factory unconditionally.
func WithTenantStore(s tenant.Store) Option {
	return func(srv *Server) { srv.tenantStore = s }
}

// WithTenantMiddlewareOptions tunes how the tenant middleware
// extracts the request hostname and bounds the lookup. Optional
// — defaults are XFH first-hop → r.Host (port stripped),
// 100ms timeout, suspended tenants resolve to "no tenant" so
// handlers naturally degrade. Pass a custom HostExtractor when
// the deployment doesn't trust X-Forwarded-Host.
func WithTenantMiddlewareOptions(opts TenantMiddlewareOptions) Option {
	return func(s *Server) { s.tenantMiddlewareOpts = opts }
}

// WithRiskScorer plugs in a fraud / abuse evaluator that runs on every
// /auth/login attempt after credential validation but before token
// issuance. See [RiskScorer] for the contract — fail-open on scorer
// errors, default [DecisionAllow] when this option is not set.
func WithRiskScorer(r RiskScorer) Option {
	return func(s *Server) { s.riskScorer = r }
}

// WithMetrics enables Prometheus instrumentation on the HTTP layer +
// login / token / risk-scoring counters. The Server's Handler() will
// also expose /metrics for scraping the supplied registry. Omit the
// option for zero overhead (no middleware, no counters).
func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Server) { s.metrics = m }
}

// ReadyCheck reports whether a dependency / subsystem is ready to
// serve traffic. Implementations return nil when healthy, an error
// describing the problem when not. Run from /readyz on every probe.
type ReadyCheck func(ctx context.Context) error

type namedReadyCheck struct {
	Name  string
	Check ReadyCheck
}

// WithReadyCheck adds a named check to /readyz. Any check returning
// an error marks the server unready (503). Multiple checks aggregate.
// Empty check list = always ready (default).
//
// Example: ping the database, verify etcd reachable, confirm bootstrap
// completed. Cheap checks only — the readiness probe fires every few
// seconds in Kubernetes.
func WithReadyCheck(name string, check ReadyCheck) Option {
	return func(s *Server) {
		if check == nil || name == "" {
			return
		}
		s.readyChecks = append(s.readyChecks, namedReadyCheck{Name: name, Check: check})
	}
}

// WithTracing wraps every request in an OpenTelemetry HTTP span,
// honoring incoming W3C traceparent headers as the parent. operation
// is the root span name (defaults to "sso-server" when empty).
//
// Calling this option DOES NOT initialize the OTLP exporter — that's
// a separate call to [tracing.Init] (typically in cmd/sso-server/main.go
// at startup). The middleware uses the global TracerProvider, so a
// no-op provider (the SDK default when Init isn't called or its
// endpoint is unset) means zero overhead beyond the otelhttp wrap
// itself.
//
// /metrics, /livez, and /readyz are served OUTSIDE this middleware
// (alongside the metrics + rate-limit middlewares) so scrape /probe
// traffic doesn't fill traces with noise.
func WithTracing(operation string) Option {
	return func(s *Server) {
		if operation == "" {
			operation = "sso-server"
		}
		s.tracingOperation = operation
	}
}

// WithBodyLimit caps request body size at max bytes. Larger requests
// are rejected with 413 + ErrPayloadTooLarge before the handler runs.
// 0 (default) disables the limit. Typical value: 1 << 20 (1 MiB) —
// generous for any auth-flow payload but blocks gigabyte-class DoS.
//
// Defends against two failure modes the SSO server otherwise has no
// protection from: pathological JSON bombs that swallow process
// memory, and slow-loris reads where an attacker dribbles bytes
// forever.
func WithBodyLimit(maxBytes int64) Option {
	return func(s *Server) { s.bodyLimit = maxBytes }
}

// WithRateLimit installs the ratelimit middleware in the server's
// Handler() chain. The middleware sits BETWEEN /metrics (which is
// never rate-limited so scrapers don't get 429s) and the metrics
// recorder (so 429 responses still show up in sso_http_requests_total
// with status_class="4xx"). When the option is omitted, no rate
// limiting is enforced.
//
// Common policy shape (10 logins/min/IP, 60 req/min/IP otherwise):
//
//	sso.WithRateLimit(ratelimit.Policy{
//	    Default: ratelimit.NewMemoryLimiter(1, 60),       // ~60/min, burst 60
//	    Prefixes: []ratelimit.PrefixRule{
//	        {Prefix: "/auth/login",     Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
//	        {Prefix: "/auth/send-code", Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
//	    },
//	})
func WithRateLimit(p ratelimit.Policy) Option {
	return func(s *Server) { s.rateLimitPolicy = &p }
}

// RegisterAuthenticator adds an authenticator at runtime.
func (s *Server) RegisterAuthenticator(a Authenticator) {
	s.authenticators[a.Name()] = a
}

// Mount registers all SSO endpoints on the router.
func (s *Server) Mount() {
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

	s.router.GET(PathHealth, s.handleHealth)
	s.router.GET(PathJWKS, s.handleJWKS)
	s.router.POST(PathLogin, s.handleLogin)
	s.router.POST(PathSendCode, s.handleSendCode)
	s.router.GET(PathCallback, s.handleCallback)
	s.router.POST(PathToken, s.handleToken)
	s.router.GET(PathUserInfo, s.handleUserInfo)
	s.router.POST(PathLogout, s.handleLogout)
	s.router.GET(PathMyPermissions, s.handleMyPermissions)
	s.router.GET(PathMyMenus, s.handleMyMenus)
	s.router.GET(PathMyRoles, s.handleMyRoles)

	api := s.router.Group(PathAPIPrefix)
	api.GET(PathClientByID, s.handleGetClient)
	if s.auditAPI && s.auditor != nil {
		api.GET(PathAuditEvents, s.handleAuditEvents)
		api.GET(PathAuditEventByID, s.handleAuditEventByID)
	}
	if s.netAPI && s.netStore != nil {
		api.GET(PathNetPolicies, s.handleListNetPolicies)
		api.GET(PathNetPolicyByName, s.handleGetNetPolicy)
		api.POST(PathNetPolicies, s.handleApplyNetPolicy)
		api.DELETE(PathNetPolicyByName, s.handleDeleteNetPolicy)
		api.GET(PathNetPolicyClassify, s.handleClassifyNetPolicy)
		api.GET(PathNetPolicyResolveMe, s.handleResolveMeNetPolicy)
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

	var inner http.Handler = s.router
	if s.bodyLimit > 0 {
		inner = bodyLimitMiddleware(s.bodyLimit)(inner)
	}
	if s.rateLimitPolicy != nil {
		inner = ratelimit.Middleware(*s.rateLimitPolicy)(inner)
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

	mux := http.NewServeMux()
	mux.HandleFunc(PathLivez, s.handleLivez)
	mux.HandleFunc(PathReadyz, s.handleReadyz)
	if s.metrics != nil {
		mux.Handle("/metrics", promhttp.HandlerFor(s.metrics.Registry, promhttp.HandlerOpts{}))
	}
	mux.Handle("/", inner)
	return mux
}

// handleLivez returns 200 unconditionally — the handler running at
// all is itself the liveness signal. Cheap; no allocations beyond
// the response.
func (s *Server) handleLivez(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"alive"}`))
}

// handleReadyz runs every registered [ReadyCheck] in parallel,
// aggregates results into `{name: "ok" | err.Error()}`, returns 200
// when all pass / 503 when any fail. Bounded by a 3-second context
// deadline so a hung check can't wedge the probe.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	results := make(map[string]string, len(s.readyChecks))
	allOK := true
	for _, c := range s.readyChecks {
		if err := c.Check(ctx); err != nil {
			results[c.Name] = err.Error()
			allOK = false
		} else {
			results[c.Name] = "ok"
		}
	}

	status := "ready"
	code := http.StatusOK
	if !allOK {
		status = "unready"
		code = http.StatusServiceUnavailable
	}

	body, _ := json.Marshal(map[string]any{
		"status": status,
		"checks": results,
	})
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// bodyLimitMiddleware wraps r.Body with MaxBytesReader and pre-checks
// Content-Length when set so over-sized requests fail before allocating
// any buffers. Chunked requests fall back to MaxBytesReader's
// streaming guard.
func bodyLimitMiddleware(max int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > max {
				w.Header().Set(HeaderContentType, ContentTypeJSON)
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				_, _ = w.Write([]byte(`{"error":"` + ErrPayloadTooLarge + `"}`))
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, max)
			next.ServeHTTP(w, r)
		})
	}
}

func (s *Server) getAuthenticator(name string) (Authenticator, error) {
	a, ok := s.authenticators[name]
	if !ok {
		return nil, fmt.Errorf("authenticator %q not registered", name)
	}
	return a, nil
}

// issuerForClient returns the TokenIssuer that should mint tokens for the
// given client. Resolution order: client.TokenStrategy → server default →
// (if exactly one issuer is registered) that one.
func (s *Server) issuerForClient(c *Client) (string, TokenIssuer, error) {
	name := ""
	if c != nil && c.TokenStrategy != "" {
		name = c.TokenStrategy
	} else if s.defaultTokenStrategy != "" {
		name = s.defaultTokenStrategy
	} else if len(s.tokenIssuers) == 1 {
		for n := range s.tokenIssuers {
			name = n
		}
	}
	if name == "" {
		return "", nil, fmt.Errorf("no token strategy resolvable for client")
	}
	ti, ok := s.tokenIssuers[name]
	if !ok {
		return name, nil, fmt.Errorf("token strategy %q not registered", name)
	}
	return name, ti, nil
}

// ValidateToken is the public face of validateAnyToken — returns just the
// claims for callers (e.g. the admin middleware) that don't care which
// issuer accepted the token.
func (s *Server) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	claims, _, err := s.validateAnyToken(ctx, token)
	return claims, err
}

// validateAnyToken tries each registered issuer until one accepts the token.
// Returned issuerName lets callers correlate revocations or audit logs.
func (s *Server) validateAnyToken(ctx context.Context, token string) (*TokenClaims, string, error) {
	var lastErr error
	for name, ti := range s.tokenIssuers {
		claims, err := ti.Validate(ctx, token)
		if err == nil {
			return claims, name, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no token issuers registered")
	}
	return nil, "", lastErr
}

// revokeAcrossIssuers asks every registered issuer to revoke the token
// (Revoke is expected to be tolerant of unknown tokens). Returns the names
// of issuers that successfully revoked.
func (s *Server) revokeAcrossIssuers(ctx context.Context, token string) []string {
	var revoked []string
	for name, ti := range s.tokenIssuers {
		if err := ti.Revoke(ctx, token); err == nil {
			revoked = append(revoked, name)
		}
	}
	return revoked
}

func (s *Server) requireDeps(deps ...string) error {
	for _, d := range deps {
		switch d {
		case depTokenIssuer:
			if len(s.tokenIssuers) == 0 {
				return fmt.Errorf("at least one TokenIssuer is required")
			}
		case depUserProvider:
			if s.userProvider == nil {
				return fmt.Errorf("UserProvider is required")
			}
		case depClientStore:
			if s.clientStore == nil {
				return fmt.Errorf("ClientStore is required")
			}
		case depSessionMgr:
			if s.sessionMgr == nil {
				return fmt.Errorf("SessionManager is required")
			}
		}
	}
	return nil
}

func (s *Server) validateSession(sessionID string) (*Session, error) {
	ctx := context.Background()
	session, err := s.sessionMgr.Get(ctx, sessionID)
	if err != nil {
		return nil, err
	}
	if session.IsExpired() || session.Revoked {
		return nil, fmt.Errorf("session expired or revoked")
	}
	return session, nil
}
