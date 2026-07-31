package sso

// HTTP-stack and operational options: middleware toggles (CORS, tracing,
// body limits, rate limiting, compression, request logging, panic recovery),
// admin-plane knobs, and the /token idempotency cache. Split from
// options_misc.go to keep both files within the 500-line budget.

import (
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rebac"
	"github.com/yangwb1123/snaplink/platform/lifecycle/wasmauthz"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
	"github.com/yangwb1123/snaplink/shared/core"
)

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
//
// For endpoints that need a different cap (e.g. /par accepts JAR
// JWTs that legitimately exceed the global default), combine with
// WithBodyLimitForPath.
func WithBodyLimit(maxBytes int64) Option {
	return func(s *Server) { s.bodyLimit = maxBytes }
}

// WithBodyLimitForPath overrides the body cap for requests whose URL
// path matches the given prefix. Useful for /par (accepts a signed
// JAR JWT — encrypted JARs especially can run 8-32 KiB while the
// rest of the SSO surface stays under 4 KiB) or /scim/v2/Bulk
// (legitimately large). Longest-matching prefix wins; falls back to
// WithBodyLimit's global value (or unlimited when neither is set).
//
// Pass max == 0 to make a specific path unlimited even while the
// global limit is in effect (escape hatch — use sparingly).
//
// May be called multiple times to register several overrides; later
// calls for the same prefix replace earlier values.
func WithBodyLimitForPath(prefix string, maxBytes int64) Option {
	return func(s *Server) {
		if s.bodyLimitByPath == nil {
			s.bodyLimitByPath = map[string]int64{}
		}
		s.bodyLimitByPath[prefix] = maxBytes
	}
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

// resolvedRateLimitPolicy returns a copy of s.rateLimitPolicy with the
// server's Metrics + tenant resolver filled in when WithRateLimit's Policy
// didn't already set them explicitly. Read at Handler()-build time (not at
// WithRateLimit call time) so option ORDER relative to WithMetrics /
// WithTenantStore never matters. The tenant resolver runs a store lookup
// ONLY on the reject path (see ratelimit.Policy.TenantKeyFunc), so it adds
// no cost to allowed traffic. SetRateLimitPolicy (accessors.go) applies the
// SAME defaulting rules to a later live policy swap.
func (s *Server) resolvedRateLimitPolicy() ratelimit.Policy {
	p := *s.rateLimitPolicy
	if p.Metrics == nil {
		p.Metrics = s.metrics
	}
	if p.TenantKeyFunc == nil && s.tenantStore != nil {
		store, opts := s.tenantStore, s.tenantMiddlewareOpts
		p.TenantKeyFunc = func(r *http.Request) string {
			return tenant.ResolveTenantID(r.Context(), store, opts, r)
		}
	}
	return p
}

// WithAdminTokenStore wires a store for admin bearer token metadata,
// enabling the GET/POST/DELETE /api/v1/admin/tokens lifecycle
// endpoints. Without it, admin tokens have no management surface.
func WithAdminTokenStore(store core.AdminTokenStore) Option {
	return func(s *Server) { s.adminTokenStore = store }
}

// WithDegradationManager installs the disaster-recovery degraded-service gate.
// The manager holds an atomically-swappable mode (normal / read_only /
// auth_only / local_only / maintenance); when the mode is anything but normal
// the enforcement middleware refuses the request classes that mode sheds with
// 503 + Retry-After (probes always pass), and the admin GET/POST
// /api/v1/admin/dr/mode endpoints let an operator read + set the mode. A health
// loop that detects a datastore heartbeat loss can drive the same posture by
// calling m.SetMode(ctx, DegradationModeReadOnly, reason) directly.
//
// nil (the default) ⇒ no gate is installed and no route is mounted, so a build
// without this option is byte-identical. The manager's default mode is normal,
// which is itself a pass-through — installing the option but leaving the mode at
// normal has no request-path effect beyond one atomic load per request.
func WithDegradationManager(m *DegradationManager) Option {
	return func(s *Server) {
		if m == nil {
			return
		}
		s.degradation = m
		// Register the audit + metric side effects. The hook reads s.auditor /
		// s.metrics lazily at fire time, so option ORDER relative to
		// WithAuditRecorder / WithMetrics does not matter.
		m.OnChange(s.onDegradationChange)
	}
}

// WithAdminRateLimit sets a server-level admin API rate limit. rate is
// tokens per second; burst is the maximum accumulated tokens. When set,
// the admin HTTP and gRPC middleware enforce this limit before processing
// any admin request — protecting the control plane from accidental or
// malicious overuse. 0 for rate disables the limit (default).
//
// Example: 10 tokens/s, burst 20 allows short bursts of up to 20
// requests while sustaining 10/s.
//
//	srv := sso.NewServer(
//	    sso.WithAdminRateLimit(10, 20),
//	)
func WithAdminRateLimit(tokensPerSec float64, burst int) Option {
	return func(s *Server) {
		s.adminRateLimit.rate = tokensPerSec
		s.adminRateLimit.burst = burst
	}
}

// WithAuthorizeRequestTimeout sets a wall-clock deadline on the
// /auth/login handler. When the deadline elapses before the handler
// completes, the server returns interaction_required to the client
// so the user can retry instead of hanging indefinitely on a slow
// upstream IdP. 0 (default) disables the timeout.
//
// Typical value: 5 minutes — generous enough for any OIDC/SAML
// federation round-trip + user interaction, but prevents a wedged
// provider from pinning a goroutine forever.
func WithAuthorizeRequestTimeout(timeout time.Duration) Option {
	return func(s *Server) {
		if timeout > 0 {
			s.authzRequestTimeout = timeout
		}
	}
}

// WithBackupSource registers a SQLite backup source so the admin
// endpoint POST /api/v1/admin/backup can trigger VACUUM INTO on it.
func WithBackupSource(src core.BackupSource) Option {
	return func(s *Server) {
		s.backupSources = append(s.backupSources, src)
	}
}

// WithPanicRecovery installs a panic-recovery handler as the
// outermost middleware wrapper. Any panic from the router, its
// middlewares, or a handler returns HTTP 500 instead of crashing
// the process. The panic is logged with a full stack trace via the
// wired Logger — or NopLogger when no logger is set.
//
// Enabled by default.
func WithPanicRecovery(enabled bool) Option {
	return func(s *Server) { s.panicRecovery = enabled }
}

// WithCompression enables gzip response compression for responses
// larger than 1 KB. The middleware checks the client's Accept-Encoding
// header and transparently compresses responses. Useful for admin API
// endpoints (ListClients, audit events) that return large JSON payloads.
func WithCompression() Option {
	return func(s *Server) { s.compressionEnabled = true }
}

// WithRequestLogging enables debug-level request/response logging.
// When logBodies is true, request and response bodies are included in
// the log output (use with caution — bodies may contain secrets).
// Default is disabled (zero overhead).
func WithRequestLogging(logBodies bool) Option {
	return func(s *Server) {
		s.debugRequestLogging = true
		s.debugRequestLogBodies = logBodies
	}
}

// WithIdempotentStore wires an idempotency cache for the /token endpoint.
// When set, the server checks for an Idempotency-Key header on token
// requests and caches the first successful response, returning it for
// repeat requests with the same key — safe retry semantics without
// duplicate token issuance.
//
// The cache TTL is typically aligned with the token lifetime or a
// maximum of 1 hour. Pass nil to disable idempotency (default).
func WithIdempotentStore(cache core.IdempotentCache) Option {
	return func(s *Server) { s.idempotentCache = cache }
}

// FeatureGates controls which optional protocol surfaces Mount() registers
// routes for — attack-surface reduction for deployment shapes that only need
// a subset of the SSO server's protocol coverage (e.g. an OAuth-2.0-only
// gateway that never wants /userinfo or /end_session routable at all).
//
// Every field is a *bool so three states are distinguishable:
//   - nil (the zero value, and every field an operator omits from
//     `feature_gates:` in YAML): the gate follows today's behavior — ON.
//     This is what makes the whole feature byte-identical when unused.
//   - explicit true: ON, same as unset.
//   - explicit false: OFF — the surface's routes are NOT registered, so a
//     probe against them gets the router's native 404, indistinguishable
//     from a path that was never defined (no "route exists but rejects you"
//     signal to leak).
//
// A surface's own opt-in config (e.g. WithCAEPReceiver, WithFederationEntity)
// keeps gating its routes on TOP of this — the gate is an extra AND, never a
// replacement. So "config presence implies the gate is on unless explicitly
// disabled" falls out for free: with the field unset the gate is already ON,
// and an explicit false always wins regardless of what else is configured.
type FeatureGates struct {
	// OIDC gates the OpenID Connect-specific endpoints layered on top of
	// bare OAuth 2.0: /userinfo and /end_session. Off ⇒ a deployment
	// advertising itself as OAuth-2.0-only doesn't expose them at all.
	OIDC *bool
	// CIBA gates POST /backchannel-authentication (OIDC CIBA Core 1.0).
	// Unlike every other route this Mount() registers, the CIBA route was
	// previously mounted UNCONDITIONALLY even without a CIBA store wired
	// (the handler itself 501s) — this gate is the first way to hide it.
	CIBA *bool
	// CAEP gates the inbound OpenID Shared Signals (CAEP/SSF) push-delivery
	// receiver, POST /ssf/receive. Only relevant when WithCAEPReceiver is
	// also wired — otherwise the route was never mounted anyway.
	CAEP *bool
	// Federation gates the OpenID Federation 1.0 + RFC 9728 discovery
	// surface: the protected-resource metadata document, the federation
	// entity configuration (+ §8 fetch when this server is a superior),
	// and B2B home-realm discovery.
	Federation *bool
	// SelfService gates the end-user self-service surface: unauthenticated
	// signup/forgot-password/reset-password/verify-email, and the
	// authenticated /me* profile, sessions, consents, org-membership, MFA
	// factor, passkey, data-export, and account-erasure endpoints.
	SelfService *bool
	// AdminAPI gates the entire /api/v1/admin/* REST surface (client
	// lookups excluded — those live at /api/v1/clients and are not
	// admin-scoped). Off ⇒ operators who run admin tooling out-of-band
	// (or not at all) don't expose the admin bearer-auth challenge surface.
	AdminAPI *bool
	// Branding gates the public per-host branding lookup (GET /branding) —
	// the only route left under this flag now that sso-server serves no
	// static frontend of its own. Canonical name; WebSPA is its deprecated
	// alias (both set = Branding wins; YAML rejects both set).
	Branding *bool
	// WebSPA is the deprecated alias of Branding, retained for source
	// compatibility.
	WebSPA *bool
}

// brandingGate resolves the canonical gate: Branding, else WebSPA, else nil.
func (f FeatureGates) brandingGate() *bool {
	if f.Branding != nil {
		return f.Branding
	}
	return f.WebSPA
}

// WithFeatureGates installs deployment-shape attack-surface gating: any
// field left nil keeps its route set exactly as it was before FeatureGates
// existed (byte-identical). An explicit false on a field hides the
// corresponding routes entirely — Mount() does not register them, so a
// probe gets a router-native 404 rather than an endpoint that exists but
// declines the request.
//
//	srv := sso.NewServer(
//	    sso.WithFeatureGates(sso.FeatureGates{
//	        OIDC:     sso.Bool(false), // OAuth-2.0-only deployment
//	        Branding: sso.Bool(false), // API-only, no hosted UI
//	    }),
//	)
func WithFeatureGates(g FeatureGates) Option {
	return func(s *Server) { s.featureGates = g }
}

// Bool returns a pointer to b — a convenience so callers can write
// sso.Bool(false) inline in a FeatureGates literal instead of declaring a
// local variable to take its address.
func Bool(b bool) *bool { return &b }

// WithWebhookEngine wires a [webhook.Engine] — the generic event/webhook
// egress engine — as an additional audit Sink (the same AddSink/MultiSink
// seam WithCAEPTransmitter and WithSSEBroker use) and mounts the admin
// subscription + dead-letter-queue management routes (GET/POST
// /api/v1/admin/webhooks/subscriptions, DELETE .../{id}, GET
// .../deadletters, POST .../deadletters/{id}/replay).
//
// nil (the default) leaves both the sink tap and the routes unmounted —
// byte-identical to a build without the feature. A wired engine with ZERO
// registered subscriptions is ALSO byte-identical traffic-wise: matching a
// recorded event against an empty subscription set is a cheap no-op with no
// outbound POST.
func WithWebhookEngine(e *webhook.Engine) Option {
	return func(s *Server) { s.webhookEngine = e }
}

// WithRebacEngine wires a [rebac.Engine] — the Zanzibar-style relationship-
// tuple Check engine (platform/lifecycle/rebac) — and mounts ONE
// operational-debugging admin route: GET /api/v1/admin/rebac/check?object=
// &relation=&subject=. Unlike WithWebhookEngine/WithCAEPTransmitter, this
// does NOT tap the audit-sink pipeline or any built-in gate — rebac is an
// independent authorization primitive an operator consults from their own
// integration code (see the package doc), so wiring it changes NOTHING
// about /auth/login or any other request path.
//
// nil (default) leaves the route unmounted.
func WithRebacEngine(e *rebac.Engine) Option {
	return func(s *Server) { s.rebacEngine = e }
}

// WithRebacStore wires the tuple store for the FGA product API.
func WithRebacStore(store rebac.RelationTupleStore) Option {
	return func(s *Server) { s.rebacStore = store }
}

// WithWASMAuthzEngine wires a [wasmauthz.Engine] — a pluggable, WebAssembly-
// hosted authorization-decision engine (platform/lifecycle/wasmauthz) — and
// mounts ONE operational-debugging admin route: POST
// /api/v1/admin/wasmauthz/check (JSON body; POST rather than rebac's GET+
// query-params check because a wasmauthz.Request has a richer, nested shape
// — a Context map — that doesn't fit cleanly into query parameters). Like
// WithRebacEngine, this does NOT tap the audit-sink pipeline or any built-in
// gate — the hosted WASM policy module is consulted by an operator's OWN
// integration code (see the package doc), so wiring it changes NOTHING
// about /auth/login or any other request path.
//
// nil (the default) leaves the route unmounted — byte-identical to a build
// without the feature.
func WithWASMAuthzEngine(e *wasmauthz.Engine) Option {
	return func(s *Server) { s.wasmAuthzEngine = e }
}

// WithSCIMProvisioner wires an outbound SCIM 2.0 provisioning push — the
// reverse direction of the SCIM /Users + /Groups receiver — as an
// additional audit Sink (the same AddSink/MultiSink seam
// WithWebhookEngine/WithCAEPTransmitter/WithSSEBroker use). Pass a
// [scimprovision.Sink] (protocols/scimprovision); the parameter is typed as
// the narrower [audit.Sink] interface rather than the concrete type so this
// package does not need to import protocols/scimprovision (which itself
// imports protocols/scim for the shared wire types — importing the
// concrete type here would close an import cycle through
// infrastructure/defaultimpl's existing grandfathered dependency back into
// this package).
//
// nil (the default) leaves the sink tap unwired — byte-identical to a build
// without the feature: no outbound SCIM traffic, ever.
func WithSCIMProvisioner(sink audit.Sink) Option {
	return func(s *Server) { s.scimProvisionSink = sink }
}

// WebhookEngine returns the wired generic event/webhook egress engine (nil
// when unset), satisfying webhook.HandlerDeps for the admin subscription +
// dead-letter-queue management routes. Relocated from accessors.go (beside
// its WithWebhookEngine option here) to keep that file within the per-file
// line budget.
func (s *Server) WebhookEngine() *webhook.Engine { return s.webhookEngine }

// Compile-time proof that *Server satisfies the webhook admin handlers'
// dependency surface (Auditor() lives in accessors.go; WebhookEngine() just above).
var _ webhook.HandlerDeps = (*Server)(nil)

// RebacEngine returns the wired rebac.Engine (nil when unset), satisfying
// rebac.HandlerDeps for the admin debug route.
func (s *Server) RebacEngine() *rebac.Engine           { return s.rebacEngine }
func (s *Server) RebacStore() rebac.RelationTupleStore { return s.rebacStore }

var _ rebac.HandlerDeps = (*Server)(nil)

// WASMAuthzEngine returns the wired wasmauthz.Engine (nil when unset),
// satisfying wasmauthz.HandlerDeps for the admin debug route.
func (s *Server) WASMAuthzEngine() *wasmauthz.Engine { return s.wasmAuthzEngine }

var _ wasmauthz.HandlerDeps = (*Server)(nil)

// SCIMProvisionSink returns the wired outbound SCIM 2.0 provisioning sink
// (nil when unset — see WithSCIMProvisioner). Typed as audit.Sink rather
// than the concrete *scimprovision.Sink; see that option's doc for why.
func (s *Server) SCIMProvisionSink() audit.Sink { return s.scimProvisionSink }

// ConditionalAccessStore exposes the wired zero-trust CAP policy store (may be
// nil) for the admin governance view. Satisfies admin.Deps.
func (s *Server) ConditionalAccessStore() conditionalaccess.Store { return s.capStore }

// DomainResolver returns the DNS-TXT resolver for admin connection-domain
// verification, defaulting to the stdlib-backed production resolver when no
// custom one was injected — so the SDK works with zero configuration.
func (s *Server) DomainResolver() connections.DNSResolver {
	if s.domainVerificationResolver != nil {
		return s.domainVerificationResolver
	}
	return connections.NewDNSResolver()
}

// WithDomainVerificationResolver moved to options_grants.go (this file was
// at the line budget after adding WithWASMAuthzEngine below).

// WithAPIVersioning enables Accept-Version request-header negotiation
// (ADR-0008): supported lists every version token this deployment accepts
// (e.g. "v1", "v2alpha"). A request that sends Accept-Version naming a
// value NOT in this list is rejected with 400
// {"error":"unsupported_version"} before its route handler runs; a request
// that sends NO Accept-Version header — every client today — is completely
// unaffected. Omitting this option (the default) disables negotiation
// entirely: the header is never even inspected, so behavior is
// byte-identical to a build without this feature.
func WithAPIVersioning(supported ...string) Option {
	return func(s *Server) { s.apiVersionSupported = append([]string(nil), supported...) }
}

// WithAPIDeprecation marks the WHOLE API deprecated: every response carries
// the Deprecation header (+ Sunset when policy.Sunset is set, + Link when
// policy.Link is set). Combine with WithRouteDeprecation to ALSO (or
// instead) annotate individual endpoints — a path matching both gets the
// route-specific policy. Omitting this option (the default) means no
// response ever carries these headers.
func WithAPIDeprecation(policy middleware.DeprecationPolicy) Option {
	return func(s *Server) { s.deprecationPolicy = &policy }
}

// WithRouteDeprecation marks a single endpoint or a path-prefix group
// deprecated. path is matched exactly, or — when it ends in "/" — as a
// prefix (e.g. "/api/v1/admin/" matches every admin route). May be called
// multiple times to annotate several endpoints/groups independently.
// Omitting this option (the default) means no route carries these headers.
func WithRouteDeprecation(path string, policy middleware.DeprecationPolicy) Option {
	return func(s *Server) {
		if s.routeDeprecations == nil {
			s.routeDeprecations = map[string]middleware.DeprecationPolicy{}
		}
		s.routeDeprecations[path] = policy
	}
}

// WithAPIVersionPreview mounts GET /api/v2alpha/version — ADR-0008's ONE
// example route proving the "/api/v2alpha" path-prefix routing mechanism
// works, without building out a full v2 API surface. The response echoes
// this deployment's versioning posture (api_version, stability,
// supported_versions). Omitting this option (the default) means Mount()
// never registers the route — byte-identical to a build without it.
func WithAPIVersionPreview() Option {
	return func(s *Server) { s.apiV2AlphaPreview = true }
}

// WithAPIDocsUI moved to server_routes.go, beside mountAPIDocsUI (the route
// registration it feeds), to keep this file within the per-file line budget.
