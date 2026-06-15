package sso

import (
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/geo"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/spi"
	"github.com/snaplink/sso/tenant"
)
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

// WithRegionMiddleware installs the serving-region resolution middleware:
// during Mount the Server runs region.Middleware(resolver, opts) immediately
// after the geo middleware so the resolved serving-region ID is stashed on
// the HandlerContext for the login residency gate + audit enrichment to read
// via region.FromHandlerContext. opts carries the optional OnError reporter
// and the middleware-level AllowedRegions backstop.
//
// A nil resolver is a no-op: Mount does NOT install the middleware (mirrors
// WithGeoProvider's nil discipline), so a server that never wires a resolver
// behaves byte-identically to a pre-residency build — no middleware runs, the
// login gate sees servingRegion=="" and returns nil. Wire this alongside
// WithTenantResidencyCheck to turn the resolved region into a hard gate.
func WithRegionMiddleware(resolver region.Resolver, opts region.MiddlewareOptions) Option {
	return func(s *Server) {
		s.regionResolver = resolver
		s.regionMiddlewareOpts = opts
	}
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

// WithInvalidationBus wires a cross-replica coordination bus
// ([cluster.Bus]). When set, cache-invalidating admin mutations (today:
// tenant suspension) publish an Event so every other replica clears the
// matching local cache immediately, instead of waiting out its per-node
// cache TTL. Call [Server.StartInvalidationBus] with the run context to
// begin consuming Events on this replica.
//
// No-op when unset — single-node deployments invalidate locally and need
// no bus. A nil bus is treated as unset.
func WithInvalidationBus(bus cluster.Bus) Option {
	return func(srv *Server) { srv.invalidationBus = bus }
}

// WithCoordinatedKeyRotation opts this Server into deadline-coordinated
// same-kid signing-key rotation cutover. It REQUIRES an invalidation bus
// ([WithInvalidationBus]); without one it is inert.
//
// THE PROBLEM it closes: signing-key rotation + retirement run on INDEPENDENT
// per-replica timers (defaultimpl.StartRotation/scheduleRetire). During a
// rolling deploy a kid demoted-then-retired early on replica A leaves a token
// A signed under it hitting a hard "unknown kid" 401 on a lagging replica B
// that already advanced its own retire timer (or whose grace window was shorter
// in clock terms). The leaderless aggregation (signingkeys/) answers "can B
// verify A's kid", but NOT "do all replicas retire the OLD kid at the same
// instant".
//
// THE FIX: when armed, [RotationConfig.OnRotate]'s cmd callback publishes a
// cluster.KindSigningKeyRotation Event carrying the demoted kid, the new kid,
// and a retire deadline (= now + the SAME RotationConfig.GracePeriod). Every
// armed replica that receives it DEFERS the demoted kid's retirement to that
// deadline (adopting the new kid verify-only at once). The deferral only ever
// WIDENS a replica's verify window — a dropped or garbage Event merely lets the
// replica's own per-replica grace-window retire fire as the fallback. It can
// never cause a replica to drop the old kid EARLY (the 401 this exists to
// prevent), honoring the AGENTS.md §2 "rotation serves outgoing+incoming keys"
// invariant.
//
// The deadline is wall-clock-coordinated, so the same NTP discipline AGENTS.md
// §2 mandates for session expiry applies: ops MUST slew, never step, the clock
// (chrony). A backward step only DELAYS a retire (fail-safe), never advances it.
//
// No-op when unset (the default) OR when no bus is wired: the publish side
// emits nothing and a received KindSigningKeyRotation Event is ignored, so
// behavior is byte-identical to a build without the feature — no goroutine, no
// metric, no timer.
func WithCoordinatedKeyRotation() Option {
	return func(srv *Server) { srv.coordinatedKeyRotation = true }
}

// WithCrossReplicaRevocation opts this Server into cross-replica access-token
// revocation propagation. It REQUIRES an invalidation bus
// ([WithInvalidationBus]); without one it is inert.
//
// THE PROBLEM it closes: each JWT issuer holds an IN-PROCESS revocation
// deny-set (the `revoked` map keyed by the full token). /token/revoke adds the
// presented token to that deny-set on the replica that handled the request —
// but ONLY that replica. A token revoked on replica A keeps validating on
// replica B until its own exp. The Redis hot-path peers cover session/refresh/
// PAR/etc. but NOT this deny-set, and the CAEP transmitter pushes revocation
// signals to external RPs, not to the server's own replicas.
//
// THE FIX: when armed, a /token/revoke (or /end_session id_token_hint revoke)
// that hit at least one local issuer PUBLISHES a cluster.KindTokenRevoked Event
// carrying the token + its exp. Every armed replica that receives it ADDS the
// token to its own per-issuer deny-set (the same local revoke-across-issuers
// path, WITHOUT re-publishing — the adopt is local-only, so there is no
// broadcast loop).
//
// SAFETY: the propagation is purely ADDITIVE — applying an Event only ever ADDS
// a token to a deny-set (more tokens rejected, never fewer), and a token
// rejected because it's in the deny-set returns the SAME invalid_token response
// as any other validation failure (no caller-observable new code path). A
// dropped or garbage Event merely leaves that replica at today's per-replica
// behavior (the token still expires on its own exp) — fail-open, never a valid
// token wrongly rejected (beyond the mesh-internal trusted bus surface, which
// is trusted exactly like KindTenantSuspension). The adopt path never accepts
// revocations from request-facing input — only the bus and the local
// /token/revoke.
//
// No-op when unset (the default) OR when no bus is wired: the publish side
// emits nothing and a received KindTokenRevoked Event is ignored, so behavior
// is byte-identical to a build without the feature — no goroutine, no metric.
func WithCrossReplicaRevocation() Option {
	return func(srv *Server) { srv.crossReplicaRevocation = true }
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
// issuance. See [spi.RiskScorer] for the contract — fail-open on scorer
// errors, default [spi.DecisionAllow] when this option is not set.
func WithRiskScorer(r spi.RiskScorer) Option {
	return func(s *Server) { s.riskScorer = r }
}

// WithMFAProvider activates MFA orchestration: when the spi.RiskScorer
// returns [spi.DecisionRequireMFA] AND this option is set, /auth/login
// returns a pending mfa_required response (challenge ID + supported
// methods) instead of tokens. The client follows up with POST
// /auth/mfa carrying the challenge ID + factor proof. Without this
// option, RequireMFA decays to Allow — preserving the historical
// no-op behavior for callers wiring a scorer that may emit RequireMFA
// in advance of MFA orchestration shipping.
//
// Requires [WithMFAChallengeStore] (or sso panics at handler entry
// the first time a challenge would be issued — fail-loud, since a
// silent fallthrough to Allow would defeat the security control the
// scorer asked for).
func WithMFAProvider(p spi.MFAProvider) Option {
	return func(s *Server) { s.mfaProvider = p }
}

// WithAnomalyRunner wires an [anomaly.Runner] — the worker pool
// that fans LoginEvents (success + failure) out to registered
// [anomaly.Detector]s off the request hot path. The runner runs
// AFTER the login response is built; detectors surface anomalies
// via the configured [anomaly.Sink] (audit + optional webhook),
// NEVER back into the login decision.
//
// nil runner → no-op dispatch (zero overhead). Pre-call
// runner.Start() before passing here so workers are alive when the
// first event arrives.
func WithAnomalyRunner(r *anomaly.Runner) Option {
	return func(s *Server) { s.anomalyRunner = r }
}

// WithMFAChallengeStore persists in-flight MFA challenges (the state
// between /auth/login returning mfa_required and /auth/mfa completing
// the factor). ttl controls how long a challenge stays redeemable;
// pass 0 to inherit [spi.DefaultMFAChallengeTTL].
//
// Backends: [defaultimpl.MemoryMFAChallengeStore] for single-replica
// deploys, the SQLite peer for cluster-shared state. Required when
// [WithMFAProvider] is set.
func WithMFAChallengeStore(store spi.MFAChallengeStore, ttl time.Duration) Option {
	return func(s *Server) {
		s.mfaChallengeStore = store
		if ttl > 0 {
			s.mfaChallengeTTL = ttl
		}
	}
}

// WithMetrics enables Prometheus instrumentation on the HTTP layer +
// login / token / risk-scoring counters. The Server's Handler() will
// also expose /metrics for scraping the supplied registry. Omit the
// option for zero overhead (no middleware, no counters).
func WithMetrics(m *metrics.Metrics) Option {
	return func(s *Server) { s.metrics = m }
}

// WithTenantMetricsAllowlist opts into the per-tenant login + token-issue
// metrics (sso_login_attempts_by_tenant_total + sso_tokens_issued_by_tenant_total),
// labeled by tenant. CARDINALITY-GATED by design (§5): the tenant label is
// emitted ONLY for the tenant ids in this bounded allowlist; every other
// tenant — and every untenanted client — folds into the single tenant="other"
// bucket, so the label cardinality is len(allowlist)+1, never the unbounded
// SaaS-tenant set. This mirrors how MFA-method labels are restricted to the
// provider's SupportedMethods() before they reach the registry.
//
// A nil/empty allowlist (the default) is byte-identical OFF: the two vectors
// are never registered and never emitted (zero series). REQUIRES
// [WithMetrics] — without a wired *metrics.Metrics there is nothing to
// register the vectors on, so the option is inert. Never label by raw user
// id or unbounded client_id.
func WithTenantMetricsAllowlist(tenants []string) Option {
	return func(s *Server) {
		if len(tenants) == 0 {
			return
		}
		set := make(map[string]struct{}, len(tenants))
		for _, t := range tenants {
			if t == "" {
				continue
			}
			set[t] = struct{}{}
		}
		if len(set) == 0 {
			return
		}
		s.tenantMetricsAllowlist = set
		if s.metrics != nil {
			s.metrics.EnableTenantMetrics()
		}
	}
}

// ReadyCheck reports whether a dependency / subsystem is ready to
// serve traffic. Implementations return nil when healthy, an error
// describing the problem when not. Run from /readyz on every probe.
// an error marks the server unready (503). Multiple checks aggregate.
// Empty check list = always ready (default).
//
// Example: ping the database, verify etcd reachable, confirm bootstrap
// completed. Cheap checks only — the readiness probe fires every few
// seconds in Kubernetes. The aggregate /readyz handler bounds every
// check by 3 seconds; per-check overrides go through
// [WithReadyCheckTimeout].
func WithReadyCheck(name string, check ReadyCheck) Option {
	return func(s *Server) {
		if check == nil || name == "" {
			return
		}
		// Merge into a pre-registered timeout placeholder when one
		// exists for this name — let operators wire the timeout
		// option BEFORE the check option in any order.
		for i := range s.readyChecks {
			if s.readyChecks[i].Name == name && s.readyChecks[i].Check == nil {
				s.readyChecks[i].Check = check
				return
			}
		}
		s.readyChecks = append(s.readyChecks, namedReadyCheck{Name: name, Check: check})
	}
}

// WithReadyCheckTimeout registers a per-check timeout that overrides
// the aggregate 3-second /readyz deadline. Useful for slow backends
// (etcd cross-region, large SQLite WAL recovery) where the global
// bound is too tight, while keeping fast checks (memory pings)
// snappy. Timeout MUST be > 0; non-positive values silently fall
// back to the aggregate deadline.
//
// Calling this for a check already registered via WithReadyCheck
// updates that check's timeout; otherwise it pre-registers the
// timeout for a check added later in the option chain.
func WithReadyCheckTimeout(name string, timeout time.Duration) Option {
	return func(s *Server) {
		if name == "" || timeout <= 0 {
			return
		}
		// If the check is already registered, update in place.
		for i := range s.readyChecks {
			if s.readyChecks[i].Name == name {
				s.readyChecks[i].Timeout = timeout
				return
			}
		}
		// Pre-register: store the timeout against a nil Check; the
		// later WithReadyCheck call will populate Check + leave the
		// Timeout the pre-registered value.
		s.readyChecks = append(s.readyChecks, namedReadyCheck{Name: name, Timeout: timeout})
	}
}

// WithCORS installs a CORS middleware sitting between bodyLimit and
// the router, so preflight 204s short-circuit before routing but
// still get counted in metrics + traced + rate-limited. Composes
// with [ratelimit.Middleware] / [metrics.Middleware] / [tracing] —
// each handles its own concern.
//
// Empty AllowedOrigins disables CORS (zero overhead). Use the
// modern [cors] package shape rather than the legacy router-level
// [CORS] MiddlewareFunc when you want credentials / exposed headers
// / preflight caching.
func WithCORS(policy cors.Policy) Option {
	return func(s *Server) { s.corsPolicy = &policy }
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

// WithConsentStore wires a persistent consent record store. When set,
// /auth/login records the user's consent decision and enforces the
// prompt=consent parameter (re-prompting even when a grant already exists).
// When the requested scopes are not fully covered by an existing grant,
// consent_required is returned (HTTP 200) so the SPA can surface a
// consent screen. When nil (the default), all consent enforcement is skipped
// — behavior is byte-identical to a build without this feature.
