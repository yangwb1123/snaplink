package sso

// HTTP-stack and operational options: middleware toggles (CORS, tracing,
// body limits, rate limiting, compression, request logging, panic recovery),
// admin-plane knobs, and the /token idempotency cache. Split from
// options_misc.go to keep both files within the 500-line budget.

import (
	"time"

	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/shared/core"
)

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
