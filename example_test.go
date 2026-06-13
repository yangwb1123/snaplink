package sso_test

// Compile-only godoc examples showing the recommended wiring for
// common deployment shapes. These render on pkg.go.dev as the first
// thing new contributors see when they land on the package.

import (
	"context"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/ratelimit"
	"github.com/snaplink/sso/tracing"
)

// Example_productionWiring composes every optional middleware in the
// SDK for a production-grade single-binary deployment. The
// middlewares stack outermost → innermost in [sso.Server.Handler]:
//
//	tracing → metrics → ratelimit → bodyLimit → cors → router
//
// /livez, /readyz, and /metrics are served OUTSIDE the stack so
// kubelet probes and Prometheus scrapes never get throttled, traced,
// or counted as noise.
//
// Each option is independent — omit any line below to opt out of
// that concern with zero overhead (the middleware reduces to the
// identity wrap when its option is unset).
func Example_productionWiring() {
	ctx := context.Background()

	// 1. Tracing — boots the OTLP exporter from OTEL_* env vars.
	// No-op when OTEL_EXPORTER_OTLP_ENDPOINT is unset.
	tracingShutdown, _ := tracing.Init(ctx, tracing.WithServiceName("sso-server"))
	defer func() { _ = tracingShutdown(ctx) }()

	// 2. SDK building blocks (the things every deployment needs).
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519Issuer("sso-server"))
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()

	// 3. Observability — shared Metrics struct, fed to both the
	// Server (HTTP request counters) and operator-side scrape (via
	// /metrics, served outside the middleware stack).
	m := metrics.New()

	srv := sso.NewServer(
		// Identity + storage.
		sso.WithIssuer("sso-server"),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithSessionManager(sessions),

		// Observability — Prometheus metrics + OTLP traces.
		sso.WithMetrics(m),
		sso.WithTracing("sso-server"),

		// Security hardening.
		sso.WithBodyLimit(1<<20), // 1 MiB per request
		sso.WithRateLimit(ratelimit.Policy{
			Default: ratelimit.NewMemoryLimiter(1, 60), // 1/s sustained, 60 burst
			Prefixes: []ratelimit.PrefixRule{
				// Tight bucket for the credential-stuffing-prone endpoints.
				{Prefix: "/auth/login", Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
				{Prefix: "/auth/send-code", Limiter: ratelimit.NewMemoryLimiter(10.0/60, 10)},
			},
		}),
		sso.WithCORS(cors.Policy{
			AllowedOrigins:   []string{"https://app.example.com"},
			AllowedHeaders:   []string{"Authorization", "Content-Type"},
			ExposedHeaders:   []string{"X-Request-ID", "Retry-After"},
			AllowCredentials: true,
			MaxAge:           time.Hour,
		}),

		// Operational.
		sso.WithReadyCheck("user-provider", func(ctx context.Context) error {
			// Trivial liveness check — replace with a real DB ping
			// when you swap MemoryUserProvider for a SQL backend.
			_, _ = users.List(ctx)
			return nil
		}),
	)

	// srv.Handler() returns the http.Handler with the full stack
	// composed. Mount on your transport of choice:
	//
	//   http.ListenAndServe(":8080", srv.Handler())
	_ = srv
}

// Example_minimumViable shows the smallest set of options needed for
// a working sso-server — just the identity + storage primitives. No
// observability, no security hardening. Suitable for tests and
// throwaway dev runs only.
func Example_minimumViable() {
	srv := sso.NewServer(
		sso.WithIssuer("sso-dev"),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
	)
	_ = srv
}
