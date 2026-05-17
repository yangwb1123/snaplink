// Package metrics holds the Prometheus metric vectors the SSO server
// emits, plus the HTTP middleware that records request count + latency.
//
// Design choices that affect operators:
//
//   - All metric names are prefixed `sso_` so they don't collide with
//     metrics an embedding application emits on the same registry.
//
//   - Label cardinality is bounded by design — we use `status_class`
//     (2xx / 4xx / 5xx) rather than raw status code, `method` rather
//     than path, `provider` (authenticator name) rather than user id.
//     Operators who want per-endpoint breakdowns should derive them
//     from traces, not from labels.
//
//   - The Registry is held INSIDE the Metrics struct so operators who
//     embed the SSO server in a larger app can share a registry via
//     NewWithRegistry. Default New() returns a fresh isolated one
//     (the right thing for cmd/sso-server).
//
// Wire with sso.WithMetrics(metrics.New()) — when the option is
// omitted, the server skips instrumentation entirely (zero overhead).
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics groups every collector the SSO server publishes. Construct
// once at server boot, pass into [sso.WithMetrics].
type Metrics struct {
	// Registry is the prometheus.Registerer the metrics are bound to.
	// Exposed so /metrics can serve from it and tests can scrape it
	// directly.
	Registry *prometheus.Registry

	// HTTP layer.
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	// Auth flow.
	LoginAttemptsTotal *prometheus.CounterVec // labels: provider, outcome
	TokensIssuedTotal  *prometheus.CounterVec // labels: strategy

	// Risk scoring (zero traffic when no RiskScorer wired).
	RiskDecisionsTotal *prometheus.CounterVec // labels: decision
}

// New returns a Metrics bound to a fresh isolated Registry. This is
// the right shape for cmd/sso-server: the binary owns its own metric
// namespace and exposes it via /metrics.
//
// Includes the standard process + Go runtime collectors (goroutines,
// gc pause, file descriptors, etc.) which every prometheus deployment
// expects to see.
func New() *Metrics {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return NewWithRegistry(reg)
}

// NewWithRegistry binds the metric vectors to an existing Registerer.
// Use when embedding the SSO server into a larger app whose metrics
// already live on a shared registry (the embedding app supplies the
// process/Go runtime collectors itself).
//
// Caller is responsible for serving the registry via promhttp. The
// SSO server's /metrics endpoint only fires when sso.WithMetrics
// receives a *Metrics whose Registry is the one we constructed.
func NewWithRegistry(reg *prometheus.Registry) *Metrics {
	factory := promauto.With(reg)

	return &Metrics{
		Registry: reg,

		HTTPRequestsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameHTTPRequestsTotal,
				Help: "Total HTTP requests served by the SSO router, by method and status class (2xx/3xx/4xx/5xx).",
			},
			[]string{LabelMethod, LabelStatusClass},
		),

		HTTPRequestDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: NameHTTPRequestDuration,
				Help: "HTTP request latency in seconds, by method. Default buckets cover the typical auth-flow latency range (millis to seconds).",
				// DefBuckets cover .005s through 10s — appropriate for auth flows.
				Buckets: prometheus.DefBuckets,
			},
			[]string{LabelMethod},
		),

		LoginAttemptsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameLoginAttemptsTotal,
				Help: "Login attempts at /auth/login, by authenticator provider and outcome (success/failure).",
			},
			[]string{LabelProvider, LabelOutcome},
		),

		TokensIssuedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameTokensIssuedTotal,
				Help: "Tokens issued on successful login, by token strategy (jwt/session).",
			},
			[]string{LabelStrategy},
		),

		RiskDecisionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameRiskDecisionsTotal,
				Help: "RiskScorer decisions, by decision value (allow/deny/require_mfa). Zero traffic when no scorer is configured.",
			},
			[]string{LabelDecision},
		),
	}
}
