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

	// MFA orchestration (zero traffic when no MFAProvider wired).
	// MFAChallengesTotal counts every challenge issued at
	// /auth/login when the risk scorer returns DecisionRequireMFA;
	// MFACompletionsTotal counts /auth/mfa outcomes by mfa_method
	// + outcome (success/failure). Bounded cardinality: methods are
	// the wire-stable strings totp/webauthn/push/etc, not per-user.
	MFAChallengesTotal  *prometheus.CounterVec // labels: mfa_method
	MFACompletionsTotal *prometheus.CounterVec // labels: mfa_method, outcome

	// Retention scheduler observability. Single counter pair shared
	// across the three subsystems (audit, snapshot, push_approvals)
	// so operators can graph "what got pruned recently" with a
	// single PromQL query. Bounded subsystem cardinality (3 known
	// values). Operators alert on the errors series rising relative
	// to the pruned series — sustained errors with no successes
	// means retention is silently failing.
	RetentionPrunedTotal     *prometheus.CounterVec // labels: subsystem
	RetentionPruneErrorTotal *prometheus.CounterVec // labels: subsystem

	// WebAuthn ceremony completion. Incremented at the Finish phase
	// (cryptographic verification step) only — Begin observability
	// is derivable from sso_http_requests_total on the begin paths.
	// outcome ∈ {success, failure} (bounded cardinality).
	WebAuthnRegistrationsTotal *prometheus.CounterVec // labels: outcome
	WebAuthnAssertionsTotal    *prometheus.CounterVec // labels: outcome

	// Login + MFA latency histograms. Distinct from the generic HTTP
	// duration so operators can graph login-specific latency
	// (authenticator round-trips, password verification, risk scorer
	// time) without conflating it with /token / /userinfo / /metrics
	// noise. Labels: provider (login only) / outcome (login + mfa).
	LoginDuration         *prometheus.HistogramVec // labels: provider, outcome
	MFACompletionDuration *prometheus.HistogramVec // labels: outcome

	// Anomaly detection (zero traffic when no AnomalyRunner wired).
	// AnomaliesDetectedTotal counts each Anomaly surfaced by a
	// detector, labeled by type + severity. AnomalyDispatchDropsTotal
	// counts events dropped by the bounded-queue dispatcher (load-
	// shedding metric — non-zero = login traffic outpaces detector
	// capacity). AnomalyInspectErrorsTotal counts per-detector
	// failures (DB timeout, store unreachable) — surfaces the
	// "anomaly detection silently broken" failure mode.
	AnomaliesDetectedTotal    *prometheus.CounterVec // labels: anomaly_type, severity
	AnomalyDispatchDropsTotal *prometheus.CounterVec // labels: reason
	AnomalyInspectErrorsTotal *prometheus.CounterVec // labels: detector
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

		MFAChallengesTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameMFAChallengesTotal,
				Help: "MFA challenges issued at /auth/login when RiskScorer returns DecisionRequireMFA. Labeled by mfa_method (the FIRST method in the supported set, since the user picks one downstream). Zero traffic when MFA orchestration isn't wired.",
			},
			[]string{LabelMFAMethod},
		),

		MFACompletionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameMFACompletionsTotal,
				Help: "MFA verification outcomes at /auth/mfa, by mfa_method (totp/webauthn/push/...) and outcome (success/failure). Operators alert on a rising failure rate.",
			},
			[]string{LabelMFAMethod, LabelOutcome},
		),

		RetentionPrunedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameRetentionPrunedTotal,
				Help: "Rows deleted by background retention loops, by subsystem (audit/snapshot/push_approvals). Sum is total prunes since start; rate is throughput. Zero traffic when no retention loop is configured.",
			},
			[]string{LabelSubsystem},
		),

		RetentionPruneErrorTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameRetentionPruneErrTotal,
				Help: "Retention prune calls that returned an error, by subsystem. Operators alert on a rising error rate relative to retention_pruned_total — sustained errors with no successes means retention is silently failing.",
			},
			[]string{LabelSubsystem},
		),

		WebAuthnRegistrationsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameWebAuthnRegistrationsTotal,
				Help: "WebAuthn registration ceremony completions at /webauthn/registration/finish, by outcome (success/failure). Begin observability comes from sso_http_requests_total on /webauthn/registration/begin.",
			},
			[]string{LabelOutcome},
		),

		WebAuthnAssertionsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameWebAuthnAssertionsTotal,
				Help: "WebAuthn login assertion completions at /webauthn/login/finish, by outcome (success/failure). Operators alert on a rising failure rate as a credential-stuffing signal.",
			},
			[]string{LabelOutcome},
		),

		LoginDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    NameLoginDuration,
				Help:    "End-to-end /auth/login latency by authenticator provider + outcome (success/failure). Distinct from sso_http_request_duration_seconds so operators can detect a slow authenticator (TOTPStore lookup, OIDC federation roundtrip) without conflating it with /token + /userinfo latency.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{LabelProvider, LabelOutcome},
		),

		MFACompletionDuration: factory.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    NameMFACompletionDuration,
				Help:    "End-to-end /auth/mfa latency by outcome (success/failure). The Push factor's polling loop dominates this — operators alerting on push-flow stalls graph p95 of {mfa_method=push}.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{LabelOutcome},
		),

		AnomaliesDetectedTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameAnomaliesDetectedTotal,
				Help: "Anomalies surfaced by behavioral detectors (off the request hot path). Labels: anomaly_type (impossible_travel/velocity_burst/new_device/new_country/brute_force_shadow), severity (info/warn/critical). Operators alerting on credential stuffing graph rate(critical) per 5min.",
			},
			[]string{LabelAnomalyType, LabelSeverity},
		),

		AnomalyDispatchDropsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameAnomalyDispatchDropsTotal,
				Help: "Login events dropped by the AsyncAnomalyRunner bounded queue. Non-zero = login traffic outpaces detector capacity; raise queue size or worker count, or accept reduced anomaly coverage during bursts. reason ∈ {queue_full, ctx_canceled}.",
			},
			[]string{LabelDropReason},
		),

		AnomalyInspectErrorsTotal: factory.NewCounterVec(
			prometheus.CounterOpts{
				Name: NameAnomalyInspectErrorsTotal,
				Help: "Detector.Inspect calls that returned an error (DB timeout, store unreachable). Surfaces the silently-broken-detector failure mode — operators alert on any non-zero rate per detector.",
			},
			[]string{LabelDetector},
		),
	}
}
