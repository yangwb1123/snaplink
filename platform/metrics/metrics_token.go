package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// EnableTokenUsageMetrics lazily constructs + registers the token-usage
// telemetry collectors on this Metrics' Registry. Called by the Server
// ONLY when a TokenUsageRecorder is wired — without that option the
// vectors stay nil and nothing is registered or emitted (zero series,
// byte-identical off, §5). Mirrors EnableTenantMetrics.
//
// Idempotent: a second call is a no-op (the vectors are already built).
func (m *Metrics) EnableTokenUsageMetrics() {
	if m == nil || m.TokenUsageEventsTotal != nil {
		return
	}
	factory := promauto.With(m.Registry)
	m.TokenUsageEventsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameTokenUsageEventsTotal,
			Help: "Token-usage telemetry events successfully aggregated into the usage store, by token kind (access/refresh/id) and observing endpoint (token/introspect/userinfo). Bounded labels only — per-client breakdowns come from the /api/v1/admin/tokens/usage read API, not from label cardinality. Zero traffic when no TokenUsageRecorder is wired.",
		},
		[]string{LabelKind, LabelEndpoint},
	)
	m.TokenUsageDroppedTotal = factory.NewCounter(
		prometheus.CounterOpts{
			Name: NameTokenUsageDroppedTotal,
			Help: "Token-usage telemetry events dropped by the recorder's bounded queue (load-shedding, fail-open — the hot path never blocks on telemetry). Non-zero means issuance/introspection traffic outpaces the drain; raise the queue size or accept reduced usage coverage during bursts.",
		},
	)
	m.TokenUsageTrackedBuckets = factory.NewGauge(
		prometheus.GaugeOpts{
			Name: NameTokenUsageTrackedBuckets,
			Help: "Per-minute usage buckets currently tracked by the token-usage store. A bounded store evicts its oldest bucket at the cap, so a gauge pinned at the cap means the usage window is silently shrinking — raise the cap or shorten the query window. Never set when the store does not report cardinality.",
		},
	)
}

// ObserveTokenUsageEvent bumps the aggregated-events counter. Nil-safe
// so the recorder hooks can fire unconditionally; no-op until
// EnableTokenUsageMetrics ran.
func (m *Metrics) ObserveTokenUsageEvent(kind, endpoint string) {
	if m == nil || m.TokenUsageEventsTotal == nil {
		return
	}
	m.TokenUsageEventsTotal.WithLabelValues(kind, endpoint).Inc()
}

// ObserveTokenUsageDropped bumps the queue-shed counter. Nil-safe.
func (m *Metrics) ObserveTokenUsageDropped() {
	if m == nil || m.TokenUsageDroppedTotal == nil {
		return
	}
	m.TokenUsageDroppedTotal.Inc()
}

// SetTokenUsageTrackedBuckets sets the tracked-bucket gauge. Nil-safe.
func (m *Metrics) SetTokenUsageTrackedBuckets(n int) {
	if m == nil || m.TokenUsageTrackedBuckets == nil {
		return
	}
	m.TokenUsageTrackedBuckets.Set(float64(n))
}

// EnableTokenPolicyMetrics lazily constructs + registers the token-policy
// engine collectors. Called by the Server ONLY when a token-policy store is
// wired (WithTokenPolicy) — without it the vectors stay nil and nothing is
// registered or emitted (byte-identical off, §5). Folded here beside the
// token-usage metrics rather than a new file to hold platform/metrics under
// its directory-fanout budget. Idempotent.
func (m *Metrics) EnableTokenPolicyMetrics() {
	if m == nil || m.TokenPolicyEvaluationsTotal != nil {
		return
	}
	factory := promauto.With(m.Registry)
	m.TokenPolicyEvaluationsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameTokenPolicyEvaluationsTotal,
			Help: "Token-policy gate evaluations on the issuance path, by decision (allow/deny). Bounded labels only — the per-reason denial breakdown is on sso_token_policy_denials_total, never on client/scope cardinality. Zero traffic when no WithTokenPolicy store is wired.",
		},
		[]string{LabelDecision},
	)
	m.TokenPolicyDenialsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameTokenPolicyDenialsTotal,
			Help: "Token-policy denials by reason (scope_combo_blocked / refresh_depth_exceeded / active_sessions_exceeded — the closed tokenpolicy.DenyReason set). A rising count means a governance rule is actively blocking issuance; the paired wire error stays a generic invalid_scope/invalid_grant (oracle-safe). Zero traffic when no policy store is wired.",
		},
		[]string{LabelReason},
	)
}

// ObserveTokenPolicyEvaluation bumps the evaluation counter for a decision
// (PolicyDecisionAllow / PolicyDecisionDeny). Nil-safe.
func (m *Metrics) ObserveTokenPolicyEvaluation(decision string) {
	if m == nil || m.TokenPolicyEvaluationsTotal == nil {
		return
	}
	m.TokenPolicyEvaluationsTotal.WithLabelValues(decision).Inc()
}

// ObserveTokenPolicyDenial bumps the denial counter for a bounded reason.
// Nil-safe.
func (m *Metrics) ObserveTokenPolicyDenial(reason string) {
	if m == nil || m.TokenPolicyDenialsTotal == nil {
		return
	}
	m.TokenPolicyDenialsTotal.WithLabelValues(reason).Inc()
}
