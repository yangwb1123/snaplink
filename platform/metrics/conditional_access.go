package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// registerConditionalAccessMetrics registers the zero-trust conditional-access
// (CAP) decision counter. Split into its own file so metrics_ctor.go stays
// within the per-file line budget; the vector is nil-safe at the observe site
// (ObserveConditionalAccessDecision), so a build without WithConditionalAccess
// emits nothing.
func registerConditionalAccessMetrics(factory promauto.Factory, m *Metrics) {
	m.ConditionalAccessDecisionsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameConditionalAccessDecisionsTotal,
			Help: "Zero-trust conditional-access decisions, by resolved action (allow/deny/require_step_up). Zero traffic when WithConditionalAccess isn't wired.",
		},
		[]string{LabelAction},
	)

	m.SessionTrustStepUpTotal = factory.NewCounter(
		prometheus.CounterOpts{
			Name: NameSessionTrustStepUpTotal,
			Help: "Live sessions the zero-trust continuous-verification agent marked for step-up because their decayed trust score fell below the configured floor. No labels (bounded). Zero traffic when WithSessionTrustDecay isn't wired.",
		},
	)

	m.AuthHookExecutionDuration = factory.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    NameAuthHookExecutionDuration,
			Help:    "Authentication lifecycle hook duration by registered hook and outcome.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"phase", "hook", "outcome"},
	)
	m.NotificationDeliveryFailed = factory.NewCounterVec(
		prometheus.CounterOpts{Name: NameNotificationDeliveryFailed, Help: "Failed or dropped user-notification deliveries by bounded channel."},
		[]string{"channel"},
	)
}

// registerRateLimitMetrics registers the per-tenant rate-limit-hits counter.
// Split into its own file (like registerConditionalAccessMetrics above) so
// metrics_ctor.go stays within its per-file line budget.
func registerRateLimitMetrics(factory promauto.Factory, m *Metrics) {
	m.RateLimitHitsTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameRateLimitHitsTotal,
			Help: "Requests rejected by the rate limiter (interfaces/ratelimit), by resolved tenant. tenant is TenantLabelUnknown when no TenantKeyFunc is wired (single-tenant deployments). Zero traffic when WithRateLimit isn't wired.",
		},
		[]string{LabelTenant},
	)
}

// ObserveRateLimitHit bumps the rate-limit-hits counter for the resolved
// tenant label (or TenantLabelUnknown). Nil-safe so the ratelimit middleware
// can call it unconditionally whether or not metrics are wired.
func (m *Metrics) ObserveRateLimitHit(tenant string) {
	if m == nil || m.RateLimitHitsTotal == nil {
		return
	}
	m.RateLimitHitsTotal.WithLabelValues(tenant).Inc()
}
