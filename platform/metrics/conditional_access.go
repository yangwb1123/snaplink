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
}
