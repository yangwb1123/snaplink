package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// registerConfigAuditMetrics is split into its own file (rather than
// growing metrics_ctor.go, which is at its file-size budget) — see
// AGENTS.md §0.1 "appending to 490+ line file" prohibition.
func registerConfigAuditMetrics(factory promauto.Factory, m *Metrics) {
	m.ConfigDriftDetectedTotal = factory.NewCounter(
		prometheus.CounterOpts{
			Name: NameConfigDriftDetectedTotal,
			Help: "Cross-replica configuration-drift detections (this replica's running-config digest disagreed with a peer's). Report-only — never blocks a request.",
		},
	)
}
