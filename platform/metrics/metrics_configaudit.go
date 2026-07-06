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

// registerConnectionHealthMetrics wires the B2B enterprise-connection probe
// counter. Folded into this file (rather than metrics_ctor.go, which is at
// its file-size budget) — relocated from its own connection_health.go to
// stay within platform/metrics' file-count budget.
func registerConnectionHealthMetrics(factory promauto.Factory, m *Metrics) {
	m.ConnectionHealthProbesTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameConnectionHealthProbesTotal,
			Help: "Admin-triggered B2B enterprise-connection reachability probes, by type (oidc/saml) and outcome (healthy/degraded/unreachable). A rising unreachable rate means an org's upstream IdP has gone dark. Zero traffic until an admin runs a probe.",
		},
		[]string{LabelConnectionType, LabelOutcome},
	)
}
