package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// registerConnectionHealthMetrics wires the B2B enterprise-connection probe
// counter. Split into its own file (mirroring audit_async.go) rather than
// added to metrics_ctor.go, which is already near the file-size budget.
func registerConnectionHealthMetrics(factory promauto.Factory, m *Metrics) {
	m.ConnectionHealthProbesTotal = factory.NewCounterVec(
		prometheus.CounterOpts{
			Name: NameConnectionHealthProbesTotal,
			Help: "Admin-triggered B2B enterprise-connection reachability probes, by type (oidc/saml) and outcome (healthy/degraded/unreachable). A rising unreachable rate means an org's upstream IdP has gone dark. Zero traffic until an admin runs a probe.",
		},
		[]string{LabelConnectionType, LabelOutcome},
	)
}
