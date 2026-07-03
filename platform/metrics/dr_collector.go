package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/snaplink/sso/platform/lifecycle/dr"
)

// DRCollector exposes a platform/dr.DRReadiness aggregate as Prometheus
// gauges. Reads happen at scrape time against the readiness aggregate's own
// (already-synchronized) state — no polling goroutine, mirroring
// AsyncSinkCollector's shape for platform/audit.
//
// Metric names live on the dr package (dr.MetricReplicationLagSeconds etc.)
// so the Go doc comment on each constant and the Prometheus surface never
// drift apart.
type DRCollector struct {
	readiness *dr.DRReadiness

	lag       *prometheus.Desc
	recovery  *prometheus.Desc
	readyDesc *prometheus.Desc
}

// NewDRCollector wires a collector for readiness. Register exactly once per
// readiness aggregate — re-registering on the same Registerer panics
// (prometheus convention).
func NewDRCollector(readiness *dr.DRReadiness) *DRCollector {
	return &DRCollector{
		readiness: readiness,
		lag: prometheus.NewDesc(
			dr.MetricReplicationLagSeconds,
			"Age in seconds of the last successfully replicated + checksum-verified DR snapshot. Absent until the first successful replication cycle. Compare against the operator's RPO target.",
			nil, nil,
		),
		recovery: prometheus.NewDesc(
			dr.MetricLastRecoverySeconds,
			"Duration in seconds of the most recent measured recovery operation (a RecoveryTimeTracker-timed restore/promotion/drill). Absent until a recovery has been timed.",
			nil, nil,
		),
		readyDesc: prometheus.NewDesc(
			dr.MetricReadiness,
			"DR readiness verdict: 1 while a verified replica exists within the RPO target, 0 otherwise. Report-only — this gauge never gates auth traffic; wiring it into /readyz is a separate operator opt-in (dr.gate_readiness).",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *DRCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.lag
	ch <- c.recovery
	ch <- c.readyDesc
}

// Collect implements prometheus.Collector. Reads happen at scrape time — no
// caching, no polling goroutine.
func (c *DRCollector) Collect(ch chan<- prometheus.Metric) {
	if c.readiness == nil {
		return
	}
	ready, lag, _ := c.readiness.Evaluate()
	readyVal := 0.0
	if ready {
		readyVal = 1
	}
	ch <- prometheus.MustNewConstMetric(c.readyDesc, prometheus.GaugeValue, readyVal)
	// Lag is only meaningful once a replication has actually succeeded —
	// emitting 0 before that would read as "perfectly fresh" instead of
	// "unknown", so the series stays absent (matches SigningBackendUp-style
	// gauges that only appear once the underlying subsystem has fired).
	if c.readiness.Replicator != nil {
		if _, ok := c.readiness.Replicator.LastSuccess(); ok {
			ch <- prometheus.MustNewConstMetric(c.lag, prometheus.GaugeValue, lag)
		}
	}
	if c.readiness.Tracker != nil {
		if secs, ok := c.readiness.Tracker.LastRecoverySeconds(); ok {
			ch <- prometheus.MustNewConstMetric(c.recovery, prometheus.GaugeValue, secs)
		}
	}
}
