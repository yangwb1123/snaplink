package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/snaplink/sso/audit"
)

// Audit-async metric names. Mirror the public counter / gauge methods
// on audit.AsyncSink so the Prometheus surface == the Go API.
const (
	NameAuditAsyncDropsQueueFull  = "sso_audit_async_drops_queue_full_total"
	NameAuditAsyncDropsClosed     = "sso_audit_async_drops_closed_total"
	NameAuditAsyncDropsInnerError = "sso_audit_async_drops_inner_error_total"
	NameAuditAsyncQueueDepth      = "sso_audit_async_queue_depth"
	NameAuditAsyncQueueCapacity   = "sso_audit_async_queue_capacity"
)

// AsyncSinkCollector exposes an audit.AsyncSink's drop counters and
// queue gauges as Prometheus metrics. Reads happen at scrape time
// against the sink's atomic counters — no polling goroutine, no
// race, and no work when nothing scrapes /metrics.
//
// Register exactly one collector per AsyncSink. Re-registering on
// the same Registerer panics (prometheus convention); construct
// once at cmd-level boot.
type AsyncSinkCollector struct {
	sink          *audit.AsyncSink
	dropsFull     *prometheus.Desc
	dropsClosed   *prometheus.Desc
	dropsInner    *prometheus.Desc
	queueDepth    *prometheus.Desc
	queueCapacity *prometheus.Desc
}

// NewAsyncSinkCollector wires a collector for sink. Pass the
// collector to prometheus.Register / MustRegister to expose its
// metrics on the registry.
func NewAsyncSinkCollector(sink *audit.AsyncSink) *AsyncSinkCollector {
	return &AsyncSinkCollector{
		sink: sink,
		dropsFull: prometheus.NewDesc(
			NameAuditAsyncDropsQueueFull,
			"Audit events dropped because the async buffer was full at Record time. A growing counter means the inner sink can't keep up — increase buffer, workers, or look upstream for an event-storm.",
			nil, nil,
		),
		dropsClosed: prometheus.NewDesc(
			NameAuditAsyncDropsClosed,
			"Audit events dropped because Record was called after Close. Persistent non-zero values typically mean an SDK caller is missing a shutdown-ordering hook.",
			nil, nil,
		),
		dropsInner: prometheus.NewDesc(
			NameAuditAsyncDropsInnerError,
			"Audit events the worker successfully dequeued but the inner sink rejected (network error, HTTP 4xx, validation failure). Inspect via the AsyncDropHandler for the raw error.",
			nil, nil,
		),
		queueDepth: prometheus.NewDesc(
			NameAuditAsyncQueueDepth,
			"Current number of audit events waiting in the async buffer. Alarmed at >80%% of capacity is a useful saturation signal.",
			nil, nil,
		),
		queueCapacity: prometheus.NewDesc(
			NameAuditAsyncQueueCapacity,
			"Configured buffer capacity of the audit async sink.",
			nil, nil,
		),
	}
}

// Describe implements prometheus.Collector.
func (c *AsyncSinkCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.dropsFull
	ch <- c.dropsClosed
	ch <- c.dropsInner
	ch <- c.queueDepth
	ch <- c.queueCapacity
}

// Collect implements prometheus.Collector. Reads happen at scrape
// time — no caching, no polling.
func (c *AsyncSinkCollector) Collect(ch chan<- prometheus.Metric) {
	if c.sink == nil {
		return
	}
	ch <- prometheus.MustNewConstMetric(c.dropsFull, prometheus.CounterValue, float64(c.sink.DropsQueueFull()))
	ch <- prometheus.MustNewConstMetric(c.dropsClosed, prometheus.CounterValue, float64(c.sink.DropsClosed()))
	ch <- prometheus.MustNewConstMetric(c.dropsInner, prometheus.CounterValue, float64(c.sink.DropsInnerError()))
	ch <- prometheus.MustNewConstMetric(c.queueDepth, prometheus.GaugeValue, float64(c.sink.Pending()))
	ch <- prometheus.MustNewConstMetric(c.queueCapacity, prometheus.GaugeValue, float64(c.sink.Capacity()))
}
