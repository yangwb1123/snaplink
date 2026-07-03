// Package dr provides the disaster-recovery framework foundations
// (docs/dr-framework.md): measured-RTO tracking, snapshot replication to a
// DR replica mount with post-copy checksum verification and bounded
// retention, and an RPO-target readiness aggregate.
//
// Everything here is REPORT-ONLY by design: a stale or missing DR replica
// never blocks auth traffic. The one exception is operator-explicit — cmd
// wires the readiness verdict into /readyz only when dr.gate_readiness is
// set; the default surface is the admin status endpoint + the Prometheus
// gauges below.
package dr

// Prometheus metric names. Prefixed sso_ like every other metric this
// server emits (bounded cardinality, no labels — DR health is a single
// per-replica condition).
const (
	// MetricReplicationLagSeconds is the age of the last successfully
	// replicated + checksum-verified snapshot. Absent until the first
	// successful replication cycle.
	MetricReplicationLagSeconds = "sso_dr_snapshot_replication_lag_seconds"

	// MetricLastRecoverySeconds is the duration of the most recent
	// measured recovery operation (the measured RTO). Absent until a
	// recovery has been timed through the RecoveryTimeTracker.
	MetricLastRecoverySeconds = "sso_dr_last_recovery_seconds"

	// MetricReadiness is 1 while the DR readiness verdict holds (a
	// verified replica exists and its age is within the RPO target), 0
	// otherwise.
	MetricReadiness = "sso_dr_readiness"

	// MetricLastDrillSuccess is 1 when the most recent orchestrated recovery
	// (RecoveryOrchestrator.Run) succeeded end-to-end, 0 when it aborted at a
	// step. Absent until the first recovery/drill has run through an
	// orchestrator wired to the readiness aggregate — a bare replication
	// deployment (no orchestrator) never emits it, keeping the metric surface
	// byte-identical to before.
	MetricLastDrillSuccess = "sso_dr_last_drill_success"
)
