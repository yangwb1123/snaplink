// Package anomaly implements the async behavioral anomaly detection
// subsystem — detector SPI + async dispatcher + login event/signal
// types + per-subject login history + per-IP failure counter SPIs.
//
// The synchronous [github.com/yangwb1123/snaplink/shared/spi.RiskScorer] makes
// millisecond-budget allow/deny/require-MFA decisions on the request
// path. This package handles signals that require WINDOWED state
// (impossible travel, velocity, new device, brute-force shadow) and
// runs them OFF the hot path — detectors see every login event
// (success + failure) after the response is built, surface anomalies
// via audit + metrics + webhook, and NEVER block login.
//
// Reference detectors ship in
// `github.com/yangwb1123/snaplink/infrastructure/defaultimpl/detectors`.
//
// Detector ordering contract: detectors are processed in registration
// order. Exactly one write-owning detector — the impossible-travel
// detector — must be registered BEFORE any read-only history consumers
// (velocity, new-baseline): impossible-travel owns the history writes
// that the read-only consumers depend on. Omitting the write-owner
// silently disables the read-only consumers (they see no history); this
// is a documented composition constraint, not a runtime error, and
// matches the fail-open/async philosophy of the subsystem.
package anomaly

import (
	"context"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// Runner is the worker pool that fans LoginEvents out
// to every registered detector. Mirrors the [audit.AsyncSink]
// shape — bounded queue, worker pool, drop-on-overflow with metric.
// The login path's Dispatch call is non-blocking under normal load
// + bounded under saturation.
//
// Lifecycle:
//
//	r := NewRunner(detectors, sink)
//	r.Start()                       // launches workers
//	srv := sso.NewServer(sso.WithAnomalyRunner(r), ...)
//	// ... server runs ...
//	r.Close(ctx)                    // drains queue, waits for workers
type Runner struct {
	detectors []Detector
	sink      Sink

	queueSize int
	workers   int
	queue     chan *LoginEvent
	wg        sync.WaitGroup
	started   atomicBool

	// mu guards closed against queue sends. Dispatch holds the RLock across
	// BOTH the closed-check AND the queue send; Close takes the write Lock
	// before close(queue). This makes "send on queue" mutually exclusive with
	// "close(queue)" — a standalone atomic closed-flag leaves a TOCTOU window
	// where Dispatch can send on an already-closed channel and panic. Mirrors
	// the coupling in audit.AsyncSink.
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once

	// inspectTimeout bounds each per-event detector sweep — a detector
	// querying a slow backend shouldn't pile up. Default 5s; tune via
	// WithInspectTimeout.
	inspectTimeout time.Duration

	// Metrics + logger left as fields for testability; cmd wires
	// real values, tests inject stubs.
	metrics *metricsCallbacks
	logger  spi.Logger

	// dropPolicy controls what happens when the queue is full.
	// "drop_newest" returns immediately (default; load-shedding);
	// "block" applies backpressure (use only when the login path
	// can tolerate it — typically never).
	dropPolicy DropPolicy

	// threatExec is the optional Active ITDR executor that translates
	// anomaly signals into security actions. Nil (default) = no-op,
	// byte-identical to current behavior.
	threatExec threataction.ThreatExecutor
}

// Start launches the worker pool. Safe to call exactly once;
// subsequent calls are silent no-ops.
func (r *Runner) Start() {
	if r == nil || !r.started.compareAndSwap(false, true) {
		return
	}
	for i := 0; i < r.workers; i++ {
		r.wg.Add(1)
		go r.work()
	}
}

// Dispatch hands the event to the worker pool. Non-blocking under
// the default drop_newest policy; bounded by ctx under block.
//
// Returns immediately on closed runner — login path must never
// block on a stopped detector subsystem.
func (r *Runner) Dispatch(ctx context.Context, event *LoginEvent) {
	if r == nil || event == nil {
		return
	}
	// Hold the read lock across BOTH the closed-check AND the queue send so a
	// concurrent Close (which takes the write lock before close(queue)) cannot
	// close the channel between the check and the send — that race would panic.
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return
	}
	// Count every event actually offered to the queue (the offered-load
	// denominator) BEFORE the drop decision — drops are a subset, so
	// dropped/dispatched is the drop rate. Nil/closed no-ops above are
	// excluded (they never reached the dispatcher).
	r.recordDispatched()
	switch r.dropPolicy {
	case DropBlock:
		select {
		case r.queue <- event:
		case <-ctx.Done():
			r.recordDrop("ctx_canceled")
		}
	default:
		select {
		case r.queue <- event:
		default:
			r.recordDrop("queue_full")
		}
	}
}

// Close drains in-flight events + waits for workers to exit. Caller
// ctx bounds the drain — when ctx expires before all events are
// processed, the remainder are dropped and the metric is bumped.
func (r *Runner) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	closedNow := false
	r.closeOnce.Do(func() {
		// Take the write lock before flipping closed + close(queue) so any
		// in-flight Dispatch (holding the read lock across its send) has fully
		// returned first — closing the queue under a send would panic.
		r.mu.Lock()
		r.closed = true
		close(r.queue)
		r.mu.Unlock()
		closedNow = true
	})
	if !closedNow {
		return nil
	}
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		r.logger.Error("anomaly runner Close timed out")
		return ctx.Err()
	}
}

func (r *Runner) work() {
	defer r.wg.Done()
	for event := range r.queue {
		r.inspectSafe(event)
	}
}

// inspectSafe wraps inspect in recover(). Detector/Sink/ThreatExecutor are all
// pluggable, operator-supplied implementations; a panic in one must drop only
// the current event, not escape work()'s range loop — an unrecovered panic
// here would both permanently shrink this worker's slot out of the pool (the
// range loop never resumes) and crash the whole process, defeating the "one
// broken detector shouldn't blind the others" fault-isolation this package
// promises. Mirrors the per-item recover in infrastructure/saml/idp/fanout.go
// and protocols/caep.Transmitter.deliver.
func (r *Runner) inspectSafe(event *LoginEvent) {
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Error("anomaly inspect panic recovered",
				"subject", event.SubjectID, "panic", rec)
		}
	}()
	r.inspect(event)
}

// inspect runs every detector against one event. Per-detector
// failures are logged + metric'd but don't tear down siblings —
// one broken detector shouldn't blind the others.
func (r *Runner) inspect(event *LoginEvent) {
	// Bounded per-detector context — detectors querying a slow
	// backend shouldn't pile up. Default 5s (generous for a SQLite
	// read); tune via WithInspectTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), r.inspectTimeout)
	defer cancel()
	for _, d := range r.detectors {
		anomalies, err := d.Inspect(ctx, event)
		if err != nil {
			r.logger.Error("anomaly detector failed",
				"detector", d.Name(), "subject", event.SubjectID, "error", err)
			r.recordInspectError(d.Name())
			continue
		}
		for _, a := range anomalies {
			// Tenant backfill: a detector that leaves the signal's
			// tenant empty inherits the event's (mirror of the
			// SubjectID fallback the sink performs).
			if a.TenantID == "" {
				a.TenantID = event.TenantID
			}
			if r.sink != nil {
				if sinkErr := r.sink.Record(ctx, event, a); sinkErr != nil {
					r.logger.Error("anomaly sink record failed",
						"type", a.Type, "error", sinkErr)
				}
			}
			r.recordDetected(a.Type, string(a.Severity))

			r.dispatchThreat(ctx, event, a)
		}
	}
}

// metricsCallbacks is the metric handle stub — populated when cmd
// wires metrics.Metrics via WithAnomalyMetrics. Nil-safe; detectors
// run regardless.
type metricsCallbacks struct {
	dispatched    func()
	dropped       func(reason string)
	detected      func(anomalyType, severity string)
	inspectError  func(detector string)
	threatRefused func(anomalyType, reason string)
}

func (r *Runner) recordDispatched() {
	if r.metrics != nil && r.metrics.dispatched != nil {
		r.metrics.dispatched()
	}
}

func (r *Runner) recordDrop(reason string) {
	r.logger.Error("anomaly event dropped", "reason", reason)
	if r.metrics != nil && r.metrics.dropped != nil {
		r.metrics.dropped(reason)
	}
}

func (r *Runner) recordDetected(anomalyType, severity string) {
	if r.metrics != nil && r.metrics.detected != nil {
		r.metrics.detected(anomalyType, severity)
	}
}

func (r *Runner) recordInspectError(detector string) {
	if r.metrics != nil && r.metrics.inspectError != nil {
		r.metrics.inspectError(detector)
	}
}

// dispatchThreat converts Signal → Threat and dispatches off-path.
// Fail-open: errors are logged but never propagate to the login response.
// Guard truth table (design, SEC-F3): execute ⟺ event.TenantID != ""
// ∧ a.TenantID == event.TenantID (post-backfill). A refused signal still
// reaches the sink — the guard gates the RESPONSE, never the report.
// Executors are subject-scoped with no tenant predicate of their own, so
// a label-integrity guard is the only tenant control this layer provides.
func (r *Runner) dispatchThreat(ctx context.Context, event *LoginEvent, a Signal) {
	if r.threatExec == nil {
		return
	}
	if event.TenantID == "" || a.TenantID != event.TenantID {
		reason := "tenant_mismatch"
		if event.TenantID == "" {
			reason = "empty_tenant"
		}
		r.logger.Error("anomaly threat execution refused",
			"reason", reason, "type", a.Type, "subject", a.SubjectID,
			"event_tenant", event.TenantID, "signal_tenant", a.TenantID)
		r.recordThreatRefused(a.Type, reason)
		return
	}
	threat := threataction.Threat{
		Type:      a.Type,
		Severity:  string(a.Severity),
		SubjectID: a.SubjectID,
		ClientID:  event.ClientID,
		TenantID:  a.TenantID,
		Evidence:  a.Evidence,
		TraceID:   event.TraceID,
	}
	if _, err := r.threatExec.Execute(ctx, threat, threataction.ThreatPolicy{}); err != nil {
		r.logger.Error("threat executor failed",
			"executor", r.threatExec.Name(),
			"type", a.Type, "subject", a.SubjectID, "error", err)
	}
}

func (r *Runner) recordThreatRefused(anomalyType, reason string) {
	if r.metrics != nil && r.metrics.threatRefused != nil {
		r.metrics.threatRefused(anomalyType, reason)
	}
}
