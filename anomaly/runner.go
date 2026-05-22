// Package anomaly implements the async behavioral anomaly detection
// subsystem — detector SPI + async dispatcher + login event/signal
// types + per-subject login history + per-IP failure counter SPIs.
//
// The synchronous [github.com/snaplink/sso.RiskScorer] makes
// millisecond-budget allow/deny/require-MFA decisions on the request
// path. This package handles signals that require WINDOWED state
// (impossible travel, velocity, new device, brute-force shadow) and
// runs them OFF the hot path — detectors see every login event
// (success + failure) after the response is built, surface anomalies
// via audit + metrics + webhook, and NEVER block login.
//
// Reference detectors ship in `github.com/snaplink/sso/defaultimpl/anomaly`.
package anomaly

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/geo"
)

// Logger is the minimal logging interface the runner uses. Mirrors
// sso.Logger so consumers can pass the same logger they use for the
// SSO server. Defined locally to avoid the anomaly→sso circular
// import (sso imports anomaly for the WithAnomalyRunner option).
type Logger interface {
	Info(msg string, keysAndValues ...any)
	Error(msg string, keysAndValues ...any)
	Debug(msg string, keysAndValues ...any)
}

// NopLogger discards all log output.
type NopLogger struct{}

// Info implements Logger.
func (NopLogger) Info(string, ...any) {}

// Error implements Logger.
func (NopLogger) Error(string, ...any) {}

// Debug implements Logger.
func (NopLogger) Debug(string, ...any) {}

// Detector runs OFF the request hot path on every login event
// (success or failure) and surfaces behavioral anomalies the
// synchronous [RiskScorer] can't detect: impossible travel, velocity
// surges, new device / country, brute-force horizontal sprays.
//
// Why a separate SPI from RiskScorer:
//
//   - RiskScorer is synchronous — it MUST return in milliseconds so
//     the login path doesn't stall. That budget rules out anything
//     needing windowed aggregation or per-subject baseline lookups
//     beyond a single fast key.
//   - Signal detection is inherently AFTER-THE-FACT: by the time
//     "impossible travel" is detectable, the suspicious login has
//     already returned a token. Forcing this signal into the request
//     path either causes false-positive denials (VPN users, mobile
//     IP roaming) or starves real signals (operators set thresholds
//     conservative to avoid blocking legitimate users → real attacks
//     slip through).
//   - Operators want anomalies → audit + webhook + user email, NOT
//     direct login denials. The differentiator vs synchronous risk
//     is "tell me what's unusual, let me decide policy" rather than
//     "block on every guess."
//
// Implementations get one Inspect call per LoginEvent and return zero
// or more [Signal]s. The runner emits each as an audit event +
// metric + optional webhook. Errors are logged but never propagate
// back to the login response.
//
// Detectors are stateful — they typically consult a
// [RecentLoginStore] / [KnownDeviceStore] / similar history backend.
// Implementations are responsible for their own state queries inside
// Inspect; the runner provides only ctx + the event.
type Detector interface {
	// Name is the detector identifier used in audit events + metric
	// labels (e.g. "impossible_travel", "velocity"). Stable wire
	// string.
	Name() string

	// Inspect examines the event and returns any anomalies it
	// detected. nil + no error = nothing to report. Error is
	// logged at warn level and metric'd — the runner does NOT
	// re-queue; transient backend issues (DB timeout) are accepted
	// rather than backpressured into the login path.
	Inspect(ctx context.Context, event *LoginEvent) ([]Signal, error)
}

// LoginEvent is the dispatched signal — captures everything detectors
// need without forcing them back through the audit/recorder path.
// Built at /auth/login terminus + handed to the Runner
// via a bounded queue.
type LoginEvent struct {
	// SubjectID is the user resolved by the authenticator on success,
	// or the attempted identifier (username / phone / email) on
	// failure. Detectors comparing across success+failure use this
	// as the join key; missing → detectors should skip the subject-
	// scoped checks.
	SubjectID string

	// ClientID is the registered Client.ID.
	ClientID string

	// Provider is the authenticator name ("password" / "phone" /
	// "webauthn" / "totp" / etc).
	Provider string

	// Outcome is "success" or "failure". Same vocabulary as
	// sso_login_attempts_total{outcome}.
	Outcome string

	// FailureReason is non-empty only on failure; mirrors the audit
	// Event.Reason field. Detectors classifying failure types
	// (brute-force vs credential typo) branch on this.
	FailureReason string

	// RemoteIP is the apparent client IP, extracted with the same
	// X-Forwarded-For-aware logic the audit pipeline uses.
	RemoteIP string

	// UserAgent is the raw User-Agent header. Empty when absent.
	// Detectors hashing for device fingerprint should hash on demand
	// (avoid persisting raw UA — PII-adjacent).
	UserAgent string

	// Geo is populated when [WithGeoProvider] is wired and geo
	// enrichment ran. May be nil — detectors degrade gracefully.
	Geo *geo.GeoInfo

	// TraceID joins the anomaly back to the originating request in
	// distributed traces (same TraceID the audit event carries).
	TraceID string

	// Timestamp is the request time, captured by the server (NOT
	// client-controlled).
	Timestamp time.Time
}

// Signal is one detector's signal that something looks unusual.
// Multiple Anomalies per LoginEvent are allowed (a single login can
// trip impossible-travel + new-country simultaneously).
type Signal struct {
	// Type is a stable wire string identifying the anomaly class
	// (e.g. "impossible_travel", "velocity_burst", "new_country").
	// Used as a metric label — keep cardinality bounded.
	Type string

	// Severity ∈ {"info", "warn", "critical"}. Drives downstream
	// routing (info → audit only; warn → audit + webhook;
	// critical → audit + webhook + user notification).
	Severity Severity

	// Score 0..100, higher = more anomalous. Detectors with a
	// natural confidence interval populate this; binary detectors
	// (new device yes/no) leave it 0.
	Score int

	// Evidence is the detector's structured rationale. Logged on
	// the audit event as metadata so operators can investigate
	// without rerunning the detection. Keep keys to a stable schema
	// per detector (e.g. impossible_travel always sets "distance_km"
	// + "elapsed_seconds" + "implied_speed_kmh").
	Evidence map[string]string

	// SubjectID is the user the anomaly applies to. Populated even
	// when LoginEvent.SubjectID was empty if the detector resolved
	// it (e.g. brute-force shadow that recognizes the attacker as
	// "scanning user X").
	SubjectID string
}

// Severity ∈ {info, warn, critical}. Wire string.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarn     Severity = "warn"
	SeverityCritical Severity = "critical"
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
	closed    atomicBool

	// Metrics + logger left as fields for testability; cmd wires
	// real values, tests inject stubs.
	metrics *metricsCallbacks
	logger  Logger

	// dropPolicy controls what happens when the queue is full.
	// "drop_newest" returns immediately (default; load-shedding);
	// "block" applies backpressure (use only when the login path
	// can tolerate it — typically never).
	dropPolicy DropPolicy
}

// DropPolicy controls behavior when the worker queue is full.
type DropPolicy string

const (
	// DropNewest drops the incoming event + bumps the drop
	// counter. Default. Right choice for "anomaly detection is
	// best-effort, never block the login path."
	DropNewest DropPolicy = "drop_newest"

	// DropBlock backpressures Dispatch until queue space
	// frees. Use only when you've measured the login path can
	// tolerate it.
	DropBlock DropPolicy = "block"
)

// Option tunes the runner at construction.
type Option func(*Runner)

// WithQueueSize sets the bounded queue depth. Default 1024.
// Lower = sheds load sooner; higher = absorbs bursts at the cost
// of memory.
func WithQueueSize(n int) Option {
	return func(r *Runner) {
		if n > 0 {
			r.queueSize = n
		}
	}
}

// WithWorkers sets the worker goroutine count. Default 4.
// More workers = lower per-event latency at the cost of detector
// store concurrency; usually equal to the number of detectors.
func WithWorkers(n int) Option {
	return func(r *Runner) {
		if n > 0 {
			r.workers = n
		}
	}
}

// WithDropPolicy overrides drop-newest with block. Use with
// care — block backpressures into the login Dispatch call.
func WithDropPolicy(p DropPolicy) Option {
	return func(r *Runner) {
		if p != "" {
			r.dropPolicy = p
		}
	}
}

// WithLogger overrides the runner's logger. Used internally
// by cmd to share the cmd-level slog; embedders typically don't
// touch this.
func WithLogger(l Logger) Option {
	return func(r *Runner) {
		if l != nil {
			r.logger = l
		}
	}
}

// WithMetricsCallbacks wires the three anomaly metric
// emitters. cmd builds these from its *metrics.Metrics; tests
// inject inline closures to assert metric activity without
// dragging the prometheus dep into the SPI layer. Any callback
// may be nil — only set ones fire.
func WithMetricsCallbacks(
	detected func(anomalyType, severity string),
	dropped func(reason string),
	inspectError func(detector string),
) Option {
	return func(r *Runner) {
		r.metrics = &metricsCallbacks{
			detected:     detected,
			dropped:      dropped,
			inspectError: inspectError,
		}
	}
}

// NewRunner builds a runner around the given detectors
// + Sink. sink may be nil (drops every anomaly; useful for
// tests that observe detectors via direct Inspect calls instead).
// Returns nil when detectors is empty — the SSO server falls back
// to the no-op dispatch path.
func NewRunner(detectors []Detector, sink Sink, opts ...Option) *Runner {
	if len(detectors) == 0 {
		return nil
	}
	r := &Runner{
		detectors:  detectors,
		sink:       sink,
		queueSize:  1024,
		workers:    4,
		dropPolicy: DropNewest,
		logger:     NopLogger{},
	}
	for _, opt := range opts {
		opt(r)
	}
	r.queue = make(chan *LoginEvent, r.queueSize)
	return r
}

// Sink is what the runner does with each [Signal] surfaced
// by a detector. Implementations typically write an audit event +
// optionally fan out to a webhook / SIEM / SMTP notifier. The SSO
// server ships [NewRecorderSink] which writes an
// [audit.EventAnomalyDetected] event with the standard metadata
// shape — most embedders use that.
type Sink interface {
	Record(ctx context.Context, event *LoginEvent, anomaly Signal) error
}

// SinkFunc is a function adapter for Sink.
type SinkFunc func(ctx context.Context, event *LoginEvent, anomaly Signal) error

// Record implements Sink.
func (f SinkFunc) Record(ctx context.Context, event *LoginEvent, anomaly Signal) error {
	return f(ctx, event, anomaly)
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
	if r == nil || r.closed.load() || event == nil {
		return
	}
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
	if !r.closed.compareAndSwap(false, true) {
		return nil
	}
	close(r.queue)
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
		r.inspect(event)
	}
}

// inspect runs every detector against one event. Per-detector
// failures are logged + metric'd but don't tear down siblings —
// one broken detector shouldn't blind the others.
func (r *Runner) inspect(event *LoginEvent) {
	// Bounded per-detector context — detectors querying a slow
	// backend shouldn't pile up. 5s is generous for a SQLite read;
	// operator can tighten via per-detector wrapper if needed.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
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
			if r.sink != nil {
				if sinkErr := r.sink.Record(ctx, event, a); sinkErr != nil {
					r.logger.Error("anomaly sink record failed",
						"type", a.Type, "error", sinkErr)
				}
			}
			r.recordDetected(a.Type, string(a.Severity))
		}
	}
}

// metricsCallbacks is the metric handle stub — populated when cmd
// wires metrics.Metrics via WithAnomalyMetrics. Nil-safe; detectors
// run regardless.
type metricsCallbacks struct {
	dispatched   func()
	dropped      func(reason string)
	detected     func(anomalyType, severity string)
	inspectError func(detector string)
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

// NewRecorderSink is the standard [Sink] that writes
// each anomaly as an [audit.EventAnomalyDetected] event into the
// supplied recorder. The audit event carries:
//
//   - Type:      audit.EventAnomalyDetected
//   - Outcome:   audit.OutcomeFailure (anomaly = something to look at)
//   - ActorID:   anomaly.SubjectID (falls back to event.SubjectID)
//   - ClientID:  event.ClientID
//   - Provider:  event.Provider
//   - Reason:    anomaly.Type ("impossible_travel", etc)
//   - Metadata:  anomaly.Evidence keys PLUS "anomaly.severity",
//     "anomaly.score" derived from the Signal struct.
//
// Use this when you want anomalies in the standard audit query
// surface (recommended). For SIEM-only routing, implement
// Sink directly without touching the recorder.
func NewRecorderSink(recorder *audit.Recorder) Sink {
	if recorder == nil {
		return nil
	}
	return SinkFunc(func(ctx context.Context, event *LoginEvent, a Signal) error {
		actor := a.SubjectID
		if actor == "" {
			actor = event.SubjectID
		}
		e := &audit.Event{
			Type:     audit.EventAnomalyDetected,
			Outcome:  audit.OutcomeFailure,
			ActorID:  actor,
			ActorIP:  event.RemoteIP,
			ClientID: event.ClientID,
			Provider: event.Provider,
			Reason:   a.Type,
			TraceID:  event.TraceID,
		}
		setAnomalyMeta(e, "anomaly.severity", string(a.Severity))
		if a.Score > 0 {
			setAnomalyMeta(e, "anomaly.score", strconv.Itoa(a.Score))
		}
		for k, v := range a.Evidence {
			setAnomalyMeta(e, k, v)
		}
		recorder.Record(ctx, e)
		return nil
	})
}

// setAnomalyMeta is the same setMeta pattern from audit_handler.go,
// duplicated here to avoid widening the package's exported surface
// just for the anomaly path. Skips empty values + lazily allocates.
func setAnomalyMeta(e *audit.Event, k, v string) {
	if v == "" {
		return
	}
	if e.Metadata == nil {
		e.Metadata = make(map[string]string, 4)
	}
	e.Metadata[k] = v
}

// atomicBool is a tiny inline wrapper over sync/atomic.Bool — kept
// local to avoid bumping the Go version requirement if/when this
// file's import set shifts.
type atomicBool struct {
	mu sync.Mutex
	v  bool
}

func (a *atomicBool) load() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.v
}

func (a *atomicBool) compareAndSwap(old, new bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.v != old {
		return false
	}
	a.v = new
	return true
}
