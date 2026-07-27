package anomaly

import (
	"time"

	"github.com/yangwb1123/snaplink/domains/threataction"
	"github.com/yangwb1123/snaplink/shared/spi"
)

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

// WithInspectTimeout bounds the per-event detector sweep. Default 5s
// (generous for a SQLite read). A non-positive value is ignored, so
// the SDK default stands. Tighten for fleets with strict latency SLAs
// on their detector backends, loosen for slow stores.
func WithInspectTimeout(d time.Duration) Option {
	return func(r *Runner) {
		if d > 0 {
			r.inspectTimeout = d
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

// WithThreatExecutor sets the optional threat executor that translates
// anomaly signals into security actions (session suspension, token family
// revocation, MFA step-up). Off-path, fail-open — a nil executor (default)
// is byte-identical to the current behavior.
func WithThreatExecutor(exec threataction.ThreatExecutor) Option {
	return func(r *Runner) {
		r.threatExec = exec
	}
}

// WithLogger overrides the runner's logger. Used internally
// by cmd to share the cmd-level slog; embedders typically don't
// touch this.
func WithLogger(l spi.Logger) Option {
	return func(r *Runner) {
		if l != nil {
			r.logger = l
		}
	}
}

// WithMetricsCallbacks wires the anomaly metric emitters. cmd builds
// these from its *metrics.Metrics; tests inject inline closures to
// assert metric activity without dragging the prometheus dep into the
// SPI layer. Any callback may be nil — only set ones fire.
//
// dispatched fires once per event actually offered to the queue (the
// offered-load denominator) — pair it with dropped to derive a drop
// RATE (drops / offered) rather than only an absolute drop count.
func WithMetricsCallbacks(
	detected func(anomalyType, severity string),
	dropped func(reason string),
	inspectError func(detector string),
	dispatched func(),
) Option {
	return func(r *Runner) {
		r.metrics = &metricsCallbacks{
			detected:     detected,
			dropped:      dropped,
			inspectError: inspectError,
			dispatched:   dispatched,
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
		detectors:      detectors,
		sink:           sink,
		queueSize:      1024,
		workers:        4,
		inspectTimeout: 5 * time.Second,
		dropPolicy:     DropNewest,
		logger:         spi.NopLogger{},
	}
	for _, opt := range opts {
		opt(r)
	}
	r.queue = make(chan *LoginEvent, r.queueSize)
	return r
}
