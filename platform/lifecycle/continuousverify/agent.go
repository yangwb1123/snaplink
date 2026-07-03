// Package continuousverify implements the zero-trust ContinuousVerificationAgent
// (Direction 3 Phase 3): a background loop that periodically recomputes the
// time-decayed trust of live sessions and, when a session's score falls below a
// configured floor, marks it for step-up / refresh on its next request, emits an
// audit event, and bumps a metric.
//
// It is deliberately OFF the request hot path — a slow-cadence sweep of the
// session store, mirroring the wave-1 DR/rotation background loops (clean
// Start/Stop, context-cancelled ticker, an onEvent fan-out seam the composition
// root maps to audit). The decay math + the below-floor decision live in the
// pure, table-testable shared/trust package; this agent only drives them on a
// clock and writes back the advisory flag.
//
// FAIL-OPEN is the cardinal invariant (spec Edge Cases): a store-list error
// skips the sweep, a mark error is logged and swallowed, and a session with no
// bound trust signal is left untouched. The agent NEVER hard-denies — it only
// raises an advisory flag a downstream min-trust gate may act on.
package continuousverify

import (
	"context"
	"sync"
	"time"

	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
	"github.com/snaplink/sso/shared/trust"
)

// DefaultSweepInterval is the polling cadence when WithSweepInterval isn't set.
// The agent is advisory, so a coarse cadence (minute-scale) is intentional — it
// bounds how stale a below-floor session's step-up flag can be, NOT a real-time
// enforcement latency.
const DefaultSweepInterval = time.Minute

// SessionLister is the narrow read side the agent needs: enumerate the live
// session set. core.SessionManager satisfies it structurally (ListAll), so the
// agent never imports the concrete store.
type SessionLister interface {
	ListAll(ctx context.Context) ([]*core.Session, error)
}

// Event describes one below-floor marking for the operator fan-out seam
// (WithEventHook). The composition root maps it to an audit event; the agent
// itself stays decoupled from platform/audit (mirrors rotation.Scheduler).
type Event struct {
	SessionID string
	UserID    string
	Score     float64 // the decayed score that tripped the floor
	Floor     float64
}

// Agent is the ContinuousVerificationAgent. Construct with NewAgent, drive with
// Start/Stop under the process lifecycle.
type Agent struct {
	lister  SessionLister
	marker  core.SessionTrustManager
	cfg     trust.DecayConfig
	now     func() time.Time
	logger  spi.Logger
	metrics *metrics.Metrics
	onEvent func(Event)
	tick    time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// Option configures an Agent at construction.
type Option func(*Agent)

// WithSweepInterval overrides the polling cadence (default DefaultSweepInterval).
func WithSweepInterval(d time.Duration) Option {
	return func(a *Agent) {
		if d > 0 {
			a.tick = d
		}
	}
}

// WithClock injects the time source — tests pass a controllable clock so a
// sweep's decay math is deterministic. Default time.Now.
func WithClock(now func() time.Time) Option {
	return func(a *Agent) {
		if now != nil {
			a.now = now
		}
	}
}

// WithLogger overrides the default no-op logger.
func WithLogger(l spi.Logger) Option {
	return func(a *Agent) {
		if l != nil {
			a.logger = l
		}
	}
}

// WithMetrics wires the step-up counter (nil-safe at the observe site).
func WithMetrics(m *metrics.Metrics) Option {
	return func(a *Agent) { a.metrics = m }
}

// WithEventHook fans below-floor markings out to the operator (audit recorder,
// alerting). Called from the sweep goroutine — must not block.
func WithEventHook(fn func(Event)) Option {
	return func(a *Agent) { a.onEvent = fn }
}

// NewAgent builds the agent over the session lister + trust marker and decay
// config. marker MAY be nil (a backend without session-trust storage); the agent
// then no-ops every sweep, so a build wiring it against such a backend stays
// byte-identical.
func NewAgent(lister SessionLister, marker core.SessionTrustManager, cfg trust.DecayConfig, opts ...Option) *Agent {
	a := &Agent{
		lister: lister,
		marker: marker,
		cfg:    cfg,
		now:    time.Now,
		logger: spi.NopLogger{},
		tick:   DefaultSweepInterval,
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Start launches the sweep loop; the returned channel closes when the loop
// goroutine exits (so shutdown can wait on it, mirroring rotation.Scheduler).
// Calling Start on a running agent returns the existing channel. Start is inert
// (returns a closed channel) when the feature can't function — decay unconfigured,
// no lister, or no marker — so the caller may Start unconditionally.
func (a *Agent) Start(ctx context.Context) <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done != nil {
		return a.done
	}
	if !a.cfg.Enabled() || a.lister == nil || a.marker == nil {
		done := make(chan struct{})
		close(done)
		return done
	}
	runCtx, cancel := context.WithCancel(ctx)
	a.cancel = cancel
	a.done = make(chan struct{})
	go a.run(runCtx, a.done)
	return a.done
}

// Stop cancels the loop and waits for it to exit. Idempotent; safe on a
// never-started agent.
func (a *Agent) Stop() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.cancel, a.done = nil, nil
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (a *Agent) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	ticker := time.NewTicker(a.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.Sweep(ctx)
		}
	}
}

// Sweep runs one verification pass: list live sessions, and mark any whose
// decayed trust has fallen below the floor. Exported so a test (or an operator
// tool) can drive a single deterministic pass without the ticker. Fail-open: a
// list error skips the pass entirely rather than wedging the loop.
func (a *Agent) Sweep(ctx context.Context) {
	if a.marker == nil || !a.cfg.Enabled() {
		return
	}
	sessions, err := a.lister.ListAll(ctx)
	if err != nil {
		a.logger.Error("continuous verification: list sessions failed, skipping sweep", "error", err)
		return
	}
	now := a.now()
	for _, s := range sessions {
		if s == nil {
			continue
		}
		a.evaluate(ctx, *s, now)
	}
}

// evaluate marks one session if its live decayed trust is below floor. Skips
// dead sessions and ones already flagged (MarkStepUp is idempotent, but skipping
// avoids a redundant write + a duplicate audit event per sweep).
func (a *Agent) evaluate(ctx context.Context, s core.Session, now time.Time) {
	if s.Revoked || s.IsExpired() || s.StepUpRequired {
		return
	}
	if !trust.BelowFloor(s, now, a.cfg) {
		return
	}
	if err := a.marker.MarkStepUp(ctx, s.ID); err != nil {
		a.logger.Error("continuous verification: mark step-up failed", "session_id", s.ID, "error", err)
		return
	}
	score := trust.DecayedScore(s, now, a.cfg)
	a.metrics.ObserveSessionTrustStepUp()
	a.logger.Info("continuous verification: session trust below floor, marked for step-up",
		"session_id", s.ID, "score", score, "floor", a.cfg.Floor)
	a.emit(Event{SessionID: s.ID, UserID: s.UserID, Score: score, Floor: a.cfg.Floor})
}

func (a *Agent) emit(e Event) {
	if a.onEvent != nil {
		a.onEvent(e)
	}
}
