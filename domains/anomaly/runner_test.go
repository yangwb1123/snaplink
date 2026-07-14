package anomaly

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/threataction"
)

// recordingDetector captures every event it sees + optionally returns
// canned Anomalies / errors. Used to exercise the runner without
// pulling in concrete detector impls.
type recordingDetector struct {
	mu          sync.Mutex
	name        string
	seen        []*LoginEvent
	cannedAnoms []Signal
	cannedErr   error
}

func (r *recordingDetector) Name() string { return r.name }
func (r *recordingDetector) Inspect(_ context.Context, e *LoginEvent) ([]Signal, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, e)
	return r.cannedAnoms, r.cannedErr
}
func (r *recordingDetector) eventCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

// captureSink records each (event, anomaly) pair the runner emits —
// the test's view into "what the runner actually surfaced."
type captureSink struct {
	mu      sync.Mutex
	pairs   []sinkPair
	errOnce error
}

type sinkPair struct {
	Event  *LoginEvent
	Signal Signal
}

func (c *captureSink) Record(_ context.Context, e *LoginEvent, a Signal) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pairs = append(c.pairs, sinkPair{Event: e, Signal: a})
	if c.errOnce != nil {
		err := c.errOnce
		c.errOnce = nil
		return err
	}
	return nil
}
func (c *captureSink) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pairs)
}

// waitFor polls fn at 5ms intervals until it returns true or budget
// elapses. Keeps async tests deterministic without sleeping for the
// worst case.
func waitFor(t *testing.T, budget time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("waitFor: condition not met within %v", budget)
}

func TestNewAsyncAnomalyRunner_NoDetectorsReturnsNil(t *testing.T) {
	t.Parallel()
	// Empty detector list → nil runner. Server falls back to
	// no-op dispatch path; zero overhead invariant.
	r := NewRunner(nil, nil)
	if r != nil {
		t.Fatalf("empty detectors should return nil runner; got %v", r)
	}
}

func TestAsyncAnomalyRunner_DispatchesToEveryDetector(t *testing.T) {
	t.Parallel()
	d1 := &recordingDetector{name: "d1"}
	d2 := &recordingDetector{name: "d2"}
	sink := &captureSink{}
	r := NewRunner([]Detector{d1, d2}, sink)
	if r == nil {
		t.Fatal("runner should be non-nil with detectors")
	}
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	event := &LoginEvent{SubjectID: "alice", Outcome: "success"}
	r.Dispatch(context.Background(), event)

	waitFor(t, time.Second, func() bool {
		return d1.eventCount() == 1 && d2.eventCount() == 1
	})
}

func TestAsyncAnomalyRunner_DetectorErrorsDontStopSiblings(t *testing.T) {
	t.Parallel()
	// One broken detector shouldn't blind the others. The error
	// path is logged + metric'd but never propagates.
	d1 := &recordingDetector{name: "d1", cannedErr: errors.New("backend offline")}
	d2 := &recordingDetector{name: "d2", cannedAnoms: []Signal{
		{Type: "test", Severity: SeverityInfo},
	}}
	sink := &captureSink{}
	r := NewRunner([]Detector{d1, d2}, sink)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	waitFor(t, time.Second, func() bool { return sink.count() == 1 })
	// d1 ran (saw the event) even though it errored; d2 ran + sink
	// got its anomaly.
	if d1.eventCount() != 1 {
		t.Errorf("d1 should have run despite error: %d", d1.eventCount())
	}
	if d2.eventCount() != 1 || sink.count() != 1 {
		t.Errorf("d2 should have surfaced anomaly: events=%d sink=%d", d2.eventCount(), sink.count())
	}
}

func TestAsyncAnomalyRunner_SinkErrorIsLoggedNotRequeued(t *testing.T) {
	t.Parallel()
	// Sink failures shouldn't backpressure or re-queue — the
	// anomaly is already detected, we just couldn't notify. Log
	// + move on.
	d := &recordingDetector{name: "d", cannedAnoms: []Signal{
		{Type: "test", Severity: SeverityInfo},
	}}
	sink := &captureSink{errOnce: errors.New("audit sink down")}
	r := NewRunner([]Detector{d}, sink)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "bob"})
	waitFor(t, time.Second, func() bool { return d.eventCount() == 2 })
	// First Record errored but didn't re-queue; second Record
	// succeeded so sink.count = 2.
	waitFor(t, time.Second, func() bool { return sink.count() == 2 })
}

func TestAsyncAnomalyRunner_DropsNewestWhenQueueFull(t *testing.T) {
	t.Parallel()
	// Queue size 1, no started workers — second Dispatch hits a
	// full queue, drops newest, returns immediately.
	d := &recordingDetector{name: "d"}
	r := NewRunner([]Detector{d}, nil,
		WithQueueSize(1),
	)
	// NOT calling Start — workers never drain the queue.

	var dispatched atomic.Int32
	for range 10 {
		r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
		dispatched.Add(1)
	}
	if dispatched.Load() != 10 {
		t.Errorf("Dispatch should never block under drop_newest: %d", dispatched.Load())
	}
}

func TestAsyncAnomalyRunner_BlockPolicyHonorsCtx(t *testing.T) {
	t.Parallel()
	// Queue size 1, no workers, block policy — Dispatch waits for
	// space OR ctx cancellation, whichever comes first.
	d := &recordingDetector{name: "d"}
	r := NewRunner([]Detector{d}, nil,
		WithQueueSize(1),
		WithDropPolicy(DropBlock),
	)
	// Fill the queue.
	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "first"})

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	r.Dispatch(ctx, &LoginEvent{SubjectID: "second"})
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("Dispatch should honor ctx cancel (~50ms); took %v", elapsed)
	}
}

func TestAsyncAnomalyRunner_NilRunnerDispatchSafe(t *testing.T) {
	t.Parallel()
	// SDK contract: nil runner = no-op. The server's
	// dispatchLoginAnomaly path uses a nil-runner guard, but tests
	// here exercise the direct API too.
	var r *Runner
	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "x"})
	if err := r.Close(context.Background()); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}

func TestAsyncAnomalyRunner_CloseAfterCloseIsNoop(t *testing.T) {
	t.Parallel()
	d := &recordingDetector{name: "d"}
	r := NewRunner([]Detector{d}, nil)
	r.Start()
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(context.Background()); err != nil {
		t.Errorf("second Close should no-op: %v", err)
	}
}

func TestAsyncAnomalyRunner_DispatchAfterCloseDropsSilently(t *testing.T) {
	t.Parallel()
	d := &recordingDetector{name: "d"}
	r := NewRunner([]Detector{d}, nil)
	r.Start()
	_ = r.Close(context.Background())
	// Post-close Dispatch should drop silently (no panic, no block).
	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "after"})
	// d should have seen nothing post-close.
	if d.eventCount() != 0 {
		t.Errorf("post-close Dispatch leaked: %d events", d.eventCount())
	}
}

func TestAsyncAnomalyRunner_MultipleAnomaliesPerEvent(t *testing.T) {
	t.Parallel()
	// One detector can return multiple Anomalies per event (a single
	// login can trip impossible-travel + new-country at the same
	// time). Sink should receive both, attributed to the same event.
	d := &recordingDetector{name: "multi", cannedAnoms: []Signal{
		{Type: "a1", Severity: SeverityWarn},
		{Type: "a2", Severity: SeverityCritical},
	}}
	sink := &captureSink{}
	r := NewRunner([]Detector{d}, sink)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	waitFor(t, time.Second, func() bool { return sink.count() == 2 })
}

// recordingThreatExecutor captures every Threat it's asked to Execute — the
// test's view into "did the runner actually hand off to Active ITDR."
type recordingThreatExecutor struct {
	mu   sync.Mutex
	seen []threataction.Threat
}

func (r *recordingThreatExecutor) Name() string { return "recording" }
func (r *recordingThreatExecutor) Execute(_ context.Context, t threataction.Threat, _ threataction.ThreatPolicy) (threataction.ActionResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen = append(r.seen, t)
	return threataction.ActionResult{Action: threataction.ActionNoop, OK: true}, nil
}
func (r *recordingThreatExecutor) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}

// TestAsyncAnomalyRunner_ThreatExecutorReceivesDetectedSignal proves the P0
// wiring gap (WithThreatExecutor configured but never consulted) stays fixed:
// a detected Signal MUST reach the wired ThreatExecutor.Execute, carrying the
// event/signal fields the composite executor's policy matching depends on.
func TestAsyncAnomalyRunner_ThreatExecutorReceivesDetectedSignal(t *testing.T) {
	t.Parallel()
	d := &recordingDetector{name: "d", cannedAnoms: []Signal{
		{Type: "impossible_travel", Severity: SeverityCritical, SubjectID: "alice", Evidence: map[string]string{"distance_km": "9001"}},
	}}
	exec := &recordingThreatExecutor{}
	r := NewRunner([]Detector{d}, nil, WithThreatExecutor(exec))
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice", ClientID: "c1", TraceID: "trace-1"})

	waitFor(t, time.Second, func() bool { return exec.count() == 1 })
	got := exec.seen[0]
	if got.Type != "impossible_travel" || got.Severity != "critical" || got.SubjectID != "alice" {
		t.Errorf("threat fields mismatch: %+v", got)
	}
	if got.ClientID != "c1" || got.TraceID != "trace-1" {
		t.Errorf("threat should carry the event's ClientID/TraceID: %+v", got)
	}
	if got.Evidence["distance_km"] != "9001" {
		t.Errorf("threat should carry the signal's Evidence: %+v", got)
	}
}

func TestAsyncAnomalyRunner_NilThreatExecutorIsNoop(t *testing.T) {
	t.Parallel()
	// Unset (default) threat executor — the byte-identical-when-unset
	// invariant. A detected signal must not panic or block on a nil executor.
	d := &recordingDetector{name: "d", cannedAnoms: []Signal{{Type: "velocity_burst", Severity: SeverityWarn}}}
	sink := &captureSink{}
	r := NewRunner([]Detector{d}, sink)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "bob"})
	waitFor(t, time.Second, func() bool { return sink.count() == 1 })
}

// blockingDetector blocks in Inspect until either its release channel
// is closed OR the ctx the runner handed it is cancelled. It records
// which path it took so a test can prove the inspect deadline fired.
type blockingDetector struct {
	name     string
	release  chan struct{}
	ctxErr   atomic.Value // error: the ctx.Err() observed when cut off
	finished atomic.Bool
}

func (b *blockingDetector) Name() string { return b.name }
func (b *blockingDetector) Inspect(ctx context.Context, _ *LoginEvent) ([]Signal, error) {
	select {
	case <-b.release:
	case <-ctx.Done():
		b.ctxErr.Store(ctx.Err())
	}
	b.finished.Store(true)
	return nil, nil
}

func TestWithInspectTimeout_CutsOffSlowDetector(t *testing.T) {
	t.Parallel()
	// A detector that would block indefinitely must be cut off by the
	// configured per-detector inspect deadline — not hang the worker.
	d := &blockingDetector{name: "slow", release: make(chan struct{})}
	defer close(d.release) // never actually released — deadline must fire
	r := NewRunner([]Detector{d}, nil,
		WithInspectTimeout(20*time.Millisecond),
	)
	if r.inspectTimeout != 20*time.Millisecond {
		t.Fatalf("WithInspectTimeout not applied: got %v", r.inspectTimeout)
	}
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	// The detector must finish via the ctx-deadline path, not hang.
	waitFor(t, time.Second, func() bool { return d.finished.Load() })
	if got := d.ctxErr.Load(); got == nil || got.(error) != context.DeadlineExceeded {
		t.Fatalf("detector should have been cut off by inspect deadline; ctxErr=%v", got)
	}
}

func TestWithInspectTimeout_DefaultsToFiveSeconds(t *testing.T) {
	t.Parallel()
	// Unset → SDK default 5s (honor the 0→default convention).
	r := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil)
	if r.inspectTimeout != 5*time.Second {
		t.Fatalf("default inspect timeout should be 5s; got %v", r.inspectTimeout)
	}
	// A non-positive value is rejected (guard), leaving the default.
	r2 := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil,
		WithInspectTimeout(0),
		WithInspectTimeout(-1),
	)
	if r2.inspectTimeout != 5*time.Second {
		t.Fatalf("non-positive inspect timeout must be ignored; got %v", r2.inspectTimeout)
	}
}

func TestWithMetricsCallbacks_DispatchedFiresPerOfferedEvent(t *testing.T) {
	t.Parallel()
	// The dispatched (received) counter is the offered-load denominator:
	// one Inc per event actually offered to the queue — including events
	// that then get dropped — but NOT for nil events or a closed runner.
	var dispatched atomic.Int32
	d := &recordingDetector{name: "d"}
	r := NewRunner([]Detector{d}, nil,
		WithQueueSize(1),
		WithMetricsCallbacks(
			nil,                          // detected
			nil,                          // dropped
			nil,                          // inspectError
			func() { dispatched.Add(1) }, // dispatched
		),
	)
	// NOT starting workers — events pile into the queue / drop, but the
	// dispatched counter must still count every offered event.
	for range 5 {
		r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	}
	// A nil event is a no-op and must NOT increment.
	r.Dispatch(context.Background(), nil)
	if got := dispatched.Load(); got != 5 {
		t.Fatalf("dispatched should fire once per offered event (5); got %d", got)
	}

	// After Close, Dispatch is a no-op and must NOT increment.
	_ = r.Close(context.Background())
	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "bob"})
	if got := dispatched.Load(); got != 5 {
		t.Fatalf("post-close Dispatch must not increment dispatched; got %d", got)
	}
}

func TestRecorderAnomalySink_NilRecorderReturnsNil(t *testing.T) {
	t.Parallel()
	// Defensive: NewRecorderSink with nil recorder returns
	// nil so embedders can wire `NewRecorderSink(maybeNil)`
	// directly into NewRunner.
	if got := NewRecorderSink(nil); got != nil {
		t.Errorf("nil recorder should produce nil sink; got %v", got)
	}
}
