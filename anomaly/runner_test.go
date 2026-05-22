package anomaly

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
	// Empty detector list → nil runner. Server falls back to
	// no-op dispatch path; zero overhead invariant.
	r := NewRunner(nil, nil)
	if r != nil {
		t.Fatalf("empty detectors should return nil runner; got %v", r)
	}
}

func TestAsyncAnomalyRunner_DispatchesToEveryDetector(t *testing.T) {
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

func TestRecorderAnomalySink_NilRecorderReturnsNil(t *testing.T) {
	// Defensive: NewRecorderSink with nil recorder returns
	// nil so embedders can wire `NewRecorderSink(maybeNil)`
	// directly into NewRunner.
	if got := NewRecorderSink(nil); got != nil {
		t.Errorf("nil recorder should produce nil sink; got %v", got)
	}
}
