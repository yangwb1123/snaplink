package anomaly

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/geo"
)

// countingLogger is a real spi.Logger that tallies Error calls so a test
// can prove the runner routed a drop / sink failure through its logger.
// No mock framework — a plain in-package recorder, mirroring the
// recordingDetector convention already in runner_test.go.
type countingLogger struct {
	mu      sync.Mutex
	errMsgs []string
	infoN   int
	debugN  int
}

func (l *countingLogger) Info(_ string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infoN++
}
func (l *countingLogger) Error(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errMsgs = append(l.errMsgs, msg)
}
func (l *countingLogger) Debug(_ string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugN++
}
func (l *countingLogger) errorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errMsgs)
}

func TestWithWorkers_OverridesDefault(t *testing.T) {
	t.Parallel()
	// Default is 4; WithWorkers raises/lowers it. A non-positive value
	// is rejected (guard), leaving whatever stood before.
	r := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil)
	if r.workers != 4 {
		t.Fatalf("default workers should be 4; got %d", r.workers)
	}
	r2 := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil,
		WithWorkers(7),
	)
	if r2.workers != 7 {
		t.Fatalf("WithWorkers(7) not applied; got %d", r2.workers)
	}
	r3 := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil,
		WithWorkers(0),
		WithWorkers(-3),
	)
	if r3.workers != 4 {
		t.Fatalf("non-positive workers must be ignored; got %d", r3.workers)
	}
}

func TestWithWorkers_LaunchesConfiguredGoroutineCount(t *testing.T) {
	t.Parallel()
	// Prove the worker count is actually honored by Start: with 3 workers
	// and a detector that blocks until released, all 3 events can be
	// in-flight simultaneously. A single worker would serialize them.
	const n = 3
	var inFlight atomic.Int32
	var peak atomic.Int32
	release := make(chan struct{})

	det := &gateDetector{name: "gate", onInspect: func() {
		cur := inFlight.Add(1)
		for {
			old := peak.Load()
			if cur <= old || peak.CompareAndSwap(old, cur) {
				break
			}
		}
		<-release
		inFlight.Add(-1)
	}}
	r := NewRunner([]Detector{det}, nil, WithWorkers(n))
	r.Start()
	defer func() { close(release); _ = r.Close(context.Background()) }()

	for range n {
		r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	}
	waitFor(t, time.Second, func() bool { return peak.Load() == n })
	if got := peak.Load(); got != n {
		t.Fatalf("expected %d workers in flight concurrently; peak=%d", n, got)
	}
}

// gateDetector calls onInspect for every event — used to observe worker
// concurrency / saturation. Returns no anomalies.
type gateDetector struct {
	name      string
	onInspect func()
}

func (g *gateDetector) Name() string { return g.name }
func (g *gateDetector) Inspect(_ context.Context, _ *LoginEvent) ([]Signal, error) {
	g.onInspect()
	return nil, nil
}

func TestWithLogger_NilIgnored_CustomApplied(t *testing.T) {
	t.Parallel()
	// WithLogger(nil) is a guarded no-op; a real logger replaces the
	// NopLogger default.
	r := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil,
		WithLogger(nil),
	)
	if r.logger == nil {
		t.Fatal("nil logger must leave a non-nil default")
	}
	lg := &countingLogger{}
	r2 := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil,
		WithLogger(lg),
	)
	if r2.logger != lg {
		t.Fatal("WithLogger did not install the custom logger")
	}
}

func TestRecordDrop_LogsAndMetricsThroughCustomLogger(t *testing.T) {
	t.Parallel()
	// A full queue under drop_newest must: (a) log the drop via the
	// wired logger, and (b) fire the dropped metric callback with the
	// "queue_full" reason. Workers are never started so the queue stays
	// full.
	lg := &countingLogger{}
	var dropReasons []string
	var dmu sync.Mutex
	r := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil,
		WithQueueSize(1),
		WithLogger(lg),
		WithMetricsCallbacks(
			nil, // detected
			func(reason string) { // dropped
				dmu.Lock()
				dropReasons = append(dropReasons, reason)
				dmu.Unlock()
			},
			nil, // inspectError
			nil, // dispatched
		),
	)
	// First fills the queue, the next 4 all drop.
	for range 5 {
		r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	}
	if lg.errorCount() != 4 {
		t.Fatalf("expected 4 drop log lines; got %d", lg.errorCount())
	}
	dmu.Lock()
	defer dmu.Unlock()
	if len(dropReasons) != 4 {
		t.Fatalf("expected 4 dropped metric calls; got %d", len(dropReasons))
	}
	for _, reason := range dropReasons {
		if reason != "queue_full" {
			t.Fatalf("drop reason should be queue_full; got %q", reason)
		}
	}
}

func TestRecordDrop_BlockPolicyCtxCanceledReason(t *testing.T) {
	t.Parallel()
	// Under block policy with a full queue, a canceled ctx must drop
	// with the "ctx_canceled" reason (not "queue_full").
	var reasons []string
	var mu sync.Mutex
	r := NewRunner([]Detector{&recordingDetector{name: "d"}}, nil,
		WithQueueSize(1),
		WithDropPolicy(DropBlock),
		WithMetricsCallbacks(
			nil,
			func(reason string) { mu.Lock(); reasons = append(reasons, reason); mu.Unlock() },
			nil, nil,
		),
	)
	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "first"}) // fills queue
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-canceled → block select takes the ctx.Done branch
	r.Dispatch(ctx, &LoginEvent{SubjectID: "second"})

	mu.Lock()
	defer mu.Unlock()
	if len(reasons) != 1 || reasons[0] != "ctx_canceled" {
		t.Fatalf("expected single ctx_canceled drop; got %v", reasons)
	}
}

func TestMetricsCallbacks_DetectedAndInspectErrorFire(t *testing.T) {
	t.Parallel()
	// Exercise recordDetected + recordInspectError end-to-end through a
	// running worker: one detector errors (inspectError), another
	// surfaces an anomaly (detected). Both callbacks must fire with the
	// right labels.
	var detected []string
	var inspectErrs []string
	var mu sync.Mutex

	dErr := &recordingDetector{name: "broken", cannedErr: errors.New("backend down")}
	dOK := &recordingDetector{name: "ok", cannedAnoms: []Signal{
		{Type: "velocity_burst", Severity: SeverityWarn},
	}}
	r := NewRunner([]Detector{dErr, dOK}, nil,
		WithMetricsCallbacks(
			func(anomalyType, severity string) {
				mu.Lock()
				detected = append(detected, anomalyType+"/"+severity)
				mu.Unlock()
			},
			nil, // dropped
			func(detector string) {
				mu.Lock()
				inspectErrs = append(inspectErrs, detector)
				mu.Unlock()
			},
			nil, // dispatched
		),
	)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(detected) == 1 && len(inspectErrs) == 1
	})
	mu.Lock()
	defer mu.Unlock()
	if detected[0] != "velocity_burst/warn" {
		t.Fatalf("detected label mismatch: %v", detected)
	}
	if inspectErrs[0] != "broken" {
		t.Fatalf("inspectError detector label mismatch: %v", inspectErrs)
	}
}

func TestSinkFunc_RecordAdapter(t *testing.T) {
	t.Parallel()
	// SinkFunc is a func→Sink adapter; calling Record must invoke the
	// wrapped func with the same args and propagate its error.
	var gotEvent *LoginEvent
	var gotSignal Signal
	sentinel := errors.New("boom")
	var sf Sink = SinkFunc(func(_ context.Context, e *LoginEvent, a Signal) error {
		gotEvent = e
		gotSignal = a
		return sentinel
	})
	ev := &LoginEvent{SubjectID: "alice"}
	sig := Signal{Type: "x", Severity: SeverityInfo}
	if err := sf.Record(context.Background(), ev, sig); !errors.Is(err, sentinel) {
		t.Fatalf("SinkFunc must propagate the wrapped error; got %v", err)
	}
	if gotEvent != ev || gotSignal.Type != "x" {
		t.Fatalf("SinkFunc passed wrong args: event=%v signal=%v", gotEvent, gotSignal)
	}
}

func TestNewRecorderSink_WritesAnomalyAuditEvent(t *testing.T) {
	t.Parallel()
	// The standard recorder sink translates a Signal into an
	// audit.EventAnomalyDetected event carrying severity + score +
	// every Evidence key as metadata. Use the real in-memory audit
	// substrate (no mocks).
	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)
	rs := NewRecorderSink(rec)
	if rs == nil {
		t.Fatal("NewRecorderSink(non-nil) must return a sink")
	}

	ev := &LoginEvent{
		SubjectID: "alice",
		ClientID:  "web",
		Provider:  "password",
		RemoteIP:  "203.0.113.7",
		TraceID:   "trace-123",
	}
	sig := Signal{
		Type:     "impossible_travel",
		Severity: SeverityCritical,
		Score:    91,
		Evidence: map[string]string{
			"distance_km":       "9000",
			"implied_speed_kmh": "20000",
		},
	}
	if err := rs.Record(context.Background(), ev, sig); err != nil {
		t.Fatalf("recorder sink Record returned error: %v", err)
	}

	got, err := sink.Query(context.Background(), audit.Query{Type: audit.EventAnomalyDetected})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 anomaly audit event; got %d", len(got))
	}
	e := got[0]
	if e.Outcome != audit.OutcomeFailure {
		t.Errorf("anomaly outcome should be failure; got %q", e.Outcome)
	}
	if e.ActorID != "alice" || e.ClientID != "web" || e.Provider != "password" {
		t.Errorf("actor/client/provider mismatch: %+v", e)
	}
	if e.ActorIP != "203.0.113.7" || e.TraceID != "trace-123" {
		t.Errorf("ip/trace mismatch: ip=%q trace=%q", e.ActorIP, e.TraceID)
	}
	if e.Reason != "impossible_travel" {
		t.Errorf("reason should mirror anomaly type; got %q", e.Reason)
	}
	if e.Metadata["anomaly.severity"] != "critical" {
		t.Errorf("severity metadata missing: %v", e.Metadata)
	}
	if e.Metadata["anomaly.score"] != "91" {
		t.Errorf("score metadata missing: %v", e.Metadata)
	}
	if e.Metadata["distance_km"] != "9000" || e.Metadata["implied_speed_kmh"] != "20000" {
		t.Errorf("evidence metadata not propagated: %v", e.Metadata)
	}
}

func TestNewRecorderSink_ActorFallsBackToEventSubject(t *testing.T) {
	t.Parallel()
	// When the Signal carries no SubjectID, the audit ActorID falls
	// back to the event's SubjectID.
	sink := audit.NewMemorySink(8)
	rs := NewRecorderSink(audit.New(sink))

	ev := &LoginEvent{SubjectID: "from-event"}
	if err := rs.Record(context.Background(), ev,
		Signal{Type: "new_country", Severity: SeverityWarn}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventAnomalyDetected})
	if len(got) != 1 || got[0].ActorID != "from-event" {
		t.Fatalf("ActorID should fall back to event subject; got %+v", got)
	}
}

func TestNewRecorderSink_SignalSubjectWins(t *testing.T) {
	t.Parallel()
	// When the Signal resolves its own SubjectID (e.g. brute-force
	// shadow), it takes precedence over the event's subject.
	sink := audit.NewMemorySink(8)
	rs := NewRecorderSink(audit.New(sink))

	ev := &LoginEvent{SubjectID: "event-subject"}
	if err := rs.Record(context.Background(), ev,
		Signal{Type: "brute_force", Severity: SeverityCritical, SubjectID: "resolved-attacker"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventAnomalyDetected})
	if len(got) != 1 || got[0].ActorID != "resolved-attacker" {
		t.Fatalf("Signal SubjectID should win; got %+v", got)
	}
}

func TestNewRecorderSink_ZeroScoreOmitted(t *testing.T) {
	t.Parallel()
	// Binary detectors leave Score 0 → no anomaly.score metadata key.
	sink := audit.NewMemorySink(8)
	rs := NewRecorderSink(audit.New(sink))

	if err := rs.Record(context.Background(), &LoginEvent{SubjectID: "alice"},
		Signal{Type: "new_device", Severity: SeverityInfo, Score: 0}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventAnomalyDetected})
	if len(got) != 1 {
		t.Fatalf("expected 1 event; got %d", len(got))
	}
	if _, present := got[0].Metadata["anomaly.score"]; present {
		t.Errorf("zero score must be omitted; metadata=%v", got[0].Metadata)
	}
	if got[0].Metadata["anomaly.severity"] != "info" {
		t.Errorf("severity should still be present; metadata=%v", got[0].Metadata)
	}
}

func TestInspect_NeverInfluencesDispatchCaller(t *testing.T) {
	t.Parallel()
	// Hard invariant: anomaly detection MUST NOT feed back into the auth
	// decision. Dispatch is fire-and-forget — it returns no result and
	// must not block on inspect even when a detector flags critical. A
	// detector returning a critical anomaly cannot change Dispatch's
	// (void) contract: the call returns promptly regardless.
	d := &recordingDetector{name: "deny-ish", cannedAnoms: []Signal{
		{Type: "impossible_travel", Severity: SeverityCritical, Score: 100},
	}}
	sink := &captureSink{}
	r := NewRunner([]Detector{d}, sink, WithWorkers(1))
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	start := time.Now()
	r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice", Outcome: "success"})
	// Dispatch is non-blocking: it must return long before inspect runs.
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Dispatch blocked on inspect (%v) — anomaly path must be off the request path", elapsed)
	}
	// The anomaly is still surfaced asynchronously (proving the detector
	// did run), but only via the sink — never back through Dispatch.
	waitFor(t, time.Second, func() bool { return sink.count() == 1 })
}

func TestDispatch_DropNewestUnderLoad_ProcessesSomeDropsRest(t *testing.T) {
	t.Parallel()
	// Under sustained load with a small queue + a slow detector, the
	// runner processes a bounded subset and sheds the rest via
	// drop-newest — never blocking the dispatcher. Assert: every offer
	// counted (dispatched), and at least one drop occurred.
	const offers = 200
	var dispatched, dropped atomic.Int32
	release := make(chan struct{})
	det := &gateDetector{name: "slow", onInspect: func() { <-release }}

	r := NewRunner([]Detector{det}, nil,
		WithQueueSize(2),
		WithWorkers(1),
		WithMetricsCallbacks(
			nil,
			func(string) { dropped.Add(1) },
			nil,
			func() { dispatched.Add(1) },
		),
	)
	r.Start()
	for range offers {
		r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
	}
	// All offers were counted; the dispatcher never blocked.
	if got := dispatched.Load(); got != offers {
		t.Fatalf("every offered event must be counted; dispatched=%d want=%d", got, offers)
	}
	// With a queue of 2 + 1 stuck worker, most of 200 must have dropped.
	if dropped.Load() == 0 {
		t.Fatalf("expected drops under load with full queue; got 0")
	}
	// Unblock + drain.
	close(release)
	if err := r.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestDispatch_PreservesEventFields(t *testing.T) {
	t.Parallel()
	// The exact *LoginEvent pointer (with geo + all fields) reaches the
	// detector unmodified — the runner is a pure conduit.
	var seen *LoginEvent
	var mu sync.Mutex
	d := &capturingDetector{onInspect: func(e *LoginEvent) {
		mu.Lock()
		seen = e
		mu.Unlock()
	}}
	r := NewRunner([]Detector{d}, nil)
	r.Start()
	defer func() { _ = r.Close(context.Background()) }()

	ev := &LoginEvent{
		SubjectID:     "alice",
		ClientID:      "web",
		Provider:      "password",
		Outcome:       "failure",
		FailureReason: "bad_password",
		RemoteIP:      "198.51.100.4",
		UserAgent:     "curl/8",
		Geo:           &geo.GeoInfo{CountryCode: "US"},
		TraceID:       "tr-9",
		Timestamp:     time.Unix(1700000000, 0),
	}
	r.Dispatch(context.Background(), ev)
	waitFor(t, time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return seen != nil
	})
	mu.Lock()
	defer mu.Unlock()
	if seen != ev {
		t.Fatalf("detector should receive the exact event pointer")
	}
	if seen.Geo == nil || seen.Geo.CountryCode != "US" || seen.FailureReason != "bad_password" {
		t.Fatalf("event fields mutated in transit: %+v", seen)
	}
}

// capturingDetector forwards each event to onInspect, returning no
// anomalies — used to assert the runner doesn't mutate the event.
type capturingDetector struct {
	onInspect func(*LoginEvent)
}

func (c *capturingDetector) Name() string { return "capturing" }
func (c *capturingDetector) Inspect(_ context.Context, e *LoginEvent) ([]Signal, error) {
	c.onInspect(e)
	return nil, nil
}
