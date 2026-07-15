package tokenanomaly_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/threataction"
	"github.com/snaplink/sso/domains/tokenanomaly"
	tokenanomalymem "github.com/snaplink/sso/domains/tokenanomaly/memory"
	"github.com/snaplink/sso/domains/tokenusage"
	tokenusagemem "github.com/snaplink/sso/domains/tokenusage/memory"
)

// The detector is a tokenusage.Store decorator + off-path Analyze sweep. These
// tests drive it through the REAL memory usage store (as `next`) and the REAL
// memory finding store — no mocks, per repo convention. A fixed clock makes
// the window/velocity math deterministic.

var base = time.Date(2026, time.July, 3, 12, 0, 0, 0, time.UTC)

func fixedClock() func() time.Time { return func() time.Time { return base.Add(30 * time.Second) } }

// newDetector builds a detector over fresh memory stores at the fixed clock,
// returning it plus the finding store to inspect.
func newDetector(t *testing.T, opts ...tokenanomaly.Option) (*tokenanomaly.Detector, *tokenanomalymem.FindingStore, tokenusage.Store) {
	t.Helper()
	next := tokenusagemem.New()
	fs := tokenanomalymem.NewFindingStore()
	base := append([]tokenanomaly.Option{tokenanomaly.WithClock(fixedClock())}, opts...)
	return tokenanomaly.NewDetector(next, fs, base...), fs, next
}

func presentAt(t *testing.T, d *tokenanomaly.Detector, thumb, client, geo string, at time.Time) {
	t.Helper()
	if err := d.Record(context.Background(), tokenusage.Event{
		Thumbprint: thumb,
		Kind:       tokenusage.KindAccess,
		Endpoint:   tokenusage.EndpointIntrospect,
		ClientID:   client,
		SubjectID:  "user-" + client,
		GeoCountry: geo,
		At:         at,
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

// TestDetector_MultiGeo: one thumbprint seen from two distinct geos far enough
// apart to NOT be impossible travel is a warn-level multi_geo finding; a third
// geo escalates it to critical.
func TestDetector_MultiGeo(t *testing.T) {
	d, fs, _ := newDetector(t)
	// Two geos 6 minutes apart (> the 5m default velocity gap) within window.
	presentAt(t, d, "tp1", "c1", "US", base.Add(-14*time.Minute))
	presentAt(t, d, "tp1", "c1", "DE", base.Add(-8*time.Minute))

	found, err := d.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	f := findByType(found, tokenanomaly.FindingMultiGeo)
	if f == nil {
		t.Fatalf("no multi_geo finding: %+v", found)
	}
	if f.Severity != tokenanomaly.SeverityWarn {
		t.Errorf("severity = %q, want warn (2 geos, slow)", f.Severity)
	}
	if f.Thumbprint != "tp1" || len(f.Geos) != 2 {
		t.Errorf("finding = %+v, want tp1 with 2 geos", f)
	}
	// The store received it.
	list, _ := fs.List(context.Background(), tokenanomaly.FindingQuery{})
	if len(list) != 1 {
		t.Fatalf("store has %d findings, want 1", len(list))
	}

	// A third distinct geo (still spaced > velocity gap) escalates severity to
	// critical on the next sweep, updating the same deduped row.
	presentAt(t, d, "tp1", "c1", "JP", base.Add(-2*time.Minute))
	found, _ = d.Analyze(context.Background())
	if f := findByType(found, tokenanomaly.FindingMultiGeo); f == nil || f.Severity != tokenanomaly.SeverityCritical {
		t.Fatalf("3-geo finding = %+v, want critical", f)
	}
	if list, _ := fs.List(context.Background(), tokenanomaly.FindingQuery{}); len(list) != 1 {
		t.Fatalf("dedup failed: store has %d findings, want 1", len(list))
	}
}

// recordingThreatExecutor captures every Threat it's asked to Execute — used
// to prove a wired executor actually gets consulted (the P0 wiring gap this
// guards against), not just that Analyze still emits Findings.
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

// TestDetector_ThreatExecutorReceivesFindings proves a wired ThreatExecutor
// gets an Execute call for every finding Analyze emits, carrying the
// finding's Type/Severity/SubjectID/ClientID/Thumbprint through to the
// Threat — this is the P0 wiring the detector's own doc comment promises but
// that (pre-fix) had no automated coverage anywhere in the repo.
func TestDetector_ThreatExecutorReceivesFindings(t *testing.T) {
	exec := &recordingThreatExecutor{}
	d, _, _ := newDetector(t, tokenanomaly.WithVelocityGap(5*time.Minute), tokenanomaly.WithThreatExecutor(exec))
	presentAt(t, d, "tpv", "c1", "US", base.Add(-3*time.Minute))
	presentAt(t, d, "tpv", "c1", "AU", base.Add(-2*time.Minute)) // impossible travel

	found, err := d.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("expected at least one finding")
	}
	if len(exec.seen) != len(found) {
		t.Fatalf("executor saw %d Execute calls, want %d (one per finding)", len(exec.seen), len(found))
	}
	got := exec.seen[0]
	want := found[0]
	if got.Type != want.Type || got.Severity != string(want.Severity) || got.ClientID != want.ClientID {
		t.Errorf("threat = %+v, want to mirror finding %+v", got, want)
	}
	if got.Evidence["token_thumbprint"] != want.Thumbprint {
		t.Errorf("threat evidence thumbprint = %q, want %q", got.Evidence["token_thumbprint"], want.Thumbprint)
	}
}

// TestDetector_NilThreatExecutorIsNoop proves the byte-identical-when-unset
// invariant: Analyze must not panic when no executor is wired (the default).
func TestDetector_NilThreatExecutorIsNoop(t *testing.T) {
	d, _, _ := newDetector(t, tokenanomaly.WithVelocityGap(5*time.Minute))
	presentAt(t, d, "tpv", "c1", "US", base.Add(-3*time.Minute))
	presentAt(t, d, "tpv", "c1", "AU", base.Add(-2*time.Minute))
	if _, err := d.Analyze(context.Background()); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
}

// failingThreatExecutor always returns an error — used to prove Analyze
// logs (rather than silently drops) a threatExec.Execute failure.
type failingThreatExecutor struct {
	err error
}

func (f *failingThreatExecutor) Name() string { return "failing" }
func (f *failingThreatExecutor) Execute(_ context.Context, _ threataction.Threat, _ threataction.ThreatPolicy) (threataction.ActionResult, error) {
	return threataction.ActionResult{}, f.err
}

// countingLogger is a real spi.Logger that tallies Error calls — mirrors
// domains/anomaly's countingLogger test double (a plain in-package
// recorder, no mock framework, per repo convention).
type countingLogger struct {
	mu      sync.Mutex
	errMsgs []string
}

func (l *countingLogger) Info(_ string, _ ...any)  {}
func (l *countingLogger) Debug(_ string, _ ...any) {}
func (l *countingLogger) Error(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errMsgs = append(l.errMsgs, msg)
}
func (l *countingLogger) errorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errMsgs)
}

// TestDetector_ThreatExecutorErrorIsLogged proves Analyze routes a
// threatExec.Execute failure through the detector's logger — mirroring
// anomaly.Runner.inspect's equivalent behavior (domains/anomaly/runner.go) —
// instead of silently discarding it, which left an operator with no signal
// that a configured threat_action never actually fired.
func TestDetector_ThreatExecutorErrorIsLogged(t *testing.T) {
	lg := &countingLogger{}
	exec := &failingThreatExecutor{err: errors.New("boom")}
	d, _, _ := newDetector(t, tokenanomaly.WithThreatExecutor(exec), tokenanomaly.WithLogger(lg))
	presentAt(t, d, "tp1", "c1", "US", base.Add(-6*time.Minute))
	presentAt(t, d, "tp1", "c1", "DE", base.Add(-1*time.Minute))

	found, err := d.Analyze(context.Background())
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if len(found) == 0 {
		t.Fatal("expected at least one finding")
	}
	if lg.errorCount() != len(found) {
		t.Fatalf("logger recorded %d errors, want %d (one per finding)", lg.errorCount(), len(found))
	}
}

// TestDetector_ThreatExecutorErrorWithoutLoggerIsSafe proves Analyze never
// panics on a threatExec.Execute failure when no WithLogger option was set —
// the NopLogger default swallows it silently, preserving the fail-open
// contract for a build that hasn't wired a custom logger.
func TestDetector_ThreatExecutorErrorWithoutLoggerIsSafe(t *testing.T) {
	exec := &failingThreatExecutor{err: errors.New("boom")}
	d, _, _ := newDetector(t, tokenanomaly.WithThreatExecutor(exec))
	presentAt(t, d, "tp2", "c1", "US", base.Add(-6*time.Minute))
	presentAt(t, d, "tp2", "c1", "DE", base.Add(-1*time.Minute))
	if _, err := d.Analyze(context.Background()); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
}

// TestDetector_Velocity: two distinct-geo sightings closer than the velocity
// gap are impossible travel — a critical velocity finding, not multi_geo.
func TestDetector_Velocity(t *testing.T) {
	d, _, _ := newDetector(t, tokenanomaly.WithVelocityGap(5*time.Minute))
	presentAt(t, d, "tpv", "c1", "US", base.Add(-3*time.Minute))
	presentAt(t, d, "tpv", "c1", "AU", base.Add(-2*time.Minute)) // 1m apart, two continents

	found, _ := d.Analyze(context.Background())
	if findByType(found, tokenanomaly.FindingMultiGeo) != nil {
		t.Errorf("velocity case should not also emit multi_geo: %+v", found)
	}
	f := findByType(found, tokenanomaly.FindingVelocity)
	if f == nil || f.Severity != tokenanomaly.SeverityCritical {
		t.Fatalf("velocity finding = %+v, want critical", f)
	}
}

// TestDetector_SingleGeoNoFinding: a thumbprint seen from one geo (or none) is
// never a geo/velocity finding.
func TestDetector_SingleGeoNoFinding(t *testing.T) {
	d, _, _ := newDetector(t)
	presentAt(t, d, "tp1", "c1", "US", base.Add(-4*time.Minute))
	presentAt(t, d, "tp1", "c1", "US", base.Add(-2*time.Minute))
	presentAt(t, d, "tp2", "c1", "", base.Add(-1*time.Minute)) // no geo
	found, _ := d.Analyze(context.Background())
	if len(found) != 0 {
		t.Fatalf("expected no findings, got %+v", found)
	}
}

// TestDetector_StaleObservationNotReported: a multi-geo token whose last
// sighting is older than the window is not re-reported.
func TestDetector_StaleObservationNotReported(t *testing.T) {
	d, _, _ := newDetector(t, tokenanomaly.WithWindow(10*time.Minute))
	presentAt(t, d, "old", "c1", "US", base.Add(-40*time.Minute))
	presentAt(t, d, "old", "c1", "DE", base.Add(-30*time.Minute))
	found, _ := d.Analyze(context.Background())
	if len(found) != 0 {
		t.Fatalf("stale observation should not be reported, got %+v", found)
	}
}

// TestDetector_RateSpike: a client whose latest minute breaks well above its
// own trailing baseline is a rate_spike finding.
func TestDetector_RateSpike(t *testing.T) {
	d, _, _ := newDetector(t, tokenanomaly.WithSpikeMinCount(5), tokenanomaly.WithSpikeFactor(3))
	// Baseline: 1 issuance/min for three minutes, then a burst of 12.
	issue(t, d, "c1", 1, base.Add(-4*time.Minute))
	issue(t, d, "c1", 1, base.Add(-3*time.Minute))
	issue(t, d, "c1", 1, base.Add(-2*time.Minute))
	issue(t, d, "c1", 12, base.Add(-1*time.Minute))

	found, _ := d.Analyze(context.Background())
	f := findByType(found, tokenanomaly.FindingRateSpike)
	if f == nil {
		t.Fatalf("no rate_spike finding: %+v", found)
	}
	if f.ClientID != "c1" || f.Count != 12 {
		t.Errorf("finding = %+v, want c1 count 12", f)
	}
}

// TestDetector_NoSpikeBelowFloor: a proportionally-large jump that stays under
// the absolute floor is noise, not a spike.
func TestDetector_NoSpikeBelowFloor(t *testing.T) {
	d, _, _ := newDetector(t, tokenanomaly.WithSpikeMinCount(20), tokenanomaly.WithSpikeFactor(3))
	issue(t, d, "c1", 1, base.Add(-3*time.Minute))
	issue(t, d, "c1", 1, base.Add(-2*time.Minute))
	issue(t, d, "c1", 4, base.Add(-1*time.Minute)) // 4x baseline but < floor 20
	found, _ := d.Analyze(context.Background())
	if findByType(found, tokenanomaly.FindingRateSpike) != nil {
		t.Fatalf("below-floor jump should not spike: %+v", found)
	}
}

// TestDetector_ForwardsStore: the decorator forwards Record into the wrapped
// store's aggregation (Query) and reports its TrackedBuckets, so the wave-1
// usage read API + gauge keep working unchanged.
func TestDetector_ForwardsStore(t *testing.T) {
	d, _, next := newDetector(t)
	issue(t, d, "c1", 3, base.Add(-1*time.Minute))
	buckets, err := d.Query(context.Background(), tokenusage.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	var total int64
	for _, b := range buckets {
		total += b.Count
	}
	if total != 3 {
		t.Errorf("forwarded Query total = %d, want 3", total)
	}
	if d.TrackedBuckets() == 0 {
		t.Error("TrackedBuckets forwarded 0, want >0")
	}
	// The wrapped store agrees.
	if got, _ := next.Query(context.Background(), tokenusage.Query{}); len(got) != len(buckets) {
		t.Errorf("decorator Query diverged from wrapped store")
	}
}

// TestDetector_MetricHook: the finding hook fires once per emitted finding.
func TestDetector_MetricHook(t *testing.T) {
	var hookCalls int
	d, _, _ := newDetector(t)
	d.SetFindingHook(func(_, _ string) { hookCalls++ })
	presentAt(t, d, "tp1", "c1", "US", base.Add(-6*time.Minute))
	presentAt(t, d, "tp1", "c1", "DE", base.Add(-1*time.Minute))
	found, _ := d.Analyze(context.Background())
	if hookCalls != len(found) || hookCalls == 0 {
		t.Fatalf("hook fired %d times, want %d (one per finding)", hookCalls, len(found))
	}
}

// TestDetector_NilSafe: every method on a nil detector is a safe no-op.
func TestDetector_NilSafe(t *testing.T) {
	var d *tokenanomaly.Detector
	if err := d.Record(context.Background(), tokenusage.Event{}); err != nil {
		t.Errorf("nil Record: %v", err)
	}
	if _, err := d.Analyze(context.Background()); err != nil {
		t.Errorf("nil Analyze: %v", err)
	}
	if d.Findings() != nil || d.TrackedBuckets() != 0 {
		t.Error("nil accessors should be zero")
	}
}

// TestNewDetector_NilNext: a nil wrapped store yields a nil detector (safe
// no-op wiring, mirroring tokenusage.NewRecorder).
func TestNewDetector_NilNext(t *testing.T) {
	if d := tokenanomaly.NewDetector(nil, tokenanomalymem.NewFindingStore()); d != nil {
		t.Fatal("NewDetector(nil, ...) should be nil")
	}
}

// TestDetector_ConcurrentRecordAndAnalyze proves the off-path contract holds
// under the race detector: the drain goroutine (Record) and the sweep
// goroutine (Analyze) plus a hook install run concurrently without a data race.
func TestDetector_ConcurrentRecordAndAnalyze(t *testing.T) {
	d, _, _ := newDetector(t)
	d.SetFindingHook(func(_, _ string) {})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 500; i++ {
			presentAt(t, d, "tp", "c1", []string{"US", "DE", "JP"}[i%3], base.Add(-time.Duration(i%10)*time.Minute))
		}
		close(done)
	}()
	for i := 0; i < 50; i++ {
		if _, err := d.Analyze(context.Background()); err != nil {
			t.Errorf("Analyze: %v", err)
		}
	}
	<-done
}

// issue records n issuance events (empty thumbprint, EndpointToken) for client
// at minute `at` — the rate-spike data source.
func issue(t *testing.T, d *tokenanomaly.Detector, client string, n int, at time.Time) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := d.Record(context.Background(), tokenusage.Event{
			Kind:     tokenusage.KindAccess,
			Endpoint: tokenusage.EndpointToken,
			ClientID: client,
			At:       at,
		}); err != nil {
			t.Fatalf("Record issuance: %v", err)
		}
	}
}

func findByType(fs []tokenanomaly.Finding, typ string) *tokenanomaly.Finding {
	for i := range fs {
		if fs[i].Type == typ {
			return &fs[i]
		}
	}
	return nil
}
