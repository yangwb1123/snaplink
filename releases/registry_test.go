package releases_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/releases"
	"github.com/snaplink/sso/releases/store/memory"
)

// captureP records each call so tests can assert ordering + count.
type captureP struct {
	forward  atomic.Int32
	rollback atomic.Int32
	err      error
}

func (p *captureP) PinForward(_ context.Context, _ *releases.Release) error {
	p.forward.Add(1)
	return p.err
}

func (p *captureP) PinRollback(_ context.Context, _ *releases.Release) error {
	p.rollback.Add(1)
	return p.err
}

func newRegistry(t *testing.T, p releases.Pinner) (*releases.Registry, *memory.Store) {
	t.Helper()
	st := memory.New()
	return &releases.Registry{Store: st, Pinner: p}, st
}

func mkRel(id string, schema int) *releases.Release {
	return &releases.Release{
		ID:            id,
		SchemaVersion: schema,
		Frontend:      releases.Artifact{GitRef: "v" + id},
		Backend:       releases.Artifact{GitRef: "v" + id},
	}
}

func TestPin_ForwardSuccessAdvancesCurrent(t *testing.T) {
	p := &captureP{}
	r, st := newRegistry(t, p)
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))

	rep, err := r.Pin(ctx, "rel-1")
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if rep.Mode != releases.PinForward {
		t.Errorf("Mode=%v", rep.Mode)
	}
	if rep.PreviousID != "" {
		t.Errorf("PreviousID=%q want empty", rep.PreviousID)
	}
	if p.forward.Load() != 1 || p.rollback.Load() != 0 {
		t.Errorf("pinner counts: forward=%d rollback=%d", p.forward.Load(), p.rollback.Load())
	}
	cur, _ := r.Current(ctx)
	if cur == nil || cur.ID != "rel-1" {
		t.Errorf("Current = %+v", cur)
	}
}

func TestPin_PreviousIDReportedOnSecondPin(t *testing.T) {
	p := &captureP{}
	r, st := newRegistry(t, p)
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))
	_ = st.Register(ctx, mkRel("rel-2", 2))
	_, _ = r.Pin(ctx, "rel-1")
	rep, err := r.Pin(ctx, "rel-2")
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if rep.PreviousID != "rel-1" {
		t.Errorf("PreviousID=%q want rel-1", rep.PreviousID)
	}
}

func TestPin_PinnerErrorAbortsAndKeepsCurrent(t *testing.T) {
	wantErr := errors.New("deploy fails")
	p := &captureP{err: wantErr}
	r, st := newRegistry(t, p)
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))

	if _, err := r.Pin(ctx, "rel-1"); !errors.Is(err, wantErr) {
		t.Fatalf("Pin err = %v, want wraps wantErr", err)
	}
	if _, err := r.Current(ctx); !errors.Is(err, releases.ErrNoCurrent) {
		t.Errorf("Current after failed Pin: %v", err)
	}
}

func TestPin_NilPinnerAdvancesCurrent(t *testing.T) {
	r, st := newRegistry(t, nil)
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))
	if _, err := r.Pin(ctx, "rel-1"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	cur, _ := r.Current(ctx)
	if cur.ID != "rel-1" {
		t.Errorf("Current id=%q", cur.ID)
	}
}

func TestPin_SchemaRegressionRejected(t *testing.T) {
	p := &captureP{}
	r, st := newRegistry(t, p)
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-old", 1))
	_ = st.Register(ctx, mkRel("rel-new", 2))
	_, _ = r.Pin(ctx, "rel-new")

	_, err := r.Pin(ctx, "rel-old")
	if !errors.Is(err, releases.ErrSchemaRegress) {
		t.Fatalf("expected ErrSchemaRegress, got %v", err)
	}
	// Ensure current didn't budge.
	cur, _ := r.Current(ctx)
	if cur.ID != "rel-new" {
		t.Errorf("current drifted to %q", cur.ID)
	}
}

func TestRollback_SchemaRegressionAllowed(t *testing.T) {
	p := &captureP{}
	r, st := newRegistry(t, p)
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-old", 1))
	_ = st.Register(ctx, mkRel("rel-new", 2))
	_, _ = r.Pin(ctx, "rel-new")

	rep, err := r.Rollback(ctx, "rel-old")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rep.Mode != releases.PinRollback {
		t.Errorf("Mode=%v", rep.Mode)
	}
	if p.rollback.Load() != 1 {
		t.Errorf("PinRollback not called")
	}
	cur, _ := r.Current(ctx)
	if cur.ID != "rel-old" {
		t.Errorf("current = %q", cur.ID)
	}
}

func TestPin_UnknownReleaseIsNotFound(t *testing.T) {
	r, _ := newRegistry(t, nil)
	if _, err := r.Pin(context.Background(), "ghost"); !errors.Is(err, releases.ErrReleaseNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestCurrent_FreshStoreReturnsErrNoCurrent(t *testing.T) {
	r, _ := newRegistry(t, nil)
	if _, err := r.Current(context.Background()); !errors.Is(err, releases.ErrNoCurrent) {
		t.Fatalf("err = %v", err)
	}
}

// scriptedProbe returns the next error in a fixed sequence, then
// returns nil for any subsequent call. Lets tests script
// "fail-then-succeed" and "always-fail" probe behaviors precisely.
type scriptedProbe struct {
	calls   atomic.Int32
	results []error
}

func (p *scriptedProbe) Probe(_ context.Context, _ *releases.Release) error {
	idx := int(p.calls.Add(1)) - 1
	if idx >= len(p.results) {
		return nil
	}
	return p.results[idx]
}

func TestPin_ProbeSuccessKeepsRelease(t *testing.T) {
	p := &captureP{}
	probe := &scriptedProbe{} // empty results → all calls succeed
	st := memory.New()
	r := &releases.Registry{Store: st, Pinner: p, Probe: probe, ProbeBackoff: time.Millisecond}
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))
	if _, err := r.Pin(ctx, "rel-1"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if probe.calls.Load() != 1 {
		t.Errorf("probe calls = %d, want 1", probe.calls.Load())
	}
	if p.rollback.Load() != 0 {
		t.Errorf("rollback unexpectedly called")
	}
}

func TestPin_ProbeFailureRollsBackToPrevious(t *testing.T) {
	p := &captureP{}
	wantErr := errors.New("503")
	probe := &scriptedProbe{results: []error{wantErr, wantErr}} // both attempts fail
	st := memory.New()
	r := &releases.Registry{Store: st, Pinner: p, Probe: probe, ProbePolls: 2, ProbeBackoff: time.Millisecond}
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))
	_ = st.Register(ctx, mkRel("rel-2", 2))
	_, _ = r.Pin(ctx, "rel-1")
	probe.calls.Store(0) // reset for the rel-2 attempt

	_, err := r.Pin(ctx, "rel-2")
	if err == nil {
		t.Fatal("expected probe error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("err does not wrap probe error: %v", err)
	}
	// Forward count: rel-1 + rel-2 = 2; rollback count: rel-1 (auto) = 1.
	if p.forward.Load() != 2 || p.rollback.Load() != 1 {
		t.Errorf("pinner counts: forward=%d rollback=%d", p.forward.Load(), p.rollback.Load())
	}
	cur, _ := r.Current(ctx)
	if cur == nil || cur.ID != "rel-1" {
		t.Errorf("Current after auto-rollback = %+v", cur)
	}
}

func TestPin_ProbeFailureNoPreviousLeavesAsIs(t *testing.T) {
	p := &captureP{}
	probe := &scriptedProbe{results: []error{errors.New("nope")}}
	st := memory.New()
	r := &releases.Registry{Store: st, Pinner: p, Probe: probe, ProbePolls: 1, ProbeBackoff: time.Millisecond}
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))

	if _, err := r.Pin(ctx, "rel-1"); err == nil {
		t.Fatal("expected probe error")
	}
	// No previous to roll back to — release stays current.
	cur, _ := r.Current(ctx)
	if cur == nil || cur.ID != "rel-1" {
		t.Errorf("Current = %+v want rel-1", cur)
	}
	if p.rollback.Load() != 0 {
		t.Errorf("rollback called with no previous: %d", p.rollback.Load())
	}
}

func TestPin_ProbeRetriesUntilSuccess(t *testing.T) {
	p := &captureP{}
	probe := &scriptedProbe{results: []error{errors.New("warming up"), errors.New("warming up")}}
	st := memory.New()
	r := &releases.Registry{Store: st, Pinner: p, Probe: probe, ProbePolls: 5, ProbeBackoff: time.Millisecond}
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-1", 1))

	if _, err := r.Pin(ctx, "rel-1"); err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if probe.calls.Load() != 3 {
		t.Errorf("probe calls = %d, want 3", probe.calls.Load())
	}
}

func TestRollback_DoesNotProbe(t *testing.T) {
	p := &captureP{}
	probe := &scriptedProbe{results: []error{errors.New("would fail")}}
	st := memory.New()
	r := &releases.Registry{Store: st, Pinner: p, Probe: probe, ProbePolls: 1, ProbeBackoff: time.Millisecond}
	ctx := context.Background()
	_ = st.Register(ctx, mkRel("rel-old", 1))
	_ = st.Register(ctx, mkRel("rel-new", 2))
	probe.results = nil // forward Pin should succeed
	_, _ = r.Pin(ctx, "rel-new")
	probeBefore := probe.calls.Load()

	if _, err := r.Rollback(ctx, "rel-old"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if probe.calls.Load() != probeBefore {
		t.Errorf("Rollback should not probe; calls before=%d after=%d", probeBefore, probe.calls.Load())
	}
}
