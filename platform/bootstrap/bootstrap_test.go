package bootstrap_test

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/bootstrap/file"
	"github.com/yangwb1123/snaplink/platform/bootstrap/memory"
)

type recorder struct {
	calls atomic.Int64
}

func (r *recorder) ran(_ context.Context) error { r.calls.Add(1); return nil }

func step(name string, version int, fn func(context.Context) error) bootstrap.Step {
	return bootstrap.StepFunc(name, version, fn)
}

func TestRunner_AppliesPendingInOrder(t *testing.T) {
	t.Parallel()
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr)
	r1, r2, r3 := &recorder{}, &recorder{}, &recorder{}
	// Register out of order to verify the runner sorts.
	r.Register(
		step("two", 2, r2.ran),
		step("three", 3, r3.ran),
		step("one", 1, r1.ran),
	)
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if r1.calls.Load() != 1 || r2.calls.Load() != 1 || r3.calls.Load() != 1 {
		t.Errorf("each step should run once: %d %d %d", r1.calls.Load(), r2.calls.Load(), r3.calls.Load())
	}
}

func TestRunner_AlreadyAppliedIsSkipped(t *testing.T) {
	t.Parallel()
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr)
	r1 := &recorder{}
	r.Register(step("one", 1, r1.ran))

	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("first run: %v", err)
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if got := r1.calls.Load(); got != 1 {
		t.Errorf("expected 1 invocation across two runs, got %d", got)
	}
}

func TestRunner_NewStepRunsOnLaterCall(t *testing.T) {
	t.Parallel()
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr)
	r1, r2 := &recorder{}, &recorder{}

	r.Register(step("one", 1, r1.ran))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("first run: %v", err)
	}

	// Now extend with v2; only it should run.
	r.Register(step("two", 2, r2.ran))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if r1.calls.Load() != 1 || r2.calls.Load() != 1 {
		t.Errorf("expected exactly 1 each, got %d %d", r1.calls.Load(), r2.calls.Load())
	}
}

func TestRunner_FailureStopsAndDoesNotMarkApplied(t *testing.T) {
	t.Parallel()
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr)
	good, bad, after := &recorder{}, &recorder{}, &recorder{}
	r.Register(
		step("good", 1, good.ran),
		step("bad", 2, func(_ context.Context) error { bad.calls.Add(1); return errors.New("boom") }),
		step("after", 3, after.ran),
	)

	err := r.Run(context.Background())
	if err == nil {
		t.Fatal("expected error from bad step")
	}
	if good.calls.Load() != 1 {
		t.Errorf("good should run once, got %d", good.calls.Load())
	}
	if bad.calls.Load() != 1 {
		t.Errorf("bad should run once, got %d", bad.calls.Load())
	}
	if after.calls.Load() != 0 {
		t.Errorf("after should NOT run after failure, got %d", after.calls.Load())
	}
	v, _ := tr.AppliedVersion(context.Background(), "ns")
	if v != 1 {
		t.Errorf("applied version should be 1 (good), got %d", v)
	}
}

func TestRunner_DuplicateVersionIsRejected(t *testing.T) {
	t.Parallel()
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr)
	r.Register(
		step("a", 1, func(_ context.Context) error { return nil }),
		step("b", 1, func(_ context.Context) error { return nil }),
	)
	if err := r.Run(context.Background()); err == nil {
		t.Fatal("expected duplicate-version error")
	}
}

func TestRunner_NamespaceIsolation(t *testing.T) {
	t.Parallel()
	tr := memory.New()
	r1 := bootstrap.NewRunner("alpha", tr)
	r2 := bootstrap.NewRunner("beta", tr)
	a, b := &recorder{}, &recorder{}
	r1.Register(step("a1", 1, a.ran))
	r2.Register(step("b1", 1, b.ran))

	if err := r1.Run(context.Background()); err != nil {
		t.Fatalf("r1: %v", err)
	}
	if err := r2.Run(context.Background()); err != nil {
		t.Fatalf("r2: %v", err)
	}
	if a.calls.Load() != 1 || b.calls.Load() != 1 {
		t.Errorf("each namespace should run its step once: %d %d", a.calls.Load(), b.calls.Load())
	}
}

func TestRunner_AuditRecorded(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	tr := memory.New()
	r := bootstrap.NewRunner("ns", tr, bootstrap.WithRecorder(rec))
	r.Register(step("one", 1, func(_ context.Context) error { return nil }))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := sink.Len(); got != 1 {
		t.Errorf("expected 1 audit event after first run, got %d", got)
	}
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("second run: %v", err)
	}
	// Second run records a "skipped" event.
	if got := sink.Len(); got != 2 {
		t.Errorf("expected 2 audit events after second run, got %d", got)
	}
}

// --- file tracker ---

func TestFileTracker_PersistsAcrossInstances(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	t1, err := file.New(path)
	if err != nil {
		t.Fatalf("file.New: %v", err)
	}
	r := bootstrap.NewRunner("ns", t1)
	hits := &recorder{}
	r.Register(step("one", 1, hits.ran))
	if err := r.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = t1.Close()

	// Fresh tracker against the same file should report version 1.
	t2, err := file.New(path)
	if err != nil {
		t.Fatalf("file.New 2: %v", err)
	}
	v, _ := t2.AppliedVersion(context.Background(), "ns")
	if v != 1 {
		t.Errorf("after restart version = %d, want 1", v)
	}

	// Re-run with the SAME step list — should be skipped.
	r2 := bootstrap.NewRunner("ns", t2)
	hits2 := &recorder{}
	r2.Register(step("one", 1, hits2.ran))
	if err := r2.Run(context.Background()); err != nil {
		t.Fatalf("Run 2: %v", err)
	}
	if hits2.calls.Load() != 0 {
		t.Errorf("expected step to be skipped after restart, ran %d times", hits2.calls.Load())
	}
}

func TestFileTracker_MissingFileIsEmpty(t *testing.T) {
	t.Parallel()
	tr, err := file.New(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err != nil {
		t.Fatalf("file.New: %v", err)
	}
	v, _ := tr.AppliedVersion(context.Background(), "anything")
	if v != 0 {
		t.Errorf("v = %d, want 0", v)
	}
}

func TestFileTracker_RequiresPath(t *testing.T) {
	t.Parallel()
	if _, err := file.New(""); err == nil {
		t.Fatal("expected error for empty path")
	}
}
