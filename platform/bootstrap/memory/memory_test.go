package memory

import (
	"context"
	"sync"
	"testing"

	"github.com/snaplink/sso/platform/bootstrap"
)

func TestTracker_StartsAtZero(t *testing.T) {
	tr := New()
	v, err := tr.AppliedVersion(context.Background(), "ns")
	if err != nil {
		t.Fatalf("AppliedVersion: %v", err)
	}
	if v != 0 {
		t.Errorf("v = %d, want 0 for fresh namespace", v)
	}
}

func TestTracker_MonotonicVersion(t *testing.T) {
	tr := New()
	ctx := context.Background()

	for _, v := range []int{1, 2, 3} {
		if err := tr.MarkApplied(ctx, "ns", v, "step"); err != nil {
			t.Fatalf("MarkApplied(%d): %v", v, err)
		}
	}
	got, _ := tr.AppliedVersion(ctx, "ns")
	if got != 3 {
		t.Errorf("got %d, want 3", got)
	}

	// Out-of-order lower-version mark must NOT regress the watermark.
	if err := tr.MarkApplied(ctx, "ns", 2, "rerun"); err != nil {
		t.Fatalf("MarkApplied(2): %v", err)
	}
	got, _ = tr.AppliedVersion(ctx, "ns")
	if got != 3 {
		t.Errorf("after low-version mark: got %d, want 3 (no regression)", got)
	}
}

func TestTracker_NamespacesIsolated(t *testing.T) {
	tr := New()
	ctx := context.Background()
	_ = tr.MarkApplied(ctx, "a", 5, "step")
	_ = tr.MarkApplied(ctx, "b", 1, "step")

	if v, _ := tr.AppliedVersion(ctx, "a"); v != 5 {
		t.Errorf("ns a = %d, want 5", v)
	}
	if v, _ := tr.AppliedVersion(ctx, "b"); v != 1 {
		t.Errorf("ns b = %d, want 1", v)
	}
	if v, _ := tr.AppliedVersion(ctx, "c"); v != 0 {
		t.Errorf("untouched ns c = %d, want 0", v)
	}
}

func TestTracker_ConcurrentMarksSafe(t *testing.T) {
	tr := New()
	ctx := context.Background()
	const n = 100
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 1; i <= n; i++ {
		go func(v int) {
			defer wg.Done()
			_ = tr.MarkApplied(ctx, "ns", v, "step")
		}(i)
	}
	wg.Wait()
	if v, _ := tr.AppliedVersion(ctx, "ns"); v != n {
		t.Errorf("after concurrent marks: v = %d, want %d", v, n)
	}
}

func TestTracker_CloseIsNop(t *testing.T) {
	tr := New()
	if err := tr.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestTracker_SatisfiesInterface(t *testing.T) {
	var _ bootstrap.Tracker = New()
}
