package auditsink

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit/auditspi"
)

// countingSink is a minimal real Sink fixture (not a mock — it has genuine
// storage-shaped behavior via failuresRemaining/records) used to drive
// RetryingSink through its retry loop deterministically. The equivalent
// black-box test in platform/audit/retrying_sink_test.go cannot reach the
// unexported sleep/backoff fields this file exercises directly, so this is
// new coverage, not a duplicate.
type countingSink struct {
	failuresRemaining atomic.Int32
	calls             atomic.Int32
	err               error
	onRecord          func(attempt int32)
}

func (s *countingSink) Record(_ context.Context, _ *auditspi.Event) error {
	n := s.calls.Add(1)
	if s.onRecord != nil {
		s.onRecord(n)
	}
	if s.failuresRemaining.Add(-1) >= 0 {
		return s.err
	}
	return nil
}

func (s *countingSink) Get(_ context.Context, id string) (*auditspi.Event, error) {
	return &auditspi.Event{ID: id}, nil
}

func (s *countingSink) Query(_ context.Context, _ auditspi.Query) ([]*auditspi.Event, error) {
	return []*auditspi.Event{{ID: "from-inner"}}, nil
}

// noSleep replaces RetryingSink's real sleep with a no-op so backoff-driven
// tests run instantly instead of burning real wall-clock time.
func noSleep(time.Duration) {}

func TestRetryingSink_SucceedsFirstAttemptNoRetry(t *testing.T) {
	t.Parallel()
	inner := &countingSink{err: errors.New("boom")}
	r := NewRetryingSink(inner, WithRetryMaxAttempts(5))
	r.sleep = noSleep

	if err := r.Record(context.Background(), &auditspi.Event{}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1 (no retry needed)", got)
	}
}

func TestRetryingSink_RetriesThenSucceeds(t *testing.T) {
	t.Parallel()
	inner := &countingSink{err: errors.New("transient")}
	inner.failuresRemaining.Store(2)
	r := NewRetryingSink(inner, WithRetryMaxAttempts(5))
	r.sleep = noSleep

	if err := r.Record(context.Background(), &auditspi.Event{}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := inner.calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3 (2 failures + 1 success)", got)
	}
}

func TestRetryingSink_ExhaustsAttemptsReturnsLastError(t *testing.T) {
	t.Parallel()
	wantErr := errors.New("always fails")
	inner := &countingSink{err: wantErr}
	inner.failuresRemaining.Store(1000) // never succeeds within maxAttempts
	r := NewRetryingSink(inner, WithRetryMaxAttempts(3))
	r.sleep = noSleep

	err := r.Record(context.Background(), &auditspi.Event{})
	if !errors.Is(err, wantErr) {
		t.Fatalf("Record err = %v, want %v", err, wantErr)
	}
	if got := inner.calls.Load(); got != 3 {
		t.Fatalf("calls = %d, want 3 (== maxAttempts, no attempt wasted after exhaustion)", got)
	}
}

func TestRetryingSink_NonTransientClassifierStopsImmediately(t *testing.T) {
	t.Parallel()
	permanent := errors.New("validation error")
	inner := &countingSink{err: permanent}
	inner.failuresRemaining.Store(1000)
	r := NewRetryingSink(inner,
		WithRetryMaxAttempts(5),
		WithRetryClassifier(func(error) bool { return false }), // nothing is transient
	)
	slept := false
	r.sleep = func(time.Duration) { slept = true }

	err := r.Record(context.Background(), &auditspi.Event{})
	if !errors.Is(err, permanent) {
		t.Fatalf("Record err = %v, want %v", err, permanent)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1 (classifier says non-transient, must not retry)", got)
	}
	if slept {
		t.Fatal("sleep was called even though the classifier rejected retry")
	}
}

// TestRetryingSink_ContextCanceledMidLoop drives the two branches of the
// ctx.Done() select inside Record: canceling before any attempt returns
// ctx.Err() (lastErr is nil); canceling after a failed attempt but before the
// retry sleep returns lastErr instead, since a real failure reason beats a
// generic "context canceled".
func TestRetryingSink_ContextCanceledMidLoop(t *testing.T) {
	t.Parallel()

	t.Run("canceled before first attempt", func(t *testing.T) {
		t.Parallel()
		inner := &countingSink{err: errors.New("unused")}
		r := NewRetryingSink(inner, WithRetryMaxAttempts(5))
		r.sleep = noSleep
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		err := r.Record(ctx, &auditspi.Event{})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Record err = %v, want context.Canceled", err)
		}
		if got := inner.calls.Load(); got != 0 {
			t.Fatalf("calls = %d, want 0 (canceled before any attempt)", got)
		}
	})

	t.Run("canceled after a failed attempt returns last real error", func(t *testing.T) {
		t.Parallel()
		wantErr := errors.New("first attempt failed")
		inner := &countingSink{err: wantErr}
		inner.failuresRemaining.Store(1000)
		ctx, cancel := context.WithCancel(context.Background())
		inner.onRecord = func(attempt int32) {
			if attempt == 1 {
				cancel() // cancel right after the first (failing) attempt
			}
		}
		r := NewRetryingSink(inner, WithRetryMaxAttempts(5))
		r.sleep = noSleep

		err := r.Record(ctx, &auditspi.Event{})
		if !errors.Is(err, wantErr) {
			t.Fatalf("Record err = %v, want %v (real failure should win over ctx cancellation)", err, wantErr)
		}
		if got := inner.calls.Load(); got != 1 {
			t.Fatalf("calls = %d, want 1 (loop must stop at the ctx.Done() check before attempt 2)", got)
		}
	})
}

func TestRetryingSink_GetAndQueryDelegateToInner(t *testing.T) {
	t.Parallel()
	inner := &countingSink{}
	r := NewRetryingSink(inner)

	e, err := r.Get(context.Background(), "evt-1")
	if err != nil || e == nil || e.ID != "evt-1" {
		t.Fatalf("Get() = %+v, %v; want delegated event with ID evt-1", e, err)
	}
	events, err := r.Query(context.Background(), auditspi.Query{})
	if err != nil || len(events) != 1 || events[0].ID != "from-inner" {
		t.Fatalf("Query() = %+v, %v; want delegated single event", events, err)
	}
}

// TestRetryingSink_Backoff exercises the exponential+jitter+cap arithmetic
// directly (white-box access to the unexported method) — including the
// overflow guard (base <= 0) that fires once initial<<attempt wraps negative
// for a large attempt count. A black-box test could only ever observe this by
// sleeping for real, which the parent audit package's test avoids entirely.
func TestRetryingSink_Backoff(t *testing.T) {
	t.Parallel()
	r := NewRetryingSink(&countingSink{},
		WithRetryInitialBackoff(100*time.Millisecond),
		WithRetryMaxBackoff(1*time.Second),
	)

	assertJittered := func(t *testing.T, got, base time.Duration) {
		t.Helper()
		lo := time.Duration(float64(base) * 0.75)
		hi := time.Duration(float64(base) * 1.25)
		if got < lo || got > hi {
			t.Errorf("backoff = %v, want within [%v, %v] of base %v", got, lo, hi, base)
		}
	}

	// attempt 0: base == initial (100ms).
	assertJittered(t, r.backoff(0), 100*time.Millisecond)
	// attempt 1: base == initial*2 (200ms).
	assertJittered(t, r.backoff(1), 200*time.Millisecond)
	// attempt 3: base == initial*8 (800ms), still under the 1s cap.
	assertJittered(t, r.backoff(3), 800*time.Millisecond)
	// attempt 4: base == initial*16 (1.6s) exceeds the 1s cap -> clamped to max.
	assertJittered(t, r.backoff(4), 1*time.Second)
	// attempt 100: initial<<100 overflows time.Duration (int64) into a
	// negative/zero value -> the "base <= 0" guard must also clamp to max.
	assertJittered(t, r.backoff(100), 1*time.Second)
}

func TestDefaultTransientClassifier(t *testing.T) {
	t.Parallel()
	if DefaultTransientClassifier(nil) {
		t.Error("DefaultTransientClassifier(nil) = true, want false")
	}
	if !DefaultTransientClassifier(errors.New("anything")) {
		t.Error("DefaultTransientClassifier(err) = false, want true for any non-nil error")
	}
}

func TestRetryOptions_IgnoreNonPositiveValues(t *testing.T) {
	t.Parallel()
	r := NewRetryingSink(&countingSink{},
		WithRetryMaxAttempts(0),
		WithRetryInitialBackoff(0),
		WithRetryMaxBackoff(-1),
		WithRetryClassifier(nil),
	)
	if r.maxAttempts != DefaultRetryMaxAttempts {
		t.Errorf("maxAttempts = %d, want default %d (WithRetryMaxAttempts(0) must be a no-op)", r.maxAttempts, DefaultRetryMaxAttempts)
	}
	if r.initial != DefaultRetryInitialBackoff {
		t.Errorf("initial = %v, want default %v", r.initial, DefaultRetryInitialBackoff)
	}
	if r.max != DefaultRetryMaxBackoff {
		t.Errorf("max = %v, want default %v", r.max, DefaultRetryMaxBackoff)
	}
	if r.isTransient == nil {
		t.Error("isTransient must fall back to DefaultTransientClassifier, got nil")
	}
}
