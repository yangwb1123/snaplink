package audit_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

// flakySink fails the first N Record calls, then succeeds. Lets tests
// assert retry actually reaches the success path.
type flakySink struct {
	failsRemaining atomic.Int32
	calls          atomic.Int32
	failErr        error
}

func newFlakySink(initialFailures int, failErr error) *flakySink {
	f := &flakySink{failErr: failErr}
	f.failsRemaining.Store(int32(initialFailures))
	return f
}

func (f *flakySink) Record(_ context.Context, _ *audit.Event) error {
	f.calls.Add(1)
	if f.failsRemaining.Add(-1) >= 0 {
		return f.failErr
	}
	return nil
}
func (f *flakySink) Get(_ context.Context, _ string) (*audit.Event, error) {
	return nil, audit.ErrEventNotFound
}
func (f *flakySink) Query(_ context.Context, _ audit.Query) ([]*audit.Event, error) {
	return nil, nil
}

func TestRetryingSink_RetriesUntilSuccess(t *testing.T) {
	t.Parallel()
	inner := newFlakySink(2, errors.New("transient"))
	r := audit.NewRetryingSink(inner,
		audit.WithRetryMaxAttempts(5),
		audit.WithRetryInitialBackoff(time.Millisecond),
		audit.WithRetryMaxBackoff(10*time.Millisecond),
	)
	if err := r.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := inner.calls.Load(); got != 3 {
		t.Errorf("inner.calls = %d want 3 (2 failures + 1 success)", got)
	}
}

func TestRetryingSink_GivesUpAfterMaxAttempts(t *testing.T) {
	t.Parallel()
	inner := newFlakySink(99, errors.New("never recovers"))
	r := audit.NewRetryingSink(inner,
		audit.WithRetryMaxAttempts(4),
		audit.WithRetryInitialBackoff(time.Millisecond),
		audit.WithRetryMaxBackoff(5*time.Millisecond),
	)
	err := r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if err == nil {
		t.Fatal("expected error after exhausted retries")
	}
	if got := inner.calls.Load(); got != 4 {
		t.Errorf("inner.calls = %d want 4 (initial + 3 retries)", got)
	}
}

func TestRetryingSink_NonTransientShortCircuits(t *testing.T) {
	t.Parallel()
	inner := newFlakySink(99, errors.New("permanent"))
	r := audit.NewRetryingSink(inner,
		audit.WithRetryMaxAttempts(5),
		audit.WithRetryClassifier(func(err error) bool {
			// Never retry — every error is fatal.
			return false
		}),
	)
	err := r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if err == nil {
		t.Fatal("expected error")
	}
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("inner.calls = %d want 1 (no retries on non-transient)", got)
	}
}

func TestRetryingSink_HappyPathSingleCall(t *testing.T) {
	t.Parallel()
	inner := newFlakySink(0, errors.New("would fail if hit"))
	r := audit.NewRetryingSink(inner, audit.WithRetryMaxAttempts(5))
	if err := r.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if got := inner.calls.Load(); got != 1 {
		t.Errorf("inner.calls = %d want 1 (single call on first-try success)", got)
	}
}

func TestRetryingSink_ContextCancellationShortCircuits(t *testing.T) {
	t.Parallel()
	inner := newFlakySink(99, errors.New("transient"))
	r := audit.NewRetryingSink(inner,
		audit.WithRetryMaxAttempts(20),
		audit.WithRetryInitialBackoff(50*time.Millisecond),
	)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := r.Record(ctx, &audit.Event{Type: audit.EventLogin}); err == nil {
		t.Fatal("expected error on context cancellation")
	}
	// We allow 1-3 calls — depends on scheduler timing. The key
	// invariant: NOT all 20 attempts ran.
	if got := inner.calls.Load(); got > 5 {
		t.Errorf("inner.calls = %d — cancellation didn't short-circuit", got)
	}
}

func TestRetryingSink_ComposesWithAsyncSink(t *testing.T) {
	t.Parallel()
	// Realistic stack: AsyncSink -> RetryingSink -> flaky inner.
	// The retry wrapper should mask transient inner failures from
	// the AsyncSink drop accounting.
	inner := newFlakySink(2, errors.New("transient"))
	retrying := audit.NewRetryingSink(inner,
		audit.WithRetryMaxAttempts(5),
		audit.WithRetryInitialBackoff(time.Millisecond),
	)
	async := audit.NewAsyncSink(retrying)
	async.Start()

	_ = async.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	if err := async.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := async.DropsInnerError(); got != 0 {
		t.Errorf("DropsInnerError = %d want 0 (retry should mask flaky failures)", got)
	}
	if got := inner.calls.Load(); got != 3 {
		t.Errorf("inner.calls = %d want 3", got)
	}
}

func TestRetryingSink_ReadPathDelegates(t *testing.T) {
	t.Parallel()
	mem := audit.NewMemorySink(8)
	r := audit.NewRetryingSink(mem)
	_ = r.Record(context.Background(), &audit.Event{Type: audit.EventLogin})
	got, _ := r.Query(context.Background(), audit.Query{Limit: 10})
	if len(got) != 1 {
		t.Fatalf("Query through retry wrapper len=%d want 1", len(got))
	}
}
