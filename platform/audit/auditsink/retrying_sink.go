package auditsink

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/snaplink/sso/platform/audit/auditspi"
)

// DefaultRetryMaxAttempts caps how many times the worker tries to
// deliver one event before giving up. Includes the initial attempt
// — 3 means "try once, retry twice on transient failures."
const DefaultRetryMaxAttempts = 3

// DefaultRetryInitialBackoff is the first sleep between retries.
// Subsequent attempts double the wait, jittered ±25 %.
const DefaultRetryInitialBackoff = 100 * time.Millisecond

// DefaultRetryMaxBackoff caps the per-attempt wait. Without a cap a
// long retry chain blocks the worker indefinitely; with a cap the
// chain still finishes within bounded time.
const DefaultRetryMaxBackoff = 5 * time.Second

// TransientErrorClassifier returns true when err is worth retrying.
// Default classifies everything as transient — webhook + network
// sinks recover from most failures by waiting a bit. Override when
// the inner sink can produce non-transient errors (4xx HTTP, schema
// validation) that retrying won't fix.
type TransientErrorClassifier func(err error) bool

// DefaultTransientClassifier treats every non-nil error as transient.
// Override on retry-sensitive inner sinks (e.g., a webhook target
// that returns HTTP 4xx for validation errors).
func DefaultTransientClassifier(err error) bool { return err != nil }

// RetryingSink wraps another Sink and retries delivery on transient
// failures with exponential backoff. Intended composition:
//
//	asyncSink := audit.NewAsyncSink(
//	    audit.NewRetryingSink(webhookSink),
//	)
//
// The retry runs inside the worker goroutine, so a long backoff
// chain keeps the worker busy and can back up AsyncSink's queue.
// Tune attempts + max backoff so total worst-case retry time stays
// well below the AsyncSink buffer / arrival rate.
//
// Read paths (Get, Query) delegate without retry — they're already
// synchronous on the caller's goroutine and short-circuiting feels
// correct (a Get failure usually means "not found", not "try again").
type RetryingSink struct {
	inner       auditspi.Sink
	maxAttempts int
	initial     time.Duration
	max         time.Duration
	isTransient TransientErrorClassifier
	now         func() time.Time
	sleep       func(time.Duration)
}

// RetryOption configures a RetryingSink.
type RetryOption func(*RetryingSink)

// WithRetryMaxAttempts caps total attempts (including the first).
// Values <= 0 fall back to DefaultRetryMaxAttempts.
func WithRetryMaxAttempts(n int) RetryOption {
	return func(r *RetryingSink) {
		if n > 0 {
			r.maxAttempts = n
		}
	}
}

// WithRetryInitialBackoff sets the first inter-attempt wait. Each
// subsequent retry doubles the wait until WithRetryMaxBackoff is
// reached. Values <= 0 fall back to DefaultRetryInitialBackoff.
func WithRetryInitialBackoff(d time.Duration) RetryOption {
	return func(r *RetryingSink) {
		if d > 0 {
			r.initial = d
		}
	}
}

// WithRetryMaxBackoff caps the per-attempt sleep. Values <= 0 fall
// back to DefaultRetryMaxBackoff.
func WithRetryMaxBackoff(d time.Duration) RetryOption {
	return func(r *RetryingSink) {
		if d > 0 {
			r.max = d
		}
	}
}

// WithRetryClassifier supplies a custom transient-error filter.
// Defaults to "every non-nil error is transient." Override when the
// inner sink produces errors that retrying won't fix.
func WithRetryClassifier(c TransientErrorClassifier) RetryOption {
	return func(r *RetryingSink) {
		if c != nil {
			r.isTransient = c
		}
	}
}

// NewRetryingSink wraps inner with bounded retry + exponential
// backoff. Apply RetryOptions to tune attempts / timing.
func NewRetryingSink(inner auditspi.Sink, opts ...RetryOption) *RetryingSink {
	r := &RetryingSink{
		inner:       inner,
		maxAttempts: DefaultRetryMaxAttempts,
		initial:     DefaultRetryInitialBackoff,
		max:         DefaultRetryMaxBackoff,
		isTransient: DefaultTransientClassifier,
		now:         time.Now,
		sleep:       time.Sleep,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Record delivers e with up to maxAttempts tries. Returns the last
// error when every attempt failed, or nil on success.
//
// ctx cancellation short-circuits the retry loop — caller bears
// responsibility for matching ctx lifetime to acceptable max latency.
// AsyncSink's deliver passes context.Background plus a per-event
// timeout, which is the right shape here.
func (r *RetryingSink) Record(ctx context.Context, e *auditspi.Event) error {
	var lastErr error
	for attempt := 0; attempt < r.maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return lastErr
			}
			return ctx.Err()
		default:
		}
		err := r.inner.Record(ctx, e)
		if err == nil {
			return nil
		}
		lastErr = err
		if !r.isTransient(err) {
			return err
		}
		if attempt == r.maxAttempts-1 {
			break
		}
		r.sleep(r.backoff(attempt))
	}
	return lastErr
}

// backoff returns the sleep before retry N (0-indexed). Exponential
// from initial with ±25 % jitter, capped at max. Jitter spreads
// concurrent failures across the retry window so an inner sink
// recovering from overload doesn't get re-hit by a thundering herd.
func (r *RetryingSink) backoff(attempt int) time.Duration {
	base := r.initial << attempt
	if base <= 0 || base > r.max {
		base = r.max
	}
	jitter := float64(base) * (0.75 + rand.Float64()*0.5)
	return time.Duration(jitter)
}

// Get delegates to the inner sink.
func (r *RetryingSink) Get(ctx context.Context, id string) (*auditspi.Event, error) {
	return r.inner.Get(ctx, id)
}

// Query delegates to the inner sink.
func (r *RetryingSink) Query(ctx context.Context, q auditspi.Query) ([]*auditspi.Event, error) {
	return r.inner.Query(ctx, q)
}

// ErrNonTransient is a convenience sentinel wrappers can use to mark
// errors the retry loop MUST treat as permanent. Default classifier
// does not consult it (everything is transient by default); custom
// classifiers can `errors.Is(err, ErrNonTransient)` to gate.
var ErrNonTransient = errors.New("audit: non-transient")
