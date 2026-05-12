package audit

import (
	"context"
	"errors"
	"time"
)

// ErrEventNotFound is returned by Sink.Get for unknown event IDs.
var ErrEventNotFound = errors.New("audit: event not found")

// Sink stores and serves audit events. Implementations must be safe for
// concurrent use. The MemorySink in this package is the default; production
// backends typically write to a database, file, or log shipper.
type Sink interface {
	Record(ctx context.Context, e *Event) error
	Query(ctx context.Context, q Query) ([]*Event, error)
	Get(ctx context.Context, id string) (*Event, error)
}

// ErrorHandler reports a failure from Sink.Record. Audit recording is best-
// effort by design — a failed sink should never block a login — so the only
// signal is this callback.
type ErrorHandler func(error)

// Recorder is the entry point used by handlers / SDKs. It buffers nothing,
// it just adapts a Sink with a few conveniences:
//   - timestamp defaulting
//   - error redirection through ErrorHandler instead of returning
//   - nil-safe Record (so handlers can call it without conditional guards)
type Recorder struct {
	sink    Sink
	onError ErrorHandler
	now     func() time.Time
}

type Option func(*Recorder)

// WithErrorHandler routes Sink.Record failures to fn instead of swallowing them.
func WithErrorHandler(fn ErrorHandler) Option {
	return func(r *Recorder) { r.onError = fn }
}

// WithClock overrides the timestamp source. Useful for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Recorder) { r.now = now }
}

func New(sink Sink, opts ...Option) *Recorder {
	r := &Recorder{sink: sink, now: time.Now}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Sink returns the underlying sink. Used by query endpoints.
func (r *Recorder) Sink() Sink { return r.sink }

// Record persists e. Safe to call on a nil Recorder (no-op) so handlers can
// always invoke it without guard. Timestamp is filled in if zero.
func (r *Recorder) Record(ctx context.Context, e *Event) {
	if r == nil || r.sink == nil || e == nil {
		return
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = r.now()
	}
	if err := r.sink.Record(ctx, e); err != nil && r.onError != nil {
		r.onError(err)
	}
}
