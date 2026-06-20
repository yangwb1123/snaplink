package audit

import (
	"context"
	"time"
)

// Recorder is the entry point used by handlers / SDKs. It buffers nothing,
// it just adapts a Sink with a few conveniences:
//   - timestamp defaulting
//   - error redirection through ErrorHandler instead of returning
//   - nil-safe Record (so handlers can call it without conditional guards)
type Recorder struct {
	sink     Sink
	onError  ErrorHandler
	now      func() time.Time
	chain    *chainer
	redactor Redactor
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

// WithHashChain enables tamper-evident hash chaining over recorded
// events. Each event's [Event.PrevHash] and [Event.Hash] fields are
// stamped before the sink sees it, so a tampered event breaks the
// chain at every subsequent event's recomputed hash.
//
// Verify offline with [VerifyChain] against a slice of events read
// from the sink (in chain order, oldest first — MemorySink returns
// newest-first by default).
//
// Cross-restart continuity: when the configured sink implements
// [ChainTip] (the SQLite sink does), the chain RESUMES from the last
// persisted event's Hash on construction, so the first event a fresh
// process records carries PrevHash == the last pre-restart Hash —
// VerifyChain sees one unbroken chain across the restart seam rather
// than a spurious second genesis. An empty store (or a memory-only
// sink that can't resume) seeds genesis. A tip-read error is
// best-effort: it seeds genesis and continues so a degraded sink
// never blocks recording — the only visible effect is a single
// chain break at this restart, identical to the pre-resume behavior.
func WithHashChain() Option {
	return func(r *Recorder) {
		r.chain = &chainer{}
		// Resume from durable storage before any event is stamped.
		// Options run after r.sink is set in New, so the sink (and its
		// optional ChainTip extension) is already in place here.
		if tip, ok := r.sink.(ChainTip); ok {
			if last, err := tip.LastHash(context.Background()); err == nil {
				r.chain.seed(last)
			}
		}
	}
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

// AddSink fans every recorded event out to extra IN ADDITION to the
// existing sink, by wrapping the current sink in a MultiSink. The
// original sink stays first, so reads (Get/Query) keep being served by
// it; extra is a write-side tap (e.g. a CAEP Transmitter) whose Record
// runs after the primary's. Redaction + hash-chaining still happen once,
// before either sink sees the event (they run in Record ahead of the
// sink call), so the tap observes the SAME redacted, chained event the
// primary stored.
//
// Not safe for concurrent use with Record — call it during wiring,
// before the Recorder is shared with request handlers. No-op on a nil
// Recorder or nil extra.
func (r *Recorder) AddSink(extra Sink) {
	if r == nil || extra == nil {
		return
	}
	r.sink = NewMultiSink(r.sink, extra)
}

// Record persists e. Safe to call on a nil Recorder (no-op) so handlers can
// always invoke it without guard. Timestamp is filled in if zero. When the
// Recorder was constructed with [WithHashChain], the event's PrevHash + Hash
// fields are stamped before the sink sees it.
func (r *Recorder) Record(ctx context.Context, e *Event) {
	if r == nil || r.sink == nil || e == nil {
		return
	}
	if e.Timestamp.IsZero() {
		e.Timestamp = r.now()
	}
	// Redaction runs BEFORE the hash chainer so the chain validates
	// over the redacted form. A downstream verifier shouldn't need
	// access to the pre-redaction values to check chain integrity.
	if r.redactor != nil {
		r.redactor.Redact(e)
	}
	if r.chain != nil {
		r.chain.stamp(e)
	}
	if err := r.sink.Record(ctx, e); err != nil && r.onError != nil {
		r.onError(err)
	}
}
