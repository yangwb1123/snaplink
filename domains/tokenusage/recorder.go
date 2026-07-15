package tokenusage

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/shared/spi"
)

// Recorder is the bounded-buffer ingest front for a [Store]. Handlers
// call Offer (non-blocking, drop-on-full); a single background drainer
// writes to the store. One drainer (not a pool) keeps store writes
// ordered and lets Store implementations optimize for a single writer;
// usage aggregation is far below the write volume that would need
// fan-out.
//
// Lifecycle mirrors anomaly.Runner:
//
//	rec := tokenusage.NewRecorder(store)
//	rec.Start()
//	srv := sso.NewServer(sso.WithTokenUsageRecorder(rec), ...)
//	// ... server runs ...
//	rec.Close(ctx) // drains the queue, waits for the drainer
type Recorder struct {
	store Store

	queueSize     int
	queue         chan Event
	recordTimeout time.Duration
	logger        spi.Logger

	// hooks is swapped atomically so sso.NewServer can bind metric
	// emitters AFTER the operator constructed (and possibly started)
	// the recorder — a plain field would race with the drainer.
	hooks atomic.Pointer[Hooks]

	// mu guards closed against queue sends: Offer holds the RLock
	// across BOTH the closed-check AND the send; Close takes the write
	// lock before close(queue). Without that coupling a concurrent
	// Offer could send on an already-closed channel and panic (same
	// TOCTOU as anomaly.Runner / audit.AsyncSink).
	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once
	wg        sync.WaitGroup
	started   atomic.Bool
}

// Hooks are the metric emitters the recorder fires. Any field may be
// nil — only set ones fire. Plain closures (not a prometheus dep) so
// the domain layer stays metric-library-free and tests can observe
// activity inline.
type Hooks struct {
	// Recorded fires after each successful store write, with the
	// event's kind + endpoint (both bounded label sets).
	Recorded func(kind, endpoint string)
	// Dropped fires when Offer sheds an event because the queue is
	// full — the load-shedding signal.
	Dropped func()
	// Tracked receives the store's tracked-bucket count after each
	// write, when the store implements TrackedBucketReporter.
	Tracked func(n int)
}

// RecorderOption tunes the Recorder at construction.
type RecorderOption func(*Recorder)

// WithQueueSize sets the bounded queue depth. Default 1024. Lower =
// sheds load sooner; higher = absorbs bursts at the cost of memory.
func WithQueueSize(n int) RecorderOption {
	return func(r *Recorder) {
		if n > 0 {
			r.queueSize = n
		}
	}
}

// WithRecordTimeout bounds each store write. Default 5s — generous
// for a memory/SQLite write while keeping a wedged backend from
// stalling the drain forever.
func WithRecordTimeout(d time.Duration) RecorderOption {
	return func(r *Recorder) {
		if d > 0 {
			r.recordTimeout = d
		}
	}
}

// WithRecorderLogger overrides the recorder's logger.
func WithRecorderLogger(l spi.Logger) RecorderOption {
	return func(r *Recorder) {
		if l != nil {
			r.logger = l
		}
	}
}

// NewRecorder builds a Recorder over store. Returns nil when store is
// nil — every method on a nil *Recorder is a safe no-op, so callers
// can wire it unconditionally.
func NewRecorder(store Store, opts ...RecorderOption) *Recorder {
	if store == nil {
		return nil
	}
	r := &Recorder{
		store:         store,
		queueSize:     1024,
		recordTimeout: 5 * time.Second,
		logger:        spi.NopLogger{},
	}
	for _, opt := range opts {
		opt(r)
	}
	r.queue = make(chan Event, r.queueSize)
	return r
}

// SetHooks atomically installs the metric emitters. Safe before or
// after Start, and while events are in flight.
func (r *Recorder) SetHooks(h Hooks) {
	if r == nil {
		return
	}
	r.hooks.Store(&h)
}

// UsageStore exposes the backing store for the admin read API.
func (r *Recorder) UsageStore() Store {
	if r == nil {
		return nil
	}
	return r.store
}

// Start launches the drainer. Safe to call exactly once; subsequent
// calls are silent no-ops.
func (r *Recorder) Start() {
	if r == nil || !r.started.CompareAndSwap(false, true) {
		return
	}
	r.wg.Add(1)
	go r.drain()
}

// Offer enqueues one event without ever blocking: a full queue drops
// the event and fires the Dropped hook (fail-open — telemetry loss is
// always preferable to /token latency). A zero At is stamped with the
// current time so buckets reflect observation time even when callers
// leave it unset.
func (r *Recorder) Offer(ev Event) {
	if r == nil {
		return
	}
	// Hold the read lock across BOTH the closed-check AND the send so a
	// concurrent Close (write lock before close(queue)) cannot close the
	// channel between the two — that race would panic.
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	select {
	case r.queue <- ev:
	default:
		if h := r.hooks.Load(); h != nil && h.Dropped != nil {
			h.Dropped()
		}
	}
}

// Close drains in-flight events + waits for the drainer to exit.
// ctx bounds the drain; on expiry the remaining events are abandoned.
func (r *Recorder) Close(ctx context.Context) error {
	if r == nil {
		return nil
	}
	closedNow := false
	r.closeOnce.Do(func() {
		r.mu.Lock()
		r.closed = true
		close(r.queue)
		r.mu.Unlock()
		closedNow = true
	})
	if !closedNow {
		return nil
	}
	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		r.logger.Error("token usage recorder Close timed out")
		return ctx.Err()
	}
}

func (r *Recorder) drain() {
	defer r.wg.Done()
	for ev := range r.queue {
		r.recordSafe(ev)
	}
}

// recordSafe wraps record in recover(). Store and Hooks are pluggable,
// operator-supplied implementations; a panic in one must drop only the
// current event, not escape drain()'s range loop — an unrecovered panic here
// would both permanently shrink this worker's slot out of the pool and crash
// the whole process over best-effort telemetry.
func (r *Recorder) recordSafe(ev Event) {
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Error("token usage record panic recovered", "panic", rec)
		}
	}()
	r.record(ev)
}

// record writes one event. A store error is logged and swallowed
// (fail-open): broken telemetry must never escalate beyond a log line.
func (r *Recorder) record(ev Event) {
	ctx, cancel := context.WithTimeout(context.Background(), r.recordTimeout)
	defer cancel()
	if err := r.store.Record(ctx, ev); err != nil {
		r.logger.Error("token usage record failed", "error", err)
		return
	}
	h := r.hooks.Load()
	if h == nil {
		return
	}
	if h.Recorded != nil {
		h.Recorded(string(ev.Kind), string(ev.Endpoint))
	}
	if h.Tracked != nil {
		if rep, ok := r.store.(TrackedBucketReporter); ok {
			h.Tracked(rep.TrackedBuckets())
		}
	}
}
