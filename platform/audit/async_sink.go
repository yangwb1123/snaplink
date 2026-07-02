package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/snaplink/sso/platform/tracing"
	"go.opentelemetry.io/otel/attribute"
)

// DefaultAsyncBufferSize is the queue capacity when WithAsyncBuffer is
// not provided.
const DefaultAsyncBufferSize = 1024

// DefaultBatchSize is the maximum number of events collected in a single
// drain pass when using [NewBatchAsyncSink]. Sized to keep one SQLite
// transaction small enough that a slow fsync doesn't starve other writers
// while still amortising the per-transaction overhead well past the
// breakeven point.
const DefaultBatchSize = 64

// ErrAsyncQueueFull signals that the AsyncSink dropped an event because
// the in-memory buffer was at capacity. Audit recording is best-effort
// by design — the request path is intentionally never blocked.
var ErrAsyncQueueFull = errors.New("audit: async queue full")

// ErrAsyncSinkClosed signals an event dropped because Record was called
// after Close.
var ErrAsyncSinkClosed = errors.New("audit: async sink closed")

// AsyncDropHandler is invoked when AsyncSink cannot deliver an Event:
// queue overflow (ErrAsyncQueueFull), shutdown (ErrAsyncSinkClosed), or
// a delivery error from the inner Sink. Wire this to a counter / log so
// drops are visible.
type AsyncDropHandler func(e *Event, err error)

// AsyncSink wraps an inner Sink and dispatches Record calls on a
// background worker pool. Record never blocks: when the buffer is
// full, the event is dropped and the AsyncDropHandler is invoked.
//
// Use this when the inner Sink can be slow (HTTP webhook, network log
// shipper) and the request path must stay bounded. For purely in-memory
// or local-file sinks the synchronous Recorder is already fine — don't
// reach for async indiscriminately, the extra goroutine hop has its own
// cost.
//
// Read paths (Get, Query) are served synchronously from the inner Sink;
// only the write path is asynchronous.
type AsyncSink struct {
	inner     Sink
	queue     chan *Event
	workers   int
	onDrop    AsyncDropHandler
	timeout   time.Duration
	batchSize int // 0 or 1 = per-event (default); > 1 = batch mode

	mu        sync.RWMutex
	closed    bool
	closeOnce sync.Once

	startedMu sync.Mutex
	started   bool
	wg        sync.WaitGroup

	// Monotonic counters operators can scrape into a Prometheus gauge
	// (DropsQueueFull + DropsClosed + DropsInnerError as separate
	// labels). All updates are atomic so reads are safe concurrent
	// with worker activity.
	dropsQueueFull  atomic.Int64
	dropsClosed     atomic.Int64
	dropsInnerError atomic.Int64
}

// AsyncOption configures an AsyncSink at construction.
type AsyncOption func(*AsyncSink)

// WithAsyncBuffer sets the queue capacity. Values <= 0 fall back to
// DefaultAsyncBufferSize. Sized for peak burst; oversize means slower
// drop detection during sustained overload.
func WithAsyncBuffer(n int) AsyncOption {
	return func(a *AsyncSink) {
		if n > 0 {
			a.queue = make(chan *Event, n)
		}
	}
}

// WithAsyncWorkers sets the number of goroutines draining the queue.
// Values <= 0 default to 1. Increase only when the inner Sink is
// thread-safe AND the wire allows useful parallelism (e.g., HTTP/2
// webhook); otherwise more workers just contend on the same socket.
func WithAsyncWorkers(n int) AsyncOption {
	return func(a *AsyncSink) {
		if n > 0 {
			a.workers = n
		}
	}
}

// WithAsyncDropHandler routes drop notifications to fn. When unset,
// drops are silently swallowed (still best-effort, but invisible).
func WithAsyncDropHandler(fn AsyncDropHandler) AsyncOption {
	return func(a *AsyncSink) { a.onDrop = fn }
}

// WithAsyncRecordTimeout caps the inner Sink.Record call. Without it,
// a hung webhook can pin a worker indefinitely and the queue fills.
// Values <= 0 disable the timeout.
func WithAsyncRecordTimeout(d time.Duration) AsyncOption {
	return func(a *AsyncSink) { a.timeout = d }
}

// NewAsyncSink wraps inner with a buffered, worker-drained delivery
// path. The pool must be activated with Start; the caller controls the
// lifecycle so wiring code can defer Close cleanly.
func NewAsyncSink(inner Sink, opts ...AsyncOption) *AsyncSink {
	a := &AsyncSink{
		inner:   inner,
		workers: 1,
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.queue == nil {
		a.queue = make(chan *Event, DefaultAsyncBufferSize)
	}
	return a
}

// NewBatchAsyncSink is like [NewAsyncSink] but the worker drains up to
// batchSize events per queue-receive and calls [BatchSink.RecordBatch]
// instead of per-event Record — collapsing N single-row INSERTs into one
// transaction and cutting per-event SQLite overhead by 10-50x at moderate
// QPS.
//
// batchSize <= 1 falls back to [DefaultBatchSize].
// queueLen <= 0 falls back to [DefaultAsyncBufferSize].
//
// Only the write path is batched; Get/Query are served synchronously from
// the inner sink exactly as with NewAsyncSink.
func NewBatchAsyncSink(inner BatchSink, batchSize int, queueLen int, opts ...AsyncOption) *AsyncSink {
	if batchSize <= 1 {
		batchSize = DefaultBatchSize
	}
	a := &AsyncSink{
		inner:     inner,
		workers:   1,
		batchSize: batchSize,
	}
	if queueLen > 0 {
		a.queue = make(chan *Event, queueLen)
	}
	for _, opt := range opts {
		opt(a)
	}
	if a.queue == nil {
		a.queue = make(chan *Event, DefaultAsyncBufferSize)
	}
	return a
}

// Start launches the worker pool. Idempotent — additional calls are
// no-ops so wiring code can defensively double-start.
func (a *AsyncSink) Start() {
	a.startedMu.Lock()
	defer a.startedMu.Unlock()
	if a.started {
		return
	}
	a.started = true
	for i := 0; i < a.workers; i++ {
		a.wg.Add(1)
		if a.batchSize > 1 {
			go a.batchWorker()
		} else {
			go a.worker()
		}
	}
}

func (a *AsyncSink) worker() {
	defer a.wg.Done()
	for e := range a.queue {
		a.deliver(e)
	}
}

func (a *AsyncSink) deliver(e *Event) {
	ctx := context.Background()
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	ctx, span := deliverSpanCtx(ctx, "audit.sink.deliver", e)
	defer span.End()
	span.SetAttributes(sinkTypeAttr(a.inner), attribute.String("audit.event_type", string(e.Type)))

	if err := a.inner.Record(ctx, e); err != nil {
		tracing.SetError(span, err)
		a.dropsInnerError.Add(1)
		if a.onDrop != nil {
			a.onDrop(e, err)
		}
	}
}

// batchWorker drains up to batchSize events per iteration. It blocks on the
// first event (so the goroutine sleeps when the queue is empty), then does
// non-blocking reads to coalesce any additional events that arrived
// concurrently. The resulting slice is handed to deliverBatch.
func (a *AsyncSink) batchWorker() {
	defer a.wg.Done()
	batch := make([]*Event, 0, a.batchSize)
	for {
		e, ok := <-a.queue
		if !ok {
			return
		}
		batch = append(batch, e)

		for len(batch) < a.batchSize {
			select {
			case e2, ok2 := <-a.queue:
				if !ok2 {
					if len(batch) > 0 {
						a.deliverBatch(batch)
					}
					return
				}
				batch = append(batch, e2)
			default:
				goto flush
			}
		}
	flush:
		a.deliverBatch(batch)
		batch = batch[:0]
	}
}

func (a *AsyncSink) deliverBatch(batch []*Event) {
	ctx := context.Background()
	if a.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.timeout)
		defer cancel()
	}
	bs, ok := a.inner.(BatchSink)
	if !ok || len(batch) == 1 {
		for _, e := range batch {
			a.deliver(e)
		}
		return
	}
	// A batch can carry events from several unrelated requests; parenting
	// on the first event's trace is a best-effort heuristic (still correct
	// when the batch is single-trace, which dominates at low-to-moderate
	// QPS) rather than an attempt to model a genuine multi-parent span.
	ctx, span := deliverSpanCtx(ctx, "audit.sink.deliver_batch", batch[0])
	defer span.End()
	span.SetAttributes(sinkTypeAttr(a.inner), attribute.Int("audit.batch_size", len(batch)))

	if err := bs.RecordBatch(ctx, batch); err != nil {
		tracing.SetError(span, err)
		a.dropsInnerError.Add(int64(len(batch)))
		if a.onDrop != nil {
			for _, e := range batch {
				a.onDrop(e, err)
			}
		}
	}
}

// Record enqueues e for background delivery and returns nil. The
// request-path caller never sees a propagated error; drops are reported
// only via the AsyncDropHandler.
//
// The supplied ctx is intentionally NOT forwarded to the worker: the
// request goroutine often returns before delivery, and a cancelled ctx
// would abort the inner Sink.Record. Trace IDs ride on the Event itself
// (TraceID / SpanID / ParentSpanID), so observability is preserved.
func (a *AsyncSink) Record(_ context.Context, e *Event) error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.closed {
		a.dropsClosed.Add(1)
		if a.onDrop != nil {
			a.onDrop(e, ErrAsyncSinkClosed)
		}
		return nil
	}
	select {
	case a.queue <- e:
		return nil
	default:
		a.dropsQueueFull.Add(1)
		if a.onDrop != nil {
			a.onDrop(e, ErrAsyncQueueFull)
		}
		return nil
	}
}

// Get delegates to the inner sink (read path is synchronous).
func (a *AsyncSink) Get(ctx context.Context, id string) (*Event, error) {
	return a.inner.Get(ctx, id)
}

// Query delegates to the inner sink (read path is synchronous).
func (a *AsyncSink) Query(ctx context.Context, q Query) ([]*Event, error) {
	return a.inner.Query(ctx, q)
}

// ErrFacetsUnsupported is returned by Facets when the wrapped Sink does
// not implement the optional FacetQuerier extension. Callers (the HTTP
// handler) translate this into a not-implemented response rather than a
// generic 500 so a filter UI can fall back to plain queries.
var ErrFacetsUnsupported = errors.New("audit: sink does not support facet aggregation")

// Facets delegates to the inner sink when it implements FacetQuerier
// (the read path is synchronous), mirroring Query. A wrapped sink without
// facet support yields ErrFacetsUnsupported so the capability stays
// optional end-to-end.
func (a *AsyncSink) Facets(ctx context.Context, q Query) (*Facets, error) {
	fq, ok := a.inner.(FacetQuerier)
	if !ok {
		return nil, ErrFacetsUnsupported
	}
	return fq.Facets(ctx, q)
}

// LastHash delegates to the inner sink when it implements the optional
// ChainTip extension, mirroring Facets — this is a synchronous read of
// the persisted chain head, so it bypasses the async write queue. An
// inner sink without ChainTip yields genesis ("") so the chain seeds
// fresh rather than failing the resume.
func (a *AsyncSink) LastHash(ctx context.Context) (string, error) {
	ct, ok := a.inner.(ChainTip)
	if !ok {
		return "", nil
	}
	return ct.LastHash(ctx)
}

// Close stops accepting new events and drains the in-flight queue.
// Returns nil when the queue empties, or ctx.Err() if the supplied
// deadline expires first. Idempotent.
func (a *AsyncSink) Close(ctx context.Context) error {
	a.closeOnce.Do(func() {
		a.mu.Lock()
		a.closed = true
		// Closing the queue is safe here: holding the write lock
		// guarantees no Record call is in the middle of a send.
		close(a.queue)
		a.mu.Unlock()
	})
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Pending returns the current queue depth — useful for metrics gauges.
func (a *AsyncSink) Pending() int { return len(a.queue) }

// Capacity returns the configured buffer size.
func (a *AsyncSink) Capacity() int { return cap(a.queue) }

// DropsQueueFull is the monotonic count of events dropped because
// the buffer was full when Record was called. A growing counter
// means the inner sink can't keep up — increase buffer / workers,
// or look upstream for an event-storm.
func (a *AsyncSink) DropsQueueFull() int64 { return a.dropsQueueFull.Load() }

// DropsClosed is the monotonic count of events dropped because
// Record was called after Close. A non-zero counter typically only
// surfaces during a fleet restart; persistent growth means an SDK
// caller is missing a shutdown ordering hook.
func (a *AsyncSink) DropsClosed() int64 { return a.dropsClosed.Load() }

// DropsInnerError is the monotonic count of events the worker
// successfully dequeued but the inner sink rejected (network error,
// HTTP 4xx, validation failure). Inspect via the AsyncDropHandler
// for the raw error.
func (a *AsyncSink) DropsInnerError() int64 { return a.dropsInnerError.Load() }
