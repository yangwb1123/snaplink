package webhook

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// DefaultDeliveryTimeout bounds a single webhook POST.
const DefaultDeliveryTimeout = 10 * time.Second

// Outcome labels for MetricFunc. Bounded cardinality by construction (three
// fixed values), mirroring protocols/caep's outcome-label discipline.
const (
	OutcomeDelivered    = "delivered"
	OutcomeFailed       = "failed"
	OutcomeDeadLettered = "dead_lettered"
)

// MetricFunc records one delivery outcome. Wired by cmd to a Prometheus
// counter; nil = no metric. Mirrors protocols/caep.MetricFunc.
type MetricFunc func(outcome string)

// Logger is the minimal logging surface the Engine needs. Satisfied by
// spi.Logger; kept local so this package depends only on platform/audit,
// mirroring protocols/caep.Logger.
type Logger interface {
	Error(msg string, args ...any)
}

// EventWebhookDeliveryFailed is the internal audit event recorded (when a
// failure Recorder is wired) when a subscription's delivery exhausts every
// retry and lands in the dead-letter queue. Mirrors
// protocols/caep.EventCAEPBroadcastFailed — an operator signal, not part of
// the outbound event vocabulary this engine forwards.
const EventWebhookDeliveryFailed audit.EventType = "webhook_delivery_failed"

// Engine is the generic event/webhook egress engine: composed into the
// audit pipeline as an audit.Sink (via sso.WithWebhookEngine, the same
// AddSink/MultiSink seam protocols/caep.Transmitter uses), it fans every
// recorded event out to whichever registered EventSubscriptions match the
// event's Type, signs each outbound payload with that subscription's own
// HMAC secret, retries transient failures with jittered exponential
// backoff, and dead-letters a delivery that exhausts its retry budget.
//
// Zero registered subscriptions is the default state — Record is then a
// cheap no-match no-op with no outbound POST, no goroutine, byte-identical
// to a build without this feature.
type Engine struct {
	subs SubscriptionStore
	dlq  DeadLetterStore

	client              *http.Client
	timeout             time.Duration
	retryMaxAttempts    int
	retryInitialBackoff time.Duration
	retryMaxBackoff     time.Duration

	metric   MetricFunc
	logger   Logger
	recorder *audit.Recorder

	deliveryMu sync.RWMutex
	closed     bool
	wg         sync.WaitGroup
	ctx        context.Context
	cancel     context.CancelFunc
}

// Runtime is the stable management and audit surface shared by the native
// Engine and lifecycle-managed wrappers. Keeping the admin methods here lets
// a host replace a delivery generation without replacing its route closures
// or subscription/dead-letter stores.
type Runtime interface {
	audit.Sink
	Subscriptions() SubscriptionStore
	DeadLetters() DeadLetterStore
	Replay(context.Context, string) (DeadLetterEntry, error)
}

// Option configures an Engine at construction.
type Option func(*Engine)

// WithHTTPClient injects a custom *http.Client shared across every
// delivery (connection reuse). A nil client is ignored.
func WithHTTPClient(c *http.Client) Option {
	return func(e *Engine) {
		if c != nil {
			e.client = c
		}
	}
}

// WithDeliveryTimeout overrides the per-POST timeout (DefaultDeliveryTimeout).
// Values <= 0 are ignored.
func WithDeliveryTimeout(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.timeout = d
		}
	}
}

// WithDeliveryRetry caps TOTAL attempts per delivery (including the first)
// and tunes the jittered exponential backoff between them — the Engine
// delegates the actual retry loop to an auditsink.RetryingSink built per
// delivery, so these knobs mirror that package's. Non-positive values keep
// the auditsink defaults.
func WithDeliveryRetry(maxAttempts int, initialBackoff, maxBackoff time.Duration) Option {
	return func(e *Engine) {
		if maxAttempts > 0 {
			e.retryMaxAttempts = maxAttempts
		}
		if initialBackoff > 0 {
			e.retryInitialBackoff = initialBackoff
		}
		if maxBackoff > 0 {
			e.retryMaxBackoff = maxBackoff
		}
	}
}

// WithMetric wires the delivery-outcome counter.
func WithMetric(fn MetricFunc) Option { return func(e *Engine) { e.metric = fn } }

// WithLogger wires error logging. nil ⇒ silent.
func WithLogger(l Logger) Option { return func(e *Engine) { e.logger = l } }

// WithFailureRecorder wires the audit Recorder the Engine writes
// EventWebhookDeliveryFailed events to on dead-letter. nil (the default)
// leaves failures logged/metric'd only.
func WithFailureRecorder(r *audit.Recorder) Option { return func(e *Engine) { e.recorder = r } }

// NewEngine builds an Engine. subs is required for Record to do anything;
// dlq is required for exhausted deliveries to be queryable/replayable.
// Either may be nil for a degraded-but-safe engine: nil subs ⇒ Record is a
// no-op; nil dlq ⇒ exhausted deliveries are logged/metric'd only, never
// retained.
func NewEngine(subs SubscriptionStore, dlq DeadLetterStore, opts ...Option) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	e := &Engine{
		subs: subs,
		dlq:  dlq,
		// Redirect-follow disabled: an admin-registered subscription URL
		// that later 302s (compromised, or malicious after passing
		// validateHTTPSURL's shape check) would otherwise bypass the
		// https-only gate — the same SSRF-via-redirect class already closed
		// for CAEP (protocols/caep/broadcaster.go) and CIBA push
		// (protocols/oauth/handle_ciba.go). Treat the stored URL as
		// authoritative; a 3xx response fails delivery like any other
		// non-2xx status and feeds the existing retry/dead-letter path.
		client: &http.Client{
			Timeout:       DefaultDeliveryTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		timeout:             DefaultDeliveryTimeout,
		retryMaxAttempts:    audit.DefaultRetryMaxAttempts,
		retryInitialBackoff: audit.DefaultRetryInitialBackoff,
		retryMaxBackoff:     audit.DefaultRetryMaxBackoff,
		ctx:                 ctx,
		cancel:              cancel,
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Subscriptions returns the wired SubscriptionStore (nil when unset) — the
// admin handlers' read/write surface.
func (e *Engine) Subscriptions() SubscriptionStore { return e.subs }

// DeadLetters returns the wired DeadLetterStore (nil when unset) — the
// admin handlers' inspection surface.
func (e *Engine) DeadLetters() DeadLetterStore { return e.dlq }

// Record implements audit.Sink. It never blocks the caller on network I/O:
// matching is a cheap local store read, then each matched delivery runs in
// its own supervised goroutine. Always returns nil so it never disturbs a
// MultiSink's other sinks — the engine is a fan-out tap, not the audit
// system of record.
func (e *Engine) Record(ctx context.Context, ev *audit.Event) error {
	if e == nil || e.subs == nil || ev == nil {
		return nil
	}
	subs, err := e.subs.List(ctx)
	if err != nil || len(subs) == 0 {
		return nil
	}
	e.deliveryMu.RLock()
	defer e.deliveryMu.RUnlock()
	if e.closed {
		return nil
	}
	evCopy := *ev
	for _, sub := range subs {
		if !sub.Matches(ev.Type) {
			continue
		}
		e.wg.Add(1)
		go e.deliver(sub, evCopy)
	}
	return nil
}

// Get implements audit.Sink — write-only. The engine stores nothing itself;
// the dead-letter queue is inspected via DeadLetters(), not this read path.
func (e *Engine) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Query implements audit.Sink — write-only.
func (e *Engine) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Close cancels the Engine's delivery context — aborting any in-flight POST
// immediately (via the request's own context, same as an http.Client
// timeout firing mid-request) and short-circuiting future retry attempts —
// then waits for every in-flight deliver goroutine to observe the
// cancellation and return, so a shutting-down server doesn't abandon
// goroutines. Bounded by ctx: a slow drain past its deadline returns
// ctx.Err() rather than hanging Shutdown indefinitely. Idempotent (cancel is
// safe to call more than once).
func (e *Engine) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.deliveryMu.Lock()
	e.closed = true
	e.cancel()
	e.deliveryMu.Unlock()
	return e.waitDeliveries(ctx)
}

// CloseGraceful stops new deliveries, waits for already accepted deliveries
// to finish, and only then cancels the engine context. Lifecycle managers use
// this after request leases drain so an audit exporter replacement does not
// discard an in-flight webhook merely because its generation retired.
func (e *Engine) CloseGraceful(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.deliveryMu.Lock()
	e.closed = true
	e.deliveryMu.Unlock()
	if err := e.waitDeliveries(ctx); err != nil {
		e.cancel()
		return err
	}
	e.cancel()
	return nil
}

func (e *Engine) waitDeliveries(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	done := make(chan struct{})
	go func() { e.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// compile-time guard: an Engine is an audit.Sink.
var _ audit.Sink = (*Engine)(nil)
var _ Runtime = (*Engine)(nil)
