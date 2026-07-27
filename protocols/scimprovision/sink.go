package scimprovision

import (
	"context"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/webhook"
	"github.com/yangwb1123/snaplink/shared/core"
)

// DefaultEventTypes is the FIXED vocabulary this Sink reacts to — see
// doc.go's "vocabulary is fixed" note for why this is not operator-
// configurable the way platform/lifecycle/webhook's subscriptions are.
var DefaultEventTypes = []audit.EventType{
	audit.EventAdminUserCreated,
	audit.EventAdminUserUpdated,
	audit.EventAdminUserDeleted,
	audit.EventAdminUserEmailChanged,
	audit.EventAdminUserLifecycleChanged,
	audit.EventAdminRoleAdded,
	audit.EventAdminRoleUpdated,
	audit.EventAdminRoleRemoved,
}

// EventSCIMProvisionFailed is the internal audit event recorded (when a
// failure Recorder is wired) when a push exhausts every retry and lands in
// the dead-letter queue. Mirrors webhook.EventWebhookDeliveryFailed /
// protocols/caep.EventCAEPBroadcastFailed — an operator signal, not part of
// the vocabulary this Sink consumes.
const EventSCIMProvisionFailed audit.EventType = "scim_provision_failed"

// MetricFunc records one delivery outcome. Mirrors webhook.MetricFunc.
type MetricFunc func(outcome string)

// Outcome labels for MetricFunc — mirrors webhook.Outcome{Delivered,Failed,DeadLettered}.
const (
	OutcomeDelivered    = "delivered"
	OutcomeFailed       = "failed"
	OutcomeDeadLettered = "dead_lettered"
)

// Logger is the minimal logging surface the Sink needs. Satisfied by
// spi.Logger; kept local so this package depends on nothing beyond
// platform/audit, mirroring webhook.Logger / protocols/caep.Logger.
type Logger interface {
	Error(msg string, args ...any)
}

// Sink is the audit.Sink that fans matching user/group lifecycle events out
// to a configured SCIMProvisioner. Compose via NewSink; wire with
// sso.WithSCIMProvisioner (the same AddSink/MultiSink seam
// platform/lifecycle/webhook.Engine and protocols/caep.Transmitter use).
//
// A nil provisioner makes every method a no-op — Record returns immediately
// without matching, so an unwired Sink is safe to reference but never used
// (mirrors webhook.Engine's nil-subs no-op discipline).
type Sink struct {
	provisioner   SCIMProvisioner
	users         core.UserProvider
	perms         permissions.Provider
	groupClientID string

	dlq webhook.DeadLetterStore

	retryMaxAttempts    int
	retryInitialBackoff time.Duration
	retryMaxBackoff     time.Duration

	metric   MetricFunc
	logger   Logger
	recorder *audit.Recorder

	wg     sync.WaitGroup
	ctx    context.Context
	cancel context.CancelFunc
}

// Option configures a Sink at construction.
type Option func(*Sink)

// WithDeadLetterStore wires the queryable/replayable exhausted-delivery
// store — reuses platform/lifecycle/webhook.DeadLetterStore (and its
// MemoryDeadLetterStore reference impl) rather than a parallel type. nil
// (the default) leaves exhausted deliveries logged/metric'd only.
func WithDeadLetterStore(dlq webhook.DeadLetterStore) Option {
	return func(s *Sink) { s.dlq = dlq }
}

// WithDeliveryRetry caps TOTAL attempts per delivery (including the first)
// and tunes the jittered exponential backoff between them, mirroring
// webhook.WithDeliveryRetry. Non-positive values keep the auditsink
// defaults.
func WithDeliveryRetry(maxAttempts int, initialBackoff, maxBackoff time.Duration) Option {
	return func(s *Sink) {
		if maxAttempts > 0 {
			s.retryMaxAttempts = maxAttempts
		}
		if initialBackoff > 0 {
			s.retryInitialBackoff = initialBackoff
		}
		if maxBackoff > 0 {
			s.retryMaxBackoff = maxBackoff
		}
	}
}

// WithMetric wires the delivery-outcome counter.
func WithMetric(fn MetricFunc) Option { return func(s *Sink) { s.metric = fn } }

// WithLogger wires error logging. nil ⇒ silent.
func WithLogger(l Logger) Option { return func(s *Sink) { s.logger = l } }

// WithFailureRecorder wires the audit Recorder the Sink writes
// EventSCIMProvisionFailed events to on dead-letter. nil (the default)
// leaves failures logged/metric'd only.
func WithFailureRecorder(r *audit.Recorder) Option { return func(s *Sink) { s.recorder = r } }

// NewSink builds a Sink over provisioner. users resolves the full current
// state of a user event's subject (the audit vocabulary carries only an id,
// not the full record — see deliver.go); perms + groupClientID do the same
// for group/role events and may be nil/"" when group provisioning isn't
// wanted (group events then become no-ops, matching how the inbound
// receiver's Groups surface is itself optional).
func NewSink(users core.UserProvider, perms permissions.Provider, groupClientID string, provisioner SCIMProvisioner, opts ...Option) *Sink {
	ctx, cancel := context.WithCancel(context.Background())
	s := &Sink{
		provisioner:         provisioner,
		users:               users,
		perms:               perms,
		groupClientID:       groupClientID,
		retryMaxAttempts:    audit.DefaultRetryMaxAttempts,
		retryInitialBackoff: audit.DefaultRetryInitialBackoff,
		retryMaxBackoff:     audit.DefaultRetryMaxBackoff,
		ctx:                 ctx,
		cancel:              cancel,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// DeadLetters returns the wired DeadLetterStore (nil when unset).
func (s *Sink) DeadLetters() webhook.DeadLetterStore { return s.dlq }

// matches reports whether t is in this Sink's fixed vocabulary.
func matches(t audit.EventType) bool {
	for _, want := range DefaultEventTypes {
		if want == t {
			return true
		}
	}
	return false
}

// Record implements audit.Sink. It never blocks the caller on network I/O:
// vocabulary matching is a cheap local comparison, then each matched event
// is translated + delivered in its own supervised goroutine. Always returns
// nil so it never disturbs a MultiSink's other sinks — this Sink is a
// fan-out tap, not the audit system of record.
func (s *Sink) Record(ctx context.Context, ev *audit.Event) error {
	if s == nil || s.provisioner == nil || ev == nil || !matches(ev.Type) {
		return nil
	}
	evCopy := *ev
	s.wg.Add(1)
	go s.deliver(evCopy)
	return nil
}

// Get implements audit.Sink — write-only.
func (s *Sink) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Query implements audit.Sink — write-only.
func (s *Sink) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Close cancels the Sink's delivery context — aborting in-flight HTTP calls
// and short-circuiting future retries — then waits for every in-flight
// deliver goroutine to return, mirroring webhook.Engine.Close.
func (s *Sink) Close(ctx context.Context) error {
	s.cancel()
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// compile-time guard: a Sink is an audit.Sink.
var _ audit.Sink = (*Sink)(nil)
