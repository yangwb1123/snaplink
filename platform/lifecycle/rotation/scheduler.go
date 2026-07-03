package rotation

import (
	"context"
	"sync"
	"time"

	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/core/corecredential"
	"github.com/snaplink/sso/shared/spi"
)

// Scheduler defaults. The tick is the polling resolution (how late a due
// rotation can fire), NOT the rotation cadence — intervals are per-rotator.
const (
	DefaultSchedulerTick = time.Minute
	DefaultRetryBase     = time.Minute
	DefaultRetryMax      = 15 * time.Minute
)

// Scheduler event outcomes (Event.Outcome), bounded to four values so the
// audit/metric fan-out stays bounded-cardinality.
const (
	EventRotated      = "rotated"
	EventRotateFailed = "rotate_failed"
	EventRetired      = "retired"
	// EventCompromised: an off-schedule emergency rotation via Compromise —
	// the previous version was retired INSTANTLY (no overlap). Meta is the
	// fresh active version; Reason carries the operator justification.
	EventCompromised = "compromised"
)

// Event describes one scheduler action for the operator fan-out seam
// (WithEventHook) — the composition root maps these to audit events, the
// same OnRotate-callback pattern the signing-key rotation loop uses.
type Event struct {
	Type    corecredential.CredentialType
	Outcome string // EventRotated | EventRotateFailed | EventRetired | EventCompromised
	Meta    corecredential.CredentialMeta
	Err     error     // set on EventRotateFailed only
	NextDue time.Time // next attempt (retry backoff on failure)
	Reason  string    // operator justification; set on EventCompromised only
}

// Scheduler drives every Registry rotator: rotations fire when due, a
// failure retries with capped doubling backoff while the OLD credential
// keeps serving (the framework never leaves a class with zero usable
// credentials), and demoted versions retire when their overlap closes.
type Scheduler struct {
	reg      *Registry
	store    corecredential.CredentialStatusStore  // optional; fail-open governance metadata
	notifier corecredential.DependentPartyNotifier // never nil (NopDependentPartyNotifier default)
	logger   spi.Logger
	metrics  *metrics.Metrics // nil-safe observe helpers
	onEvent  func(Event)

	tick      time.Duration
	retryBase time.Duration
	retryMax  time.Duration

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// SchedulerOption configures a Scheduler at construction.
type SchedulerOption func(*Scheduler)

// WithStatusStore persists per-version governance metadata (active /
// retiring / retired transitions). Store failures are fail-open: the
// rotation itself already happened in the rotator's backend, so a metadata
// write error must not wedge the loop.
func WithStatusStore(store corecredential.CredentialStatusStore) SchedulerOption {
	return func(s *Scheduler) { s.store = store }
}

// WithNotifier wires the DependentPartyNotifier fired on every rotation AND
// compromise (JWKS-changed broadcast, SAML metadata-update signal, ...). Nil is
// ignored (the NopDependentPartyNotifier default stays). Notify is best-effort:
// its error is logged and never rolls back the already-completed rotation.
func WithNotifier(n corecredential.DependentPartyNotifier) SchedulerOption {
	return func(s *Scheduler) {
		if n != nil {
			s.notifier = n
		}
	}
}

// WithSchedulerTick overrides the due-check polling resolution.
func WithSchedulerTick(d time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if d > 0 {
			s.tick = d
		}
	}
}

// WithRetryBackoff overrides the failure-retry backoff (base doubled per
// consecutive failure, capped at maxDelay).
func WithRetryBackoff(base, maxDelay time.Duration) SchedulerOption {
	return func(s *Scheduler) {
		if base > 0 {
			s.retryBase = base
		}
		if maxDelay > 0 {
			s.retryMax = maxDelay
		}
	}
}

// WithEventHook fans scheduler events out to the operator (audit recorder,
// alerting). Called from the scheduler goroutine — must not block.
func WithEventHook(fn func(Event)) SchedulerOption {
	return func(s *Scheduler) { s.onEvent = fn }
}

// WithSchedulerMetrics wires the rotation counters + credential-age gauge.
func WithSchedulerMetrics(m *metrics.Metrics) SchedulerOption {
	return func(s *Scheduler) { s.metrics = m }
}

// WithSchedulerLogger overrides the default no-op logger.
func WithSchedulerLogger(l spi.Logger) SchedulerOption {
	return func(s *Scheduler) {
		if l != nil {
			s.logger = l
		}
	}
}

func NewScheduler(reg *Registry, opts ...SchedulerOption) *Scheduler {
	s := &Scheduler{
		reg:       reg,
		notifier:  corecredential.NopDependentPartyNotifier{},
		logger:    spi.NopLogger{},
		tick:      DefaultSchedulerTick,
		retryBase: DefaultRetryBase,
		retryMax:  DefaultRetryMax,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Inventory exposes the registry's governance snapshot (metadata only) so a
// Server wired with the scheduler can serve the admin inventory endpoint.
func (s *Scheduler) Inventory() []InventoryEntry { return s.reg.Inventory() }

// Start launches the ticker loop; the returned channel closes when the loop
// goroutine exits (mirrors the cmd retention schedulers so shutdown can wait
// on it). Calling Start on a running scheduler returns the existing channel.
func (s *Scheduler) Start(ctx context.Context) <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.done != nil {
		return s.done
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.run(runCtx, s.done)
	return s.done
}

// Stop cancels the loop and waits for it to exit. Idempotent; safe to call
// on a never-started scheduler.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	cancel, done := s.cancel, s.done
	s.cancel, s.done = nil, nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (s *Scheduler) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	s.seedStore(ctx)
	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			s.sweep(ctx, now)
		}
	}
}

// seedStore records the versions already installed at start so the status
// store reflects reality before the first rotation fires.
func (s *Scheduler) seedStore(ctx context.Context) {
	if s.store == nil {
		return
	}
	for _, m := range s.reg.activeMetas() {
		if err := s.store.Upsert(ctx, m); err != nil {
			s.logger.Error("credential status seed failed", "type", string(m.Type), "error", err)
		}
	}
}

// sweep is one scheduler pass: rotate everything due, close expired overlap
// windows, refresh the age gauge.
func (s *Scheduler) sweep(ctx context.Context, now time.Time) {
	for _, d := range s.reg.due(now) {
		s.rotateOne(ctx, d, now)
	}
	for _, m := range s.reg.retireDue(now) {
		s.markRetired(ctx, m)
	}
	s.publishAges(now)
}

func (s *Scheduler) rotateOne(ctx context.Context, d dueRotation, now time.Time) {
	meta, err := d.rotator.Rotate(ctx)
	if err != nil {
		failures, next := s.reg.applyFailure(d.credType, now, s.retryBase, s.retryMax)
		s.logger.Error("credential rotation failed — previous credential keeps serving",
			"type", string(d.credType), "consecutive_failures", failures, "error", err)
		s.metrics.ObserveCredentialRotation(string(d.credType), metrics.OutcomeFailure)
		s.emit(Event{Type: d.credType, Outcome: EventRotateFailed, Err: err, NextDue: next})
		return
	}
	demoted, next := s.reg.applySuccess(d.credType, meta, now)
	s.persistRotation(ctx, meta, demoted)
	s.metrics.ObserveCredentialRotation(string(d.credType), metrics.OutcomeSuccess)
	s.notify(ctx, d.rotator, meta, false, "")
	s.emit(Event{Type: d.credType, Outcome: EventRotated, Meta: meta, NextDue: next})
}

// notify fans a rotation/compromise out to the wired DependentPartyNotifier.
// The affected-dependent set is read from the rotator when it implements
// corecredential.DependencyReporter (else empty — nothing to notify). Fail-open:
// a notifier error is logged and swallowed, since the new secret is already
// installed and serving by the time this runs.
func (s *Scheduler) notify(ctx context.Context, rotator corecredential.CredentialRotator, meta corecredential.CredentialMeta, compromised bool, reason string) {
	var deps []corecredential.Dependency
	if dr, ok := rotator.(corecredential.DependencyReporter); ok {
		deps = dr.Dependents()
	}
	notice := corecredential.RotationNotice{
		Type:        meta.Type,
		NewMeta:     meta,
		Compromised: compromised,
		Reason:      reason,
		Dependents:  deps,
	}
	if err := s.notifier.Notify(ctx, notice); err != nil {
		s.logger.Error("dependent-party notification failed — rotation already completed",
			"type", string(meta.Type), "compromised", compromised, "error", err)
	}
}

func (s *Scheduler) persistRotation(ctx context.Context, meta corecredential.CredentialMeta, demoted *corecredential.CredentialMeta) {
	if s.store == nil {
		return
	}
	if err := s.store.Upsert(ctx, meta); err != nil {
		s.logger.Error("credential status upsert failed", "type", string(meta.Type), "error", err)
	}
	if demoted == nil {
		return
	}
	if err := s.store.Upsert(ctx, *demoted); err != nil {
		s.logger.Error("credential status demote failed", "type", string(demoted.Type), "error", err)
	}
}

func (s *Scheduler) markRetired(ctx context.Context, m corecredential.CredentialMeta) {
	if s.store != nil {
		if err := s.store.UpdateStatus(ctx, m.Type, m.ID, corecredential.CredentialStatusRetired); err != nil {
			s.logger.Error("credential retire status update failed", "type", string(m.Type), "error", err)
		}
	}
	s.emit(Event{Type: m.Type, Outcome: EventRetired, Meta: m})
}

func (s *Scheduler) publishAges(now time.Time) {
	if s.metrics == nil {
		return
	}
	for _, m := range s.reg.activeMetas() {
		s.metrics.SetCredentialAge(string(m.Type), now.Sub(m.CreatedAt).Seconds())
	}
}

func (s *Scheduler) emit(e Event) {
	if s.onEvent != nil {
		s.onEvent(e)
	}
}
