package userlifecycle

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/spi"
)

const defaultSyncReactionTimeout = 30 * time.Second

// ReactionFunc is an in-process handler invoked when a user transitions INTO
// a lifecycle State the caller registered interest in via
// LifecycleEventBus.On / OnAsync (or one of the OnUserX sugar methods).
// Unlike a platform/lifecycle/webhook subscription, a ReactionFunc runs
// IN-PROCESS: it can call straight into any Go SPI the composition root
// already has wired (core.SessionManager, oauth.RefreshTokenSubjectIndex,
// ...) with no serialization, no network hop, and no operator-configured
// destination URL.
type ReactionFunc func(ctx context.Context, userID string) error

// ReactionErrorFunc reports a ReactionFunc failure (including a recovered
// panic). Best-effort by design, mirroring audit.ErrorHandler — a broken
// reaction must never block the lifecycle transition that triggered it, nor
// disturb any other sink in the same audit.MultiSink fan-out.
type ReactionErrorFunc func(state State, userID string, err error)

// reactionMode controls whether a registered ReactionFunc blocks Record's
// caller (dispatchSync) or runs detached in its own goroutine (dispatchAsync).
type reactionMode int

const (
	dispatchSync reactionMode = iota
	dispatchAsync
)

type reaction struct {
	fn   ReactionFunc
	mode reactionMode
}

// BusOption configures a LifecycleEventBus at construction.
type BusOption func(*LifecycleEventBus)

// WithBusLogger wires error logging for failed reactions. nil (the default)
// is silent, matching every other optional Logger in this codebase.
func WithBusLogger(l spi.Logger) BusOption {
	return func(b *LifecycleEventBus) { b.logger = l }
}

// WithReactionErrorHandler routes ReactionFunc failures to fn in ADDITION to
// (not instead of) the logger, mirroring audit.WithErrorHandler.
func WithReactionErrorHandler(fn ReactionErrorFunc) BusOption {
	return func(b *LifecycleEventBus) { b.onError = fn }
}

// LifecycleEventBus is the in-process reaction mechanism for
// domains/userlifecycle: operators register Go-level handler functions that
// run SYNCHRONOUSLY (On) or ASYNCHRONOUSLY (OnAsync) whenever a user
// transitions into a specific lifecycle State — e.g.
// bus.OnUserArchived(func(ctx, userID) error { ... }). See the package doc
// (userlifecycle.go) for why this is a separate concern from
// platform/lifecycle/webhook's outbound HTTP delivery.
//
// A LifecycleEventBus is itself an audit.Sink — the SAME AddSink/MultiSink
// seam protocols/caep.Transmitter and platform/lifecycle/webhook.Engine tap
// into. Wiring it via Recorder.AddSink observes the SAME
// EventAdminUserLifecycleChanged event RecordTransition already emits for
// EVERY transition, admin- or sweep-driven alike (see transitions.go /
// sweep.go) — no new instrumentation point is needed at either call site.
//
// Zero registered reactions (the default) makes Record a cheap no-match
// no-op: a build that never calls On/OnAsync is byte-identical, behavior-
// wise, to one without this file.
type LifecycleEventBus struct {
	mu       sync.RWMutex
	handlers map[State][]reaction

	logger  spi.Logger
	onError ReactionErrorFunc

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewLifecycleEventBus builds a LifecycleEventBus. Always construct it this
// way (not a zero-value composite literal) — Close and OnAsync both depend
// on the background context set up here.
func NewLifecycleEventBus(opts ...BusOption) *LifecycleEventBus {
	ctx, cancel := context.WithCancel(context.Background())
	b := &LifecycleEventBus{handlers: make(map[State][]reaction), ctx: ctx, cancel: cancel}
	for _, opt := range opts {
		opt(b)
	}
	return b
}

// On registers fn to run SYNCHRONOUSLY, in the SAME goroutine as the Record
// call that observed the transition — i.e. it blocks whatever triggered the
// transition (the admin HTTP handler, or the auto-deprovisioning sweep loop)
// until fn returns. Use this for a fast, local, in-process reaction (e.g.
// destroying sessions) the caller can rely on having completed by the time
// the transition's own response/iteration returns. A nil fn or an
// unrecognized state is a no-op.
func (b *LifecycleEventBus) On(state State, fn ReactionFunc) {
	b.register(state, fn, dispatchSync)
}

// OnAsync registers fn to run in its OWN goroutine, detached from Record's
// caller: it never blocks the transition that triggered it, and it observes
// the LifecycleEventBus's own long-lived context (canceled by Close), NOT
// the possibly request-scoped ctx Record was called with — mirroring
// platform/lifecycle/webhook.Engine's delivery goroutines. Use this for a
// reaction with I/O or latency of its own (e.g. notifying an external
// system) that must not delay the lifecycle transition.
func (b *LifecycleEventBus) OnAsync(state State, fn ReactionFunc) {
	b.register(state, fn, dispatchAsync)
}

func (b *LifecycleEventBus) register(state State, fn ReactionFunc, mode reactionMode) {
	if b == nil || fn == nil || !state.Valid() {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.handlers == nil {
		b.handlers = make(map[State][]reaction)
	}
	b.handlers[state] = append(b.handlers[state], reaction{fn: fn, mode: mode})
}

// OnUserInvited registers fn for the INVITED state (see On).
func (b *LifecycleEventBus) OnUserInvited(fn ReactionFunc) { b.On(StateInvited, fn) }

// OnUserActivated registers fn for the ACTIVE state (see On) — fires on
// every entry into ACTIVE, including initial provisioning and a reinstated
// suspension or reactivated dormant account, not just first login.
func (b *LifecycleEventBus) OnUserActivated(fn ReactionFunc) { b.On(StateActive, fn) }

// OnUserSuspended registers fn for the SUSPENDED state (see On).
func (b *LifecycleEventBus) OnUserSuspended(fn ReactionFunc) { b.On(StateSuspended, fn) }

// OnUserInactive registers fn for the INACTIVE (dormant) state (see On) —
// e.g. to notify an external system when the auto-deprovisioning sweep (or
// an admin) flags an account dormant.
func (b *LifecycleEventBus) OnUserInactive(fn ReactionFunc) { b.On(StateInactive, fn) }

// OnUserArchived registers fn for the ARCHIVED state (see On) — the state
// protocols/lifecyclereactions.RevokeAccessOnArchive's reference reaction
// hooks.
func (b *LifecycleEventBus) OnUserArchived(fn ReactionFunc) { b.On(StateArchived, fn) }

// OnUserPurged registers fn for the terminal PURGED state (see On).
func (b *LifecycleEventBus) OnUserPurged(fn ReactionFunc) { b.On(StatePurged, fn) }

// Record implements audit.Sink: it observes EVERY audit event (whatever the
// Recorder's other sinks see too) and reacts ONLY to
// EventAdminUserLifecycleChanged, dispatching to every ReactionFunc
// registered for the event's to_state. Always returns nil — like
// platform/lifecycle/webhook.Engine and protocols/caep.Transmitter, a
// reaction failure (or an unrelated event, or zero registered reactions)
// must never disturb a MultiSink's other sinks or the Recorder's caller.
func (b *LifecycleEventBus) Record(ctx context.Context, ev *audit.Event) error {
	if b == nil || ev == nil || ev.Type != audit.EventAdminUserLifecycleChanged {
		return nil
	}
	userID := ev.Metadata[MetaTargetUser]
	to := State(ev.Metadata[MetaToState])
	if userID == "" || !to.Valid() {
		return nil
	}
	b.Dispatch(ctx, userID, to)
	return nil
}

// Dispatch invokes reactions for a committed transition without coupling the
// security side effect to the audit pipeline. Synchronous reactions receive a
// detached, bounded context: a disconnected admin client cannot cancel access
// revocation after the state commit, while a broken backend cannot hang the
// transition indefinitely. Reaction failures remain best-effort and are routed
// through the bus logger/error handler.
func (b *LifecycleEventBus) Dispatch(ctx context.Context, userID string, to State) {
	if b == nil || userID == "" || !to.Valid() {
		return
	}
	b.mu.RLock()
	matched := append([]reaction(nil), b.handlers[to]...)
	b.mu.RUnlock()
	base := context.Background()
	if ctx != nil {
		base = context.WithoutCancel(ctx)
	}
	syncCtx, cancel := context.WithTimeout(base, defaultSyncReactionTimeout)
	defer cancel()
	for _, r := range matched {
		if r.mode == dispatchAsync {
			b.wg.Add(1)
			go b.invokeAsync(to, userID, r.fn)
			continue
		}
		b.invoke(syncCtx, to, userID, r.fn)
	}
}

func (b *LifecycleEventBus) invokeAsync(state State, userID string, fn ReactionFunc) {
	defer b.wg.Done()
	b.invoke(b.ctx, state, userID, fn)
}

// invoke runs fn with panic containment — arbitrary operator-supplied
// reaction code must never crash the process (mirrors
// platform/lifecycle/webhook.Engine.deliver's recover).
func (b *LifecycleEventBus) invoke(ctx context.Context, state State, userID string, fn ReactionFunc) {
	defer func() {
		if r := recover(); r != nil {
			b.reportError(state, userID, fmt.Errorf("panic: %v", r))
		}
	}()
	if err := fn(ctx, userID); err != nil {
		b.reportError(state, userID, err)
	}
}

func (b *LifecycleEventBus) reportError(state State, userID string, err error) {
	if b.logger != nil {
		b.logger.Error("userlifecycle: reaction failed", "state", string(state), "user_id", userID, "error", err)
	}
	if b.onError != nil {
		b.onError(state, userID, err)
	}
}

// Get implements audit.Sink — write-only; the bus stores nothing itself.
func (b *LifecycleEventBus) Get(context.Context, string) (*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Query implements audit.Sink — write-only.
func (b *LifecycleEventBus) Query(context.Context, audit.Query) ([]*audit.Event, error) {
	return nil, audit.ErrSinkWriteOnly
}

// Close cancels the bus's async-dispatch context and waits for every
// in-flight OnAsync reaction to return, so a shutting-down server doesn't
// abandon goroutines (mirrors platform/lifecycle/webhook.Engine.Close).
// Bounded by ctx: a slow drain past its deadline returns ctx.Err() rather
// than hanging Shutdown indefinitely. Idempotent (cancel is safe to call
// more than once).
func (b *LifecycleEventBus) Close(ctx context.Context) error {
	b.cancel()
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// compile-time guard: a LifecycleEventBus is an audit.Sink.
var _ audit.Sink = (*LifecycleEventBus)(nil)
