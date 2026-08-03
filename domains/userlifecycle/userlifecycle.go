// Package userlifecycle models the operational lifecycle of a user account as
// an explicit, validated state machine layered ADDITIVELY on top of the
// existing core.User records.
//
// A user with no lifecycle record is implicitly ACTIVE — the state every
// account already predating this package is in. Authentication enforcement is
// opt-in with the Store: unwired callers retain their previous behavior, while
// wired callers use AllowsAuthentication as the shared state predicate.
//
// The state set (INVITED -> ACTIVE -> {SUSPENDED, INACTIVE} -> ARCHIVED ->
// PURGED) and the legal transitions between them live in transitions.go; the
// dormancy signal that feeds the ACTIVE -> INACTIVE step lives in dormancy.go;
// the optional, config-gated background sweep that advances dormant users lives
// in sweep.go. Every applied transition is recorded in the account's history so
// an operator (and an audit sink) can reconstruct "who moved this account to
// which state, when, and why".
//
// # Event-driven reactions (bus.go)
//
// LifecycleEventBus is the in-process complement to the EventAdminUserLifecycleChanged
// audit event RecordTransition already emits: an operator registers a Go
// function (bus.OnUserArchived(func(ctx, userID) error { ... }), or the
// generic On/OnAsync for any State) that runs synchronously or
// asynchronously the moment a user crosses into that state — no HTTP, no
// operator-configured destination, no new instrumentation in transitions.go
// or sweep.go.
//
// This is deliberately a DIFFERENT package concern from
// platform/lifecycle/webhook (studied before writing this): that package is
// generic OUTBOUND egress — "POST this event vocabulary to this
// operator-registered URL" — and already covers "notify an external system"
// for ANY audited event, lifecycle transitions included, via a subscription
// on EventAdminUserLifecycleChanged. What it does NOT cover is an in-process
// Go callback wired at compile/wiring time with direct access to this
// server's own SPIs (SessionManager, RefreshTokenSubjectIndex, ...) — that
// is the gap LifecycleEventBus closes. Both taps compose independently onto
// the SAME audit.Recorder via AddSink; neither depends on the other, and an
// operator may wire one, both, or neither.
package userlifecycle

import (
	"context"
	"errors"
	"time"
)

// State is one operational lifecycle state of a user account. The wire values
// are stable, lowercase strings so they can be persisted and surfaced on the
// admin API without a translation table.
type State string

const (
	// StateNone is the zero state: it denotes "no record yet" and is the only
	// legal predecessor of an INITIAL state (INVITED or ACTIVE). It is never a
	// resting state — a persisted record always carries a concrete State.
	StateNone State = ""
	// StateInvited is a provisioned-but-not-yet-accepted account (an invitation
	// was issued; the user has not completed first login). Entered by the
	// provisioning/invitation flow, not by transition from an active account.
	StateInvited State = "invited"
	// StateActive is a normal, usable account. It is the DefaultState: a user
	// with no lifecycle record is treated as active.
	StateActive State = "active"
	// StateSuspended is an administratively disabled account (policy hold,
	// investigation). Reversible back to ACTIVE.
	StateSuspended State = "suspended"
	// StateInactive is a dormant account flagged by dormancy detection — no
	// recent activity. Reversible back to ACTIVE (e.g. on next login).
	StateInactive State = "inactive"
	// StateArchived is a decommissioned account retained for audit/compliance
	// but no longer usable. Restorable to ACTIVE, or advanced to PURGED.
	StateArchived State = "archived"
	// StatePurged is the terminal state: the account's data has been erased.
	// No transition leaves it.
	StatePurged State = "purged"
)

// DefaultState is the implicit state of a user that has no lifecycle record —
// ACTIVE. This is the backward-compatibility anchor: every account predating
// this package reads as active, so a build that wires the store but never
// records a transition behaves identically to one without it.
const DefaultState = StateActive

// AllowsAuthentication reports whether a persisted lifecycle state may obtain
// or continue using end-user credentials. A missing record is mapped to
// DefaultState by Store.Get; StateNone is therefore invalid input here and is
// denied rather than becoming a latent fail-open for future store backends.
func AllowsAuthentication(state State) bool { return state == StateActive }

// ActorSystem is the Transition.Actor value the auto-deprovisioning sweep
// stamps on transitions it applies (as opposed to an admin's user id on
// operator-driven transitions).
const ActorSystem = "system"

// Valid reports whether s is a concrete, persistable state (not StateNone).
func (s State) Valid() bool {
	switch s {
	case StateInvited, StateActive, StateSuspended, StateInactive, StateArchived, StatePurged:
		return true
	default:
		return false
	}
}

// Transition is one recorded move between lifecycle states. From is the state
// the account was in before the move (StateNone for an initial seed); To is the
// state it entered. Actor is the admin user id that requested it, or
// ActorSystem for a sweep-applied transition. Reason is an optional
// operator-supplied justification (audit evidence).
type Transition struct {
	From   State     `json:"from"`
	To     State     `json:"to"`
	Reason string    `json:"reason,omitempty"`
	Actor  string    `json:"actor,omitempty"`
	At     time.Time `json:"at"`
}

// Record is a user's current lifecycle state plus the ordered history of every
// transition applied to the account. History is append-only, oldest first.
type Record struct {
	UserID    string       `json:"user_id"`
	State     State        `json:"state"`
	History   []Transition `json:"history,omitempty"`
	UpdatedAt time.Time    `json:"updated_at,omitzero"`
}

// Store persists per-user lifecycle state + history. The in-process reference
// implementation lives in userlifecycle/memory; the stock shared durable
// adapter lives in infrastructure/userlifecyclepostgres. When no Store is
// wired the lifecycle surface is simply absent — byte-identical to a build
// without the feature.
type Store interface {
	// Get returns the lifecycle record for userID. A user with no stored record
	// is returned as {State: DefaultState} with empty history — NEVER an error —
	// so callers can treat "never recorded" and "explicitly active" alike.
	Get(ctx context.Context, userID string) (Record, error)

	// Append atomically applies t to userID's record: it verifies t.From is the
	// account's current state (DefaultState when no record exists yet), sets the
	// current state to t.To, and appends t to the history. A seed transition
	// (t.From == StateNone) requires that NO record exists yet. Returns
	// ErrStateConflict when t.From does not match the live state — the caller
	// read a stale value and MUST re-read before retrying. Append does NOT check
	// the legal-transition table; callers validate with ValidateTransition
	// first (the store enforces atomicity + optimistic concurrency, the domain
	// enforces legality).
	Append(ctx context.Context, userID string, t Transition) error

	// ListByState returns the ids of users whose CURRENT stored state is state.
	// Users with no record (implicitly DefaultState) are NOT returned — the
	// sweep enumerates the full roster via core.UserProvider for the active set.
	// Order is unspecified.
	ListByState(ctx context.Context, state State) ([]string, error)
}

// StateReader is the optional hot-path projection implemented by stores that
// can read current state without materializing append-only history.
type StateReader interface {
	GetState(ctx context.Context, userID string) (State, error)
}

// ReadState uses the state-only projection when available and otherwise
// preserves compatibility with Store implementations that only expose Get.
func ReadState(ctx context.Context, store Store, userID string) (State, error) {
	if reader, ok := store.(StateReader); ok {
		return reader.GetState(ctx, userID)
	}
	record, err := store.Get(ctx, userID)
	return record.State, err
}

// TransitionObserver receives a successfully committed lifecycle transition.
// It cannot roll the state change back; observers therefore own their own error
// handling and should be safe to invoke more than once.
type TransitionObserver func(ctx context.Context, userID string, transition Transition)

type observedStore struct {
	Store
	observe TransitionObserver
}

// ObserveTransitions decorates store so every successful Append synchronously
// invokes observe before Append returns. Reads are forwarded unchanged. Nil
// inputs preserve the original store, keeping observation entirely opt-in.
func ObserveTransitions(store Store, observe TransitionObserver) Store {
	if store == nil || observe == nil {
		return store
	}
	return &observedStore{Store: store, observe: observe}
}

func (s *observedStore) Append(ctx context.Context, userID string, transition Transition) error {
	if err := s.Store.Append(ctx, userID, transition); err != nil {
		return err
	}
	s.observe(ctx, userID, transition)
	return nil
}

func (s *observedStore) GetState(ctx context.Context, userID string) (State, error) {
	return ReadState(ctx, s.Store, userID)
}

// Sentinel errors. The admin transition handler maps these to stable wire
// codes (see docs/error-codes.md): ErrIllegalTransition -> 400
// illegal_lifecycle_transition, ErrUnknownState -> 400 unknown_lifecycle_state,
// ErrStateConflict -> 409 lifecycle_state_conflict.
var (
	// ErrAuthenticationBlocked is returned by enforcement adapters when the
	// current lifecycle state is not permitted to authenticate, or when that
	// state cannot be read safely. Wire handlers collapse it to their existing
	// oracle-safe denial shape.
	ErrAuthenticationBlocked = errors.New("userlifecycle: authentication blocked")
	// ErrIllegalTransition is returned by ValidateTransition when To is not
	// reachable from From per the legal-transition table.
	ErrIllegalTransition = errors.New("userlifecycle: illegal state transition")
	// ErrUnknownState is returned by ValidateTransition when From or To is not a
	// recognized state value.
	ErrUnknownState = errors.New("userlifecycle: unknown state")
	// ErrStateConflict is returned by Store.Append when the transition's From
	// does not match the account's live state (a lost-update race).
	ErrStateConflict = errors.New("userlifecycle: state conflict")
)
