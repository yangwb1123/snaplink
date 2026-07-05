package userlifecycle

import (
	"sort"
	"time"
)

// legalTransitions is the authoritative state-transition table: for each state,
// the set of states it may move to directly. It is the single source of truth
// the admin transition endpoint validates against and the documentation in
// docs/error-codes.md / the admin API mirrors.
//
//	StateNone  (seed) -> INVITED | ACTIVE          (account provisioning)
//	INVITED           -> ACTIVE | ARCHIVED         (accept invite / rescind)
//	ACTIVE            -> SUSPENDED | INACTIVE | ARCHIVED
//	SUSPENDED         -> ACTIVE | ARCHIVED         (reinstate / terminate)
//	INACTIVE          -> ACTIVE | ARCHIVED         (reactivate / deprovision)
//	ARCHIVED          -> ACTIVE | PURGED           (restore / erase)
//	PURGED            -> (terminal — no transitions)
//
// StateNone is the seed pseudo-state: it is the only legal predecessor of an
// INITIAL state, so a brand-new account can be provisioned directly as INVITED
// (the invitation flow) or ACTIVE (immediate onboarding) without inventing a
// prior state. It is never a resting state and never a transition TARGET.
var legalTransitions = map[State]map[State]bool{
	StateNone:      {StateInvited: true, StateActive: true},
	StateInvited:   {StateActive: true, StateArchived: true},
	StateActive:    {StateSuspended: true, StateInactive: true, StateArchived: true},
	StateSuspended: {StateActive: true, StateArchived: true},
	StateInactive:  {StateActive: true, StateArchived: true},
	StateArchived:  {StateActive: true, StatePurged: true},
	StatePurged:    {},
}

// CanTransition reports whether moving directly from -> to is permitted by the
// transition table. It is a pure lookup — no I/O, safe to call anywhere.
func CanTransition(from, to State) bool {
	return legalTransitions[from][to]
}

// ValidateTransition returns nil when from -> to is a legal move, and a sentinel
// error otherwise: ErrUnknownState when either endpoint is not a recognized
// state (to == StateNone is never a valid target), ErrIllegalTransition when
// both are known states but the edge is not in the table. from == StateNone is
// accepted (a seed), so callers pass it deliberately for account provisioning.
func ValidateTransition(from, to State) error {
	if from != StateNone && !from.Valid() {
		return ErrUnknownState
	}
	if !to.Valid() {
		return ErrUnknownState
	}
	if !CanTransition(from, to) {
		return ErrIllegalTransition
	}
	return nil
}

// AllowedTransitions returns the states reachable from from in one legal move,
// sorted for a stable admin-API response. The StateNone seed edges are excluded
// (from is a concrete resting state here), and a terminal state yields an empty
// slice (never nil) so the JSON encodes as [] rather than null.
func AllowedTransitions(from State) []State {
	targets := legalTransitions[from]
	out := make([]State, 0, len(targets))
	for to := range targets {
		out = append(out, to)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// NewTransition builds a Transition value from the applied move. It is a thin
// constructor shared by the admin handler (actor = admin id) and the sweep
// (actor = ActorSystem) so both stamp the record identically.
func NewTransition(from, to State, reason, actor string, at time.Time) Transition {
	return Transition{From: from, To: to, Reason: reason, Actor: actor, At: at}
}
