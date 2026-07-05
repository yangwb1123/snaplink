package userlifecycle

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestValidateTransition_LegalMoves(t *testing.T) {
	legal := []struct{ from, to State }{
		{StateNone, StateInvited},
		{StateNone, StateActive},
		{StateInvited, StateActive},
		{StateInvited, StateArchived},
		{StateActive, StateSuspended},
		{StateActive, StateInactive},
		{StateActive, StateArchived},
		{StateSuspended, StateActive},
		{StateSuspended, StateArchived},
		{StateInactive, StateActive},
		{StateInactive, StateArchived},
		{StateArchived, StateActive},
		{StateArchived, StatePurged},
	}
	for _, c := range legal {
		if err := ValidateTransition(c.from, c.to); err != nil {
			t.Errorf("ValidateTransition(%q,%q) = %v, want nil (legal)", c.from, c.to, err)
		}
		if !CanTransition(c.from, c.to) {
			t.Errorf("CanTransition(%q,%q) = false, want true", c.from, c.to)
		}
	}
}

func TestValidateTransition_IllegalMoves(t *testing.T) {
	// Representative illegal edges, each expecting ErrIllegalTransition.
	illegal := []struct{ from, to State }{
		{StateActive, StateInvited},     // can't re-invite an active account
		{StateActive, StatePurged},      // must archive before purge
		{StatePurged, StateActive},      // terminal: no exit
		{StatePurged, StateArchived},    // terminal
		{StateInactive, StateSuspended}, // not adjacent
		{StateSuspended, StateInactive}, // not adjacent
		{StateActive, StateActive},      // no-op is not a transition
	}
	for _, c := range illegal {
		if err := ValidateTransition(c.from, c.to); !errors.Is(err, ErrIllegalTransition) {
			t.Errorf("ValidateTransition(%q,%q) = %v, want ErrIllegalTransition", c.from, c.to, err)
		}
		if CanTransition(c.from, c.to) {
			t.Errorf("CanTransition(%q,%q) = true, want false", c.from, c.to)
		}
	}
}

func TestValidateTransition_UnknownState(t *testing.T) {
	cases := []struct{ from, to State }{
		{State("bogus"), StateActive},
		{StateActive, State("bogus")},
		{StateActive, StateNone}, // StateNone is never a valid target
	}
	for _, c := range cases {
		if err := ValidateTransition(c.from, c.to); !errors.Is(err, ErrUnknownState) {
			t.Errorf("ValidateTransition(%q,%q) = %v, want ErrUnknownState", c.from, c.to, err)
		}
	}
}

func TestAllowedTransitions_SortedAndTerminal(t *testing.T) {
	got := AllowedTransitions(StateActive)
	want := []State{StateArchived, StateInactive, StateSuspended} // sorted
	if !slices.Equal(got, want) {
		t.Errorf("AllowedTransitions(active) = %v, want %v", got, want)
	}
	if got := AllowedTransitions(StatePurged); len(got) != 0 {
		t.Errorf("AllowedTransitions(purged) = %v, want empty (terminal)", got)
	}
	// Never nil, so it JSON-encodes as [].
	if AllowedTransitions(StatePurged) == nil {
		t.Error("AllowedTransitions returned nil; want non-nil empty slice")
	}
}

func TestStateValid(t *testing.T) {
	for _, s := range []State{StateInvited, StateActive, StateSuspended, StateInactive, StateArchived, StatePurged} {
		if !s.Valid() {
			t.Errorf("State(%q).Valid() = false, want true", s)
		}
	}
	for _, s := range []State{StateNone, State("nope")} {
		if s.Valid() {
			t.Errorf("State(%q).Valid() = true, want false", s)
		}
	}
}

func TestNewTransition(t *testing.T) {
	at := time.Unix(1700000000, 0).UTC()
	tr := NewTransition(StateActive, StateInactive, "dormant", "admin-7", at)
	if tr.From != StateActive || tr.To != StateInactive || tr.Reason != "dormant" ||
		tr.Actor != "admin-7" || !tr.At.Equal(at) {
		t.Errorf("NewTransition produced %+v", tr)
	}
}
