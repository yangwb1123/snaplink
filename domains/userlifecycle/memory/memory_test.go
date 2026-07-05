package memory

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/userlifecycle"
)

func TestGet_MissingRecordIsDefaultActive(t *testing.T) {
	s := New()
	rec, err := s.Get(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.State != userlifecycle.DefaultState {
		t.Errorf("missing record state = %q, want %q (implicit default)", rec.State, userlifecycle.DefaultState)
	}
	if len(rec.History) != 0 {
		t.Errorf("missing record history = %v, want empty", rec.History)
	}
}

func TestAppend_TransitionFromImplicitDefault(t *testing.T) {
	s := New()
	ctx := context.Background()
	// A user with no record is implicitly ACTIVE, so ACTIVE->SUSPENDED must
	// apply against the implicit state even though no record exists yet.
	tr := userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateSuspended, "hold", "admin-1", time.Now())
	if err := s.Append(ctx, "u1", tr); err != nil {
		t.Fatalf("Append: %v", err)
	}
	rec, _ := s.Get(ctx, "u1")
	if rec.State != userlifecycle.StateSuspended {
		t.Errorf("state = %q, want suspended", rec.State)
	}
	if len(rec.History) != 1 || rec.History[0].To != userlifecycle.StateSuspended {
		t.Errorf("history = %+v, want one suspend transition", rec.History)
	}
	if rec.UpdatedAt.IsZero() {
		t.Error("UpdatedAt not stamped")
	}
}

func TestAppend_SeedRequiresNoRecord(t *testing.T) {
	s := New()
	ctx := context.Background()
	seed := userlifecycle.NewTransition(userlifecycle.StateNone, userlifecycle.StateInvited, "", "system", time.Now())
	if err := s.Append(ctx, "u1", seed); err != nil {
		t.Fatalf("seed Append: %v", err)
	}
	rec, _ := s.Get(ctx, "u1")
	if rec.State != userlifecycle.StateInvited {
		t.Errorf("seeded state = %q, want invited", rec.State)
	}
	// A second seed must conflict — the record already exists.
	if err := s.Append(ctx, "u1", seed); !errors.Is(err, userlifecycle.ErrStateConflict) {
		t.Errorf("re-seed = %v, want ErrStateConflict", err)
	}
	// Invited -> Active is legal and should now apply from the seeded state.
	accept := userlifecycle.NewTransition(userlifecycle.StateInvited, userlifecycle.StateActive, "accepted", "u1", time.Now())
	if err := s.Append(ctx, "u1", accept); err != nil {
		t.Fatalf("accept Append: %v", err)
	}
	rec, _ = s.Get(ctx, "u1")
	if rec.State != userlifecycle.StateActive || len(rec.History) != 2 {
		t.Errorf("after accept: state=%q history=%d, want active / 2", rec.State, len(rec.History))
	}
}

func TestAppend_StaleFromConflicts(t *testing.T) {
	s := New()
	ctx := context.Background()
	// current is implicitly ACTIVE; a transition claiming from=SUSPENDED is stale.
	stale := userlifecycle.NewTransition(userlifecycle.StateSuspended, userlifecycle.StateActive, "", "admin", time.Now())
	if err := s.Append(ctx, "u1", stale); !errors.Is(err, userlifecycle.ErrStateConflict) {
		t.Errorf("stale Append = %v, want ErrStateConflict", err)
	}
}

func TestGet_ReturnsCopy(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.Append(ctx, "u1", userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "sys", time.Now()))
	rec, _ := s.Get(ctx, "u1")
	rec.History = append(rec.History, userlifecycle.Transition{To: userlifecycle.StatePurged})
	rec.State = userlifecycle.StatePurged
	fresh, _ := s.Get(ctx, "u1")
	if fresh.State != userlifecycle.StateInactive || len(fresh.History) != 1 {
		t.Errorf("mutating the returned record leaked into the store: %+v", fresh)
	}
}

func TestListByState(t *testing.T) {
	s := New()
	ctx := context.Background()
	_ = s.Append(ctx, "a", userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "sys", time.Now()))
	_ = s.Append(ctx, "b", userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "sys", time.Now()))
	_ = s.Append(ctx, "c", userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateSuspended, "", "sys", time.Now()))
	got, err := s.ListByState(ctx, userlifecycle.StateInactive)
	if err != nil {
		t.Fatalf("ListByState: %v", err)
	}
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("ListByState(inactive) = %v, want [a b] sorted", got)
	}
	// Implicitly-active users (no record) are never listed.
	if got, _ := s.ListByState(ctx, userlifecycle.StateActive); len(got) != 0 {
		t.Errorf("ListByState(active) = %v, want empty (implicit-active users hold no record)", got)
	}
}

func TestActivityTracker(t *testing.T) {
	tr := NewActivityTracker()
	ctx := context.Background()
	// Unknown user -> zero.
	if got, _ := tr.LastActive(ctx, "u1"); !got.IsZero() {
		t.Errorf("LastActive(unknown) = %v, want zero", got)
	}
	early := time.Unix(1000, 0).UTC()
	late := time.Unix(2000, 0).UTC()
	tr.TouchAt("u1", late)
	tr.TouchAt("u1", early) // older must not regress the stored value
	got, _ := tr.LastActive(ctx, "u1")
	if !got.Equal(late) {
		t.Errorf("LastActive = %v, want %v (newest wins)", got, late)
	}
	// Empty id / zero time are ignored.
	tr.TouchAt("", late)
	tr.TouchAt("u2", time.Time{})
	if got, _ := tr.LastActive(ctx, "u2"); !got.IsZero() {
		t.Errorf("LastActive(u2) = %v, want zero (zero-time touch ignored)", got)
	}
}
