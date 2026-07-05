package userlifecycle_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/userlifecycle"
	"github.com/snaplink/sso/domains/userlifecycle/memory"
	"github.com/snaplink/sso/infrastructure/defaultimpl/memorystoreidentity"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

const day = 24 * time.Hour

// sweepFixture wires the real memory stores the sweep needs plus a fixed clock.
type sweepFixture struct {
	users     *memorystoreidentity.MemoryUserProvider
	lifecycle *memory.Store
	activity  *memory.ActivityTracker
	sink      *audit.MemorySink
	now       time.Time
}

func newSweepFixture(t *testing.T) *sweepFixture {
	t.Helper()
	f := &sweepFixture{
		users:     memorystoreidentity.NewMemoryUserProvider(),
		lifecycle: memory.New(),
		activity:  memory.NewActivityTracker(),
		sink:      audit.NewMemorySink(64),
		now:       time.Unix(1_700_000_000, 0).UTC(),
	}
	return f
}

func (f *sweepFixture) addUser(t *testing.T, id string, lastActive time.Time) {
	t.Helper()
	if err := f.users.CreateOrUpdate(context.Background(), &core.User{ID: id}); err != nil {
		t.Fatalf("create user %s: %v", id, err)
	}
	if !lastActive.IsZero() {
		f.activity.TouchAt(id, lastActive)
	}
}

func (f *sweepFixture) deps(cfg userlifecycle.DeprovisionConfig) userlifecycle.SweepDeps {
	return userlifecycle.SweepDeps{
		Users:      f.users,
		Lifecycle:  f.lifecycle,
		LastActive: f.activity,
		Auditor:    audit.New(f.sink),
		Now:        func() time.Time { return f.now },
		Config:     cfg,
	}
}

func (f *sweepFixture) state(t *testing.T, id string) userlifecycle.State {
	t.Helper()
	rec, err := f.lifecycle.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return rec.State
}

func TestSweepOnce_MovesDormantActiveToInactive(t *testing.T) {
	f := newSweepFixture(t)
	f.addUser(t, "dormant", f.now.Add(-40*day))
	f.addUser(t, "recent", f.now.Add(-2*day))
	f.addUser(t, "never", time.Time{}) // no activity signal -> never deprovisioned

	n, err := userlifecycle.SweepOnce(context.Background(), f.deps(userlifecycle.DeprovisionConfig{DormantAfter: 30 * day}))
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if n != 1 {
		t.Errorf("applied = %d, want 1", n)
	}
	if got := f.state(t, "dormant"); got != userlifecycle.StateInactive {
		t.Errorf("dormant user state = %q, want inactive", got)
	}
	if got := f.state(t, "recent"); got != userlifecycle.StateActive {
		t.Errorf("recent user state = %q, want active (unchanged)", got)
	}
	if got := f.state(t, "never"); got != userlifecycle.StateActive {
		t.Errorf("never-active user state = %q, want active (fail-safe: no signal)", got)
	}
	// The applied transition is audited exactly once, as a lifecycle-changed event.
	events, _ := f.sink.Query(context.Background(), audit.Query{})
	if len(events) != 1 || events[0].Type != audit.EventAdminUserLifecycleChanged {
		t.Errorf("audit events = %+v, want one admin_user_lifecycle_changed", events)
	}
	if events[0].ActorID != userlifecycle.ActorSystem {
		t.Errorf("audit actor = %q, want %q", events[0].ActorID, userlifecycle.ActorSystem)
	}
}

func TestSweepOnce_ArchivesLongDormantInactive(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	f.addUser(t, "u", f.now.Add(-100*day))
	// Seed the user as INACTIVE (as a prior sweep would have left them).
	if err := f.lifecycle.Append(ctx, "u",
		userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "sys", f.now.Add(-70*day))); err != nil {
		t.Fatalf("seed inactive: %v", err)
	}
	cfg := userlifecycle.DeprovisionConfig{DormantAfter: 30 * day, ArchiveAfter: 30 * day}
	if _, err := userlifecycle.SweepOnce(ctx, f.deps(cfg)); err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if got := f.state(t, "u"); got != userlifecycle.StateArchived {
		t.Errorf("state = %q, want archived (100d idle > 60d archive threshold)", got)
	}
}

func TestSweepOnce_InactiveNotArchivedWhenArchiveDisabled(t *testing.T) {
	f := newSweepFixture(t)
	ctx := context.Background()
	f.addUser(t, "u", f.now.Add(-100*day))
	_ = f.lifecycle.Append(ctx, "u",
		userlifecycle.NewTransition(userlifecycle.StateActive, userlifecycle.StateInactive, "", "sys", f.now.Add(-70*day)))
	// ArchiveAfter == 0 -> the sweep never advances INACTIVE further.
	n, err := userlifecycle.SweepOnce(ctx, f.deps(userlifecycle.DeprovisionConfig{DormantAfter: 30 * day}))
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if n != 0 || f.state(t, "u") != userlifecycle.StateInactive {
		t.Errorf("applied=%d state=%q, want 0 / inactive", n, f.state(t, "u"))
	}
}

func TestSweepOnce_OffByDefault(t *testing.T) {
	f := newSweepFixture(t)
	f.addUser(t, "dormant", f.now.Add(-999*day))
	// Zero-value config is OFF: DormantAfter <= 0.
	n, err := userlifecycle.SweepOnce(context.Background(), f.deps(userlifecycle.DeprovisionConfig{}))
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if n != 0 {
		t.Errorf("applied = %d, want 0 (OFF)", n)
	}
	if got := f.state(t, "dormant"); got != userlifecycle.StateActive {
		t.Errorf("state = %q, want active (sweep OFF must not touch anyone)", got)
	}
	if events, _ := f.sink.Query(context.Background(), audit.Query{}); len(events) != 0 {
		t.Errorf("audit events = %d, want 0 when OFF", len(events))
	}
}

func TestSweepOnce_MaxPerSweepCap(t *testing.T) {
	f := newSweepFixture(t)
	for _, id := range []string{"a", "b", "c", "d"} {
		f.addUser(t, id, f.now.Add(-40*day))
	}
	cfg := userlifecycle.DeprovisionConfig{DormantAfter: 30 * day, MaxPerSweep: 2}
	n, err := userlifecycle.SweepOnce(context.Background(), f.deps(cfg))
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	if n != 2 {
		t.Errorf("applied = %d, want 2 (capped by MaxPerSweep)", n)
	}
}
