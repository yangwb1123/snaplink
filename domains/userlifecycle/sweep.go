package userlifecycle

import (
	"context"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// Audit metadata keys carried by every EventAdminUserLifecycleChanged event so
// a single record answers "who moved which account from which state to which,
// and why" without a second lookup.
const (
	MetaTargetUser = "target_user"
	MetaFromState  = "from_state"
	MetaToState    = "to_state"
	MetaReason     = "reason"
)

// DeprovisionConfig gates the auto-deprovisioning sweep. The zero value is OFF:
// with DormantAfter == 0 the sweep is a no-op, so a build that never sets it
// behaves identically to one without the feature.
type DeprovisionConfig struct {
	// DormantAfter is how long an ACTIVE account may be idle (no activity per
	// the LastActiveSource) before the sweep moves it to INACTIVE. 0 disables
	// the whole sweep.
	DormantAfter time.Duration
	// ArchiveAfter is the ADDITIONAL idle time beyond DormantAfter before an
	// INACTIVE account is advanced to ARCHIVED (measured from last activity, so
	// the archive threshold is DormantAfter+ArchiveAfter). 0 leaves accounts in
	// INACTIVE indefinitely — the sweep never archives on its own.
	ArchiveAfter time.Duration
	// MaxPerSweep caps the number of transitions a single sweep applies
	// (a deprovisioning-storm guard, mirroring the bulk-revoke caps). 0 means
	// unlimited.
	MaxPerSweep int
}

// Enabled reports whether the sweep does any work. False (the default) makes
// SweepOnce a no-op.
func (c DeprovisionConfig) Enabled() bool { return c.DormantAfter > 0 }

// SweepDeps is everything SweepOnce needs. Users is the roster it walks (the
// full user set, since implicitly-ACTIVE users hold no lifecycle record);
// Lifecycle persists state + history; LastActive supplies the dormancy signal;
// Auditor + Logger are best-effort (nil-safe). Now defaults to time.Now.
type SweepDeps struct {
	Users      core.UserProvider
	Lifecycle  Store
	LastActive LastActiveSource
	Auditor    *audit.Recorder
	Logger     spi.Logger
	Now        func() time.Time
	Config     DeprovisionConfig
}

func (d SweepDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now().UTC()
}

// SweepOnce advances every dormant account one step through the lifecycle:
// ACTIVE -> INACTIVE past DormantAfter, and (when ArchiveAfter > 0) INACTIVE ->
// ARCHIVED past DormantAfter+ArchiveAfter. It returns the number of transitions
// applied. OFF (returns 0, nil) when the config is disabled or required deps
// are absent.
//
// Fail-safe by construction: a per-user read error, a missing activity signal,
// or an Append conflict is logged and SKIPPED — the sweep never advances an
// account on incomplete data and never aborts the whole run for one bad record.
func SweepOnce(ctx context.Context, d SweepDeps) (int, error) {
	if !d.Config.Enabled() || d.Users == nil || d.Lifecycle == nil || d.LastActive == nil {
		return 0, nil
	}
	users, err := d.Users.List(ctx)
	if err != nil {
		return 0, err
	}
	now := d.now()
	applied := 0
	for _, u := range users {
		if u == nil || u.ID == "" {
			continue
		}
		if d.Config.MaxPerSweep > 0 && applied >= d.Config.MaxPerSweep {
			break
		}
		if d.sweepUser(ctx, u.ID, now) {
			applied++
		}
	}
	return applied, nil
}

// sweepUser evaluates one account and applies at most one transition, returning
// whether it did. It reads the current state, the last-active signal, decides
// the next state, and (if any) applies it.
func (d SweepDeps) sweepUser(ctx context.Context, userID string, now time.Time) bool {
	rec, err := d.Lifecycle.Get(ctx, userID)
	if err != nil {
		d.logError("lifecycle sweep get failed", userID, err)
		return false
	}
	lastActive, err := d.LastActive.LastActive(ctx, userID)
	if err != nil {
		d.logError("lifecycle sweep last-active failed", userID, err)
		return false
	}
	next := d.nextState(rec.State, lastActive, now)
	if next == StateNone {
		return false
	}
	return d.apply(ctx, userID, rec.State, next, now)
}

// nextState returns the state the sweep should advance from -> to, or StateNone
// to leave the account untouched. Only ACTIVE (dormant) and INACTIVE
// (dormant beyond the archive threshold) are eligible; every other state is a
// resting/manual state the sweep never touches.
func (d SweepDeps) nextState(current State, lastActive, now time.Time) State {
	switch current {
	case StateActive:
		if IsDormant(lastActive, now, d.Config.DormantAfter) {
			return StateInactive
		}
	case StateInactive:
		if d.Config.ArchiveAfter > 0 &&
			IsDormant(lastActive, now, d.Config.DormantAfter+d.Config.ArchiveAfter) {
			return StateArchived
		}
	}
	return StateNone
}

// apply persists the from -> to transition (system actor) and audits it. A
// conflict (a concurrent admin transition) or store error is logged and skipped
// — the account is re-evaluated on the next sweep. Returns whether it persisted.
func (d SweepDeps) apply(ctx context.Context, userID string, from, to State, now time.Time) bool {
	t := NewTransition(from, to, "auto-deprovision: dormant", ActorSystem, now)
	if err := d.Lifecycle.Append(ctx, userID, t); err != nil {
		d.logError("lifecycle sweep append failed", userID, err)
		return false
	}
	RecordTransition(ctx, d.Auditor, userID, t)
	return true
}

func (d SweepDeps) logError(msg, userID string, err error) {
	if d.Logger != nil {
		d.Logger.Error(msg, "user_id", userID, "error", err)
	}
}

// RecordTransition emits the EventAdminUserLifecycleChanged audit event for an
// applied transition. No-op when rec is nil, so callers may invoke it
// unconditionally. Shared by the sweep (actor = ActorSystem, carried in t.Actor)
// and the admin transition handler (actor = admin id).
func RecordTransition(ctx context.Context, rec *audit.Recorder, userID string, t Transition) {
	if rec == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventAdminUserLifecycleChanged,
		Outcome: audit.OutcomeSuccess,
		ActorID: t.Actor,
	}
	audit.SetMeta(evt, MetaTargetUser, userID)
	audit.SetMeta(evt, MetaFromState, string(t.From))
	audit.SetMeta(evt, MetaToState, string(t.To))
	if t.Reason != "" {
		audit.SetMeta(evt, MetaReason, t.Reason)
	}
	rec.Record(ctx, evt)
}
