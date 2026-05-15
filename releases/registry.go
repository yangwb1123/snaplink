package releases

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Default tunables for the post-Pin health probe loop.
const (
	defaultProbePolls   = 6
	defaultProbeBackoff = 5 * time.Second
)

// SnapshotRestorer is the slim subset of snapshot.Restorer that the
// Registry needs for ConfigSnapshot-aware Rollback. The releases
// package intentionally does NOT import snapshot — operators wire
// the adapter at cmd time. See cmd/sso-server for the canonical
// implementation.
//
// RestoreByID loads the snapshot at id through whatever pipeline +
// storage the adapter holds, and applies it to the destination
// stores. Any error aborts the Rollback before the Pinner runs.
type SnapshotRestorer interface {
	RestoreByID(ctx context.Context, snapshotID string) error
}

// Registry layers Pin / Rollback / Current on top of a ReleaseStore.
// The Pinner is invoked first; only if it returns nil does the Store
// advance the "current" pointer — that way a half-failed deploy
// doesn't leave the system reporting a release that didn't actually
// flip.
//
// Optional fields:
//   - Pinner: nil means "advance the current pointer but skip the
//     deploy step". Useful in tests and when the operator uses the
//     Pin RPC purely as a record-keeping signal.
//   - Probe + ProbePolls + ProbeBackoff: when Probe is set, Pin runs
//     it after SetCurrent. If it fails after every attempt, Registry
//     auto-rollbacks to the previous release (PinRollback + SetCurrent
//     to the previous id) and returns the wrapped probe error. No
//     probe runs on Rollback — we're trying to recover, not introduce
//     new risk.
//   - SnapshotRestorer: when set AND the rollback target's
//     ConfigSnapshot field is non-empty, Rollback restores that
//     snapshot before flipping the Pinner. Restorer errors abort the
//     rollback (the Pinner does not run, current pointer does not
//     move) so operators see the failure instead of a half-applied
//     rollback.
type Registry struct {
	Store            ReleaseStore
	Pinner           Pinner      // optional
	Probe            HealthProbe // optional; when set, Pin auto-rollbacks on failure
	ProbePolls       int         // attempts; defaults to 6
	ProbeBackoff     time.Duration // sleep between attempts; defaults to 5s
	SnapshotRestorer SnapshotRestorer // optional; consumed by Rollback when target.ConfigSnapshot != ""
}

// PinMode tells implementations + observers whether a Pin is moving
// forward to a newer release or rolling back to a known-good one.
type PinMode int

const (
	PinForward PinMode = iota
	PinRollback
)

func (m PinMode) String() string {
	switch m {
	case PinForward:
		return "forward"
	case PinRollback:
		return "rollback"
	default:
		return "unknown"
	}
}

// PinReport is the per-call outcome. Mirrored 1:1 to the proto
// RestoreReport-equivalent in admin/v1/releases.proto.
type PinReport struct {
	ReleaseID  string
	Mode       PinMode
	PreviousID string // "" when nothing was pinned before
}

// Pin marks id as the current release in forward mode. Schema
// regression vs the current release returns ErrSchemaRegress —
// operators must use Rollback for that direction explicitly.
func (r *Registry) Pin(ctx context.Context, id string) (*PinReport, error) {
	return r.apply(ctx, id, PinForward)
}

// Rollback marks id as the current release in rollback mode. Schema
// regression is permitted.
func (r *Registry) Rollback(ctx context.Context, id string) (*PinReport, error) {
	return r.apply(ctx, id, PinRollback)
}

// Current returns the currently-pinned release, or ErrNoCurrent when
// nothing is pinned (fresh deployments).
func (r *Registry) Current(ctx context.Context) (*Release, error) {
	if r.Store == nil {
		return nil, errors.New("releases: Registry.Store not configured")
	}
	return r.Store.Current(ctx)
}

func (r *Registry) apply(ctx context.Context, id string, mode PinMode) (*PinReport, error) {
	if r.Store == nil {
		return nil, errors.New("releases: Registry.Store not configured")
	}
	target, err := r.Store.Get(ctx, id)
	if err != nil {
		return nil, err
	}

	var prevID string
	prev, err := r.Store.Current(ctx)
	if err != nil && !errors.Is(err, ErrNoCurrent) {
		return nil, fmt.Errorf("releases: read current: %w", err)
	}
	if prev != nil {
		prevID = prev.ID
		if mode == PinForward && target.SchemaVersion < prev.SchemaVersion {
			return nil, ErrSchemaRegress
		}
	}

	// On Rollback with a ConfigSnapshot pointer, restore the paired
	// admin-managed state BEFORE flipping the Pinner — the
	// just-restored backend should come up with the matching
	// clients/users/roles. Forward Pin intentionally skips this:
	// rolling forward is for new state, not re-applying old state.
	if mode == PinRollback && target.ConfigSnapshot != "" && r.SnapshotRestorer != nil {
		if err := r.SnapshotRestorer.RestoreByID(ctx, target.ConfigSnapshot); err != nil {
			return nil, fmt.Errorf("releases: rollback snapshot restore: %w", err)
		}
	}

	if r.Pinner != nil {
		var perr error
		switch mode {
		case PinForward:
			perr = r.Pinner.PinForward(ctx, target)
		case PinRollback:
			perr = r.Pinner.PinRollback(ctx, target)
		}
		if perr != nil {
			return nil, fmt.Errorf("releases: pinner %s: %w", mode, perr)
		}
	}

	if err := r.Store.SetCurrent(ctx, id); err != nil {
		return nil, fmt.Errorf("releases: set current: %w", err)
	}

	// Health-probe gate — only on forward Pin. Rollback intentionally
	// skips the probe (we're recovering, not adding risk). Failure
	// auto-rollbacks to the previous release when there is one.
	if mode == PinForward && r.Probe != nil {
		if probeErr := r.runProbe(ctx, target); probeErr != nil {
			rolledBackTo := r.autoRollback(ctx, prev)
			return nil, fmt.Errorf("releases: probe failed (auto-rollback to %q): %w", rolledBackTo, probeErr)
		}
	}

	return &PinReport{ReleaseID: id, Mode: mode, PreviousID: prevID}, nil
}

// runProbe loops r.Probe.Probe up to ProbePolls times with
// ProbeBackoff between attempts. First nil result wins. ctx
// cancellation between attempts cuts the loop short.
func (r *Registry) runProbe(ctx context.Context, target *Release) error {
	polls := r.ProbePolls
	if polls <= 0 {
		polls = defaultProbePolls
	}
	backoff := r.ProbeBackoff
	if backoff <= 0 {
		backoff = defaultProbeBackoff
	}
	var lastErr error
	for attempt := 0; attempt < polls; attempt++ {
		err := r.Probe.Probe(ctx, target)
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < polls-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return fmt.Errorf("after %d attempts: %w", polls, lastErr)
}

// autoRollback restores the previous release as the current pointer
// when probe fails. Returns the id we rolled back to ("" when there
// was no previous; the failed release stays current in that case
// because there's nowhere safe to flip to). Errors during the
// rollback are intentionally swallowed — we already have the probe
// failure to surface, and surfacing a second error here would mask it.
func (r *Registry) autoRollback(ctx context.Context, prev *Release) string {
	if prev == nil {
		return ""
	}
	if r.Pinner != nil {
		_ = r.Pinner.PinRollback(ctx, prev)
	}
	_ = r.Store.SetCurrent(ctx, prev.ID)
	return prev.ID
}
