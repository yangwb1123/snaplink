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
	Pinner           Pinner           // optional
	Probe            HealthProbe      // optional; when set, Pin auto-rollbacks on failure
	ProbePolls       int              // attempts; defaults to 6
	ProbeBackoff     time.Duration    // sleep between attempts; defaults to 5s
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

// AutoRollbackError preserves both the probe failure and the exact outcome of
// its compensating rollback so operation journals never have to infer state
// from an error string.
type AutoRollbackError struct {
	Target            string
	ProbeError        error
	CompensationError error
}

func (e *AutoRollbackError) Error() string {
	if e.CompensationError != nil {
		return fmt.Sprintf("releases: probe failed (auto-rollback to %q failed: %v): %v",
			e.Target, e.CompensationError, e.ProbeError)
	}
	return fmt.Sprintf("releases: probe failed (auto-rollback to %q): %v", e.Target, e.ProbeError)
}

func (e *AutoRollbackError) Unwrap() error { return e.ProbeError }

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

	prev, prevID, err := r.resolvePrevious(ctx, target, mode)
	if err != nil {
		return nil, err
	}

	if err := r.restoreSnapshot(ctx, target, mode); err != nil {
		return nil, err
	}

	if err := r.runPinner(ctx, target, mode); err != nil {
		return nil, err
	}

	if err := r.Store.SetCurrent(ctx, id); err != nil {
		return nil, fmt.Errorf("releases: set current: %w", err)
	}

	// Health-probe gate — only on forward Pin. Rollback intentionally
	// skips the probe (we're recovering, not adding risk). Failure
	// auto-rollbacks to the previous release when there is one.
	if mode == PinForward && r.Probe != nil {
		if probeErr := r.runProbe(ctx, target); probeErr != nil {
			rolledBackTo, compensationErr := r.autoRollback(ctx, prev)
			return nil, &AutoRollbackError{
				Target: rolledBackTo, ProbeError: probeErr, CompensationError: compensationErr,
			}
		}
	}

	return &PinReport{ReleaseID: id, Mode: mode, PreviousID: prevID}, nil
}

// resolvePrevious reads the currently-pinned release and enforces the
// forward-mode schema-regression gate. Returns the previous release
// (nil on fresh deployments) and its id ("" when nothing was pinned).
func (r *Registry) resolvePrevious(ctx context.Context, target *Release, mode PinMode) (*Release, string, error) {
	prev, err := r.Store.Current(ctx)
	if err != nil && !errors.Is(err, ErrNoCurrent) {
		return nil, "", fmt.Errorf("releases: read current: %w", err)
	}
	if prev == nil {
		return nil, "", nil
	}
	if mode == PinForward && target.SchemaVersion < prev.SchemaVersion {
		return nil, "", ErrSchemaRegress
	}
	return prev, prev.ID, nil
}

// restoreSnapshot applies the target's paired ConfigSnapshot on
// Rollback BEFORE flipping the Pinner — the just-restored backend
// should come up with the matching clients/users/roles. Forward Pin
// intentionally skips this: rolling forward is for new state, not
// re-applying old state. A no-op when there is no snapshot or restorer.
func (r *Registry) restoreSnapshot(ctx context.Context, target *Release, mode PinMode) error {
	if mode != PinRollback || target.ConfigSnapshot == "" || r.SnapshotRestorer == nil {
		return nil
	}
	if err := r.SnapshotRestorer.RestoreByID(ctx, target.ConfigSnapshot); err != nil {
		return fmt.Errorf("releases: rollback snapshot restore: %w", err)
	}
	return nil
}

// runPinner invokes the mode-appropriate Pinner deploy step. A no-op
// when no Pinner is configured (record-keeping-only Pin).
func (r *Registry) runPinner(ctx context.Context, target *Release, mode PinMode) error {
	if r.Pinner == nil {
		return nil
	}
	var perr error
	switch mode {
	case PinForward:
		perr = r.Pinner.PinForward(ctx, target)
	case PinRollback:
		perr = r.Pinner.PinRollback(ctx, target)
	}
	if perr != nil {
		return fmt.Errorf("releases: pinner %s: %w", mode, perr)
	}
	return nil
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
func (r *Registry) autoRollback(ctx context.Context, prev *Release) (string, error) {
	if prev == nil {
		return "", errors.New("no previous release")
	}
	var errs []error
	if r.Pinner != nil {
		if err := r.Pinner.PinRollback(ctx, prev); err != nil {
			errs = append(errs, fmt.Errorf("pinner rollback: %w", err))
		}
	}
	if err := r.Store.SetCurrent(ctx, prev.ID); err != nil {
		errs = append(errs, fmt.Errorf("restore current pointer: %w", err))
	}
	return prev.ID, errors.Join(errs...)
}
