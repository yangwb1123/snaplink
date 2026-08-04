package snapshot

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/shared/security"
)

// RestoreMode is how a Restorer treats existing destination state.
//
//   - ModeMerge: insert items that don't exist; leave existing untouched.
//     Safest mode — operators bringing a peer node up to a baseline use this.
//   - ModeOverwrite: insert when missing, update when present. No deletion.
//     Useful when the snapshot is the new source of truth for matching IDs
//     but the destination has extra resources you want to preserve.
//   - ModeReplace: wipe the destination categories the snapshot covers, then
//     insert everything from the snapshot. Strictly the most dangerous —
//     the Restorer requires a Confirm token equal to the SnapshotID.
type RestoreMode string

const (
	ModeMerge     RestoreMode = "merge"
	ModeOverwrite RestoreMode = "overwrite"
	ModeReplace   RestoreMode = "replace"
)

// Restorer applies a Snapshot to a destination. Every backend field is
// optional in the same shape as Snapshotter — categories whose backend is
// nil are silently skipped on restore.
type Restorer struct {
	Clients     sso.ClientStore               // optional
	Users       sso.UserProvider              // optional
	Permissions permissions.Provider          // optional
	NetPolicy   netpolicy.Store               // optional
	Tenants     tenant.Store                  // optional
	Connections connections.Store             // optional
	Pairwise    security.PairwiseSubjectStore // optional
	Invalidator RestoreInvalidator            // optional
	Tracker     bootstrap.Tracker             // optional, for AdvanceBootstrap
	Namespace   string                        // bootstrap namespace; defaults to snapshot's
}

// RestoreInvalidator flushes local and peer control-plane caches after a
// successful non-dry-run restore.
type RestoreInvalidator interface {
	InvalidateRestoredControlPlane()
}

// RestoreOptions tunes a single Restore call.
type RestoreOptions struct {
	Mode             RestoreMode
	DryRun           bool
	Exclude          []ResourceCategory
	AdvanceBootstrap bool

	// Confirm is REQUIRED for ModeReplace. Operators must echo back the
	// snapshot's SnapshotID — a dumb "yes I know what I'm doing" knob that
	// makes accidental wipes hard. Ignored for Merge and Overwrite.
	Confirm string

	// AutoSafetySnapshot and RollbackOnError are ORCHESTRATOR intents:
	// the Restorer itself never captures a safety snapshot and never rolls
	// back (it has no Pipeline/Storage). The orchestrator (grpcadmin
	// restoreTracked) consumes them to decide capture + rollback behavior
	// and passes them through so SDK-direct callers get the same
	// validation. AutoSafetySnapshot is the normalized intent (explicit
	// true, or defaulted by the orchestrator for replace non-dry-runs);
	// RollbackOnError requires AutoSafetySnapshot=true or prepareRestore
	// rejects the call with ErrRollbackWithoutSafety before any write.
	AutoSafetySnapshot bool
	RollbackOnError    bool

	// Preview attaches the entry-level snapshot-vs-live diff to the
	// report on a NON-dry-run restore (dry-run always attaches it). The
	// preview is computed before any write and fails closed on
	// enumeration errors. Default false — existing callers see zero
	// behavior change (Report.Diff stays nil).
	Preview bool
}

// Report is the per-category outcome of a restore. Counts are accumulated
// across the run; a non-nil Errors slice means at least one category bailed
// (other categories may still have applied — see Restore). Counts are
// meaningful only when Committed is true (or the run returned no error):
// on a Phase B failure the Deleted counts are partial while Inserted /
// Updated are complete.
type Report struct {
	Mode      RestoreMode
	DryRun    bool
	Items     map[ResourceCategory]CategoryCounts
	Bootstrap BootstrapAdvance
	Errors    []string

	// Committed is true iff a non-dry-run restore completed every phase
	// without error. Dry-run always reports false (predictions, not
	// writes). A bootstrap-advance failure AFTER the phases applied leaves
	// Committed true (data is applied; only the tracker didn't advance) —
	// callers must not key on err alone.
	Committed bool
	// RolledBack and SafetySnapshotID are set by the ORCHESTRATOR on the
	// rollback path (the Restorer never orchestrates). RolledBack reports
	// that the failed restore's safety snapshot was re-applied;
	// SafetySnapshotID names the undo artifact (also echoed on the success
	// path when a capture ran).
	RolledBack       bool
	SafetySnapshotID string

	// Diff is the entry-level snapshot-vs-live preview, computed when
	// opts.DryRun or opts.Preview. json:"preview,omitempty" keeps every
	// legacy ResultJSON byte identical when no preview ran. Dry-run
	// counts of diff-covered categories are projected from this diff;
	// uncovered categories keep the plan's probe/optimistic counts.
	Diff *DiffResult `json:"preview,omitempty"`
}

// CategoryCounts is the per-resource bookkeeping the Report carries.
// Unchanged counts entries whose content already matches the snapshot —
// the no-op distinction dry-run previously could not make (presence alone
// was counted as Updated). It is only meaningful on dry-run reports (and
// the preview overlay); the apply path never writes an unchanged entry.
type CategoryCounts struct {
	Inserted  int
	Updated   int
	Deleted   int
	Skipped   int
	Unchanged int
}

// BootstrapAdvance describes what happened to the destination Tracker.
type BootstrapAdvance struct {
	Attempted bool
	From      int
	To        int
	NoOp      bool   // true when From >= To (snapshot is older or same)
	Reason    string // populated when Attempted but skipped
}

// Restore applies snap onto the destination per opts. Returns a Report
// regardless of error so callers can see partial work; the error (when
// non-nil) is the first hard failure that aborted the run.
//
// ModeReplace runs in TWO phases (see restorer_stage.go): Phase A stages
// every category's insert/update/upsert in dependency order with all prunes
// disabled; Phase B, only after Phase A fully succeeds, runs every
// category's prune in the same order. A mid-plan failure therefore leaves
// either an old-state superset (Phase A fail — nothing deleted, retry-safe)
// or a target-state superset (Phase B fail — partial deletes, same-snapshot
// retry converges). Merge/overwrite run Phase A only, exactly as before.
func (r *Restorer) Restore(ctx context.Context, snap *Snapshot, opts RestoreOptions) (*Report, error) {
	if err := r.prepareRestore(snap, &opts); err != nil {
		return nil, err
	}
	rep := &Report{
		Mode:   opts.Mode,
		DryRun: opts.DryRun,
		Items:  make(map[ResourceCategory]CategoryCounts, len(AllCategories())),
	}
	if err := r.attachRestorePreview(ctx, snap, opts, rep); err != nil {
		return nil, err
	}
	if err := r.applyRestorePlans(ctx, snap, opts, rep); err != nil {
		return rep, err
	}
	rep.Committed = !opts.DryRun
	if err := r.advanceRestoreBootstrap(ctx, snap, opts, rep); err != nil {
		return rep, err
	}
	return rep, nil
}

func (r *Restorer) attachRestorePreview(ctx context.Context, snap *Snapshot, opts RestoreOptions, rep *Report) error {
	if !opts.DryRun && !opts.Preview {
		return nil
	}
	diff, err := r.Preview(ctx, snap, opts)
	if err == nil {
		rep.Diff = diff
	}
	return err
}

func (r *Restorer) applyRestorePlans(ctx context.Context, snap *Snapshot, opts RestoreOptions, rep *Report) error {
	if err := runPlan(ctx, rep, snap, opts, r.stagePlan(ctx, snap, opts)); err != nil {
		return err
	}
	if opts.Mode == ModeReplace {
		if err := runPlan(ctx, rep, snap, opts, r.prunePlan(ctx, snap, opts)); err != nil {
			return err
		}
	}
	if !opts.DryRun && r.Invalidator != nil {
		r.Invalidator.InvalidateRestoredControlPlane()
	}
	if opts.DryRun {
		overlayDryRunCounts(rep, opts.Mode, rep.Diff)
	}
	return nil
}

func (r *Restorer) advanceRestoreBootstrap(ctx context.Context, snap *Snapshot, opts RestoreOptions, rep *Report) error {
	if !opts.AdvanceBootstrap {
		return nil
	}
	advance, err := r.advanceBootstrap(ctx, snap, opts.DryRun)
	rep.Bootstrap = advance
	if err != nil {
		rep.Errors = append(rep.Errors, "bootstrap: "+err.Error())
		return fmt.Errorf("snapshot restore: bootstrap advance: %w", err)
	}
	return nil
}

// ValidateRestore runs prepareRestore's checks (snapshot validity, mode
// defaulting, the ModeReplace confirmation handshake, capability preflight,
// and the rollback-requires-a-net rule) WITHOUT applying anything. The admin
// orchestrator calls it after load and BEFORE the D1 safety capture so an
// invalid request never writes — not even the undo artifact; Restore itself
// re-runs the same checks, so SDK-direct callers are equally protected.
// opts is normalized in place exactly as Restore would.
func (r *Restorer) ValidateRestore(snap *Snapshot, opts *RestoreOptions) error {
	return r.prepareRestore(snap, opts)
}

// prepareRestore validates the snapshot and normalizes opts in place:
// defaulting an empty Mode to Merge and enforcing the ModeReplace
// confirmation handshake. It also fails before any write when the caller
// requested rollback without an explicit safety net — the validation reads
// the caller's RAW AutoSafetySnapshot (the Restorer never defaults it; the
// orchestrator does) so the strict "rollback requires an explicit net"
// contract cannot be bypassed by defaulting.
func (r *Restorer) prepareRestore(snap *Snapshot, opts *RestoreOptions) error {
	if snap == nil {
		return errors.New("snapshot: nil snapshot")
	}
	if err := snap.Validate(); err != nil {
		return err
	}
	if opts.Mode == "" {
		opts.Mode = ModeMerge
	}
	if opts.Mode == ModeReplace {
		if opts.Confirm == "" {
			return ErrConfirmationRequired
		}
		if opts.Confirm != snap.SnapshotID {
			return ErrConfirmationMismatch
		}
		// Capability preflight: fail before any write (including the
		// operations ledger) when a wired backend lacks a capability its
		// ModeReplace prune needs.
		if err := r.preflightReplace(snap, *opts); err != nil {
			return err
		}
	}
	if opts.RollbackOnError && !opts.AutoSafetySnapshot {
		return ErrRollbackWithoutSafety
	}
	return nil
}

// advanceBootstrap bumps the destination Tracker's recorded "highest
// applied" to match the snapshot's, but only when the snapshot is *newer*.
// Useful when restoring on a fresh node so seed steps don't re-run on top
// of imported data.
func (r *Restorer) advanceBootstrap(ctx context.Context, snap *Snapshot, dryRun bool) (BootstrapAdvance, error) {
	out := BootstrapAdvance{Attempted: true}
	if r.Tracker == nil {
		out.Reason = "tracker not configured"
		out.NoOp = true
		return out, nil
	}
	ns := r.Namespace
	if ns == "" {
		ns = snap.BootstrapState.Namespace
	}
	if ns == "" {
		out.Reason = "no namespace"
		out.NoOp = true
		return out, nil
	}
	cur, err := r.Tracker.AppliedVersion(ctx, ns)
	if err != nil {
		return out, fmt.Errorf("read applied version: %w", err)
	}
	out.From = cur
	out.To = snap.BootstrapState.AppliedVersion
	if out.To <= cur {
		out.NoOp = true
		out.Reason = "snapshot version not newer"
		return out, nil
	}
	if dryRun {
		return out, nil
	}
	if err := r.Tracker.MarkApplied(ctx, ns, out.To, "snapshot_restore"); err != nil {
		return out, fmt.Errorf("mark applied: %w", err)
	}
	return out, nil
}

// appendUnique adds s to dst iff it is not already present. O(n) — fine
// for the small role-code lists snapshots carry.
func appendUnique(dst []string, s string) []string {
	if slices.Contains(dst, s) {
		return dst
	}
	return append(dst, s)
}
