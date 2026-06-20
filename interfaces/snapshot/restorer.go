package snapshot

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/bootstrap"
	"github.com/snaplink/sso/platform/netpolicy"
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
	Clients     sso.ClientStore      // optional
	Users       sso.UserProvider     // optional
	Permissions permissions.Provider // optional
	NetPolicy   netpolicy.Store      // optional
	Tracker     bootstrap.Tracker    // optional, for AdvanceBootstrap
	Namespace   string               // bootstrap namespace; defaults to snapshot's
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
}

// Report is the per-category outcome of a restore. Counts are accumulated
// across the run; a non-nil Errors slice means at least one category bailed
// (other categories may still have applied — Restorer continues past
// per-item failures only when nothing destructive has happened yet, see
// per-category code below).
type Report struct {
	Mode      RestoreMode
	DryRun    bool
	Items     map[ResourceCategory]CategoryCounts
	Bootstrap BootstrapAdvance
	Errors    []string
}

// CategoryCounts is the per-resource bookkeeping the Report carries.
type CategoryCounts struct {
	Inserted int
	Updated  int
	Deleted  int
	Skipped  int
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
func (r *Restorer) Restore(ctx context.Context, snap *Snapshot, opts RestoreOptions) (*Report, error) {
	if err := r.prepareRestore(snap, &opts); err != nil {
		return nil, err
	}
	rep := &Report{
		Mode:   opts.Mode,
		DryRun: opts.DryRun,
		Items:  make(map[ResourceCategory]CategoryCounts, 6),
	}

	for _, p := range r.restorePlan(ctx, snap, opts) {
		if excluded(p.cat, opts.Exclude) {
			continue
		}
		c, err := p.run()
		rep.Items[p.cat] = c
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", p.cat, err))
			return rep, fmt.Errorf("snapshot restore: %s: %w", p.cat, err)
		}
	}

	if opts.AdvanceBootstrap {
		ba, err := r.advanceBootstrap(ctx, snap, opts.DryRun)
		rep.Bootstrap = ba
		if err != nil {
			rep.Errors = append(rep.Errors, "bootstrap: "+err.Error())
			return rep, fmt.Errorf("snapshot restore: bootstrap advance: %w", err)
		}
	}

	return rep, nil
}

// prepareRestore validates the snapshot and normalizes opts in place:
// defaulting an empty Mode to Merge and enforcing the ModeReplace
// confirmation handshake.
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
	}
	return nil
}

// catRunner pairs a category with its restore closure.
type catRunner struct {
	cat ResourceCategory
	run func() (CategoryCounts, error)
}

// restorePlan returns the per-category restore steps in dependency order:
// clients/users (leaf identities) → roles + menus (per-client config) →
// assignments (joins user×role) → netpolicy (independent). Bootstrap state
// is the terminal advance handled separately by the caller.
func (r *Restorer) restorePlan(ctx context.Context, snap *Snapshot, opts RestoreOptions) []catRunner {
	return []catRunner{
		{CategoryClients, func() (CategoryCounts, error) { return r.restoreClients(ctx, snap, opts) }},
		{CategoryUsers, func() (CategoryCounts, error) { return r.restoreUsers(ctx, snap, opts) }},
		{CategoryRoles, func() (CategoryCounts, error) { return r.restoreRoles(ctx, snap, opts) }},
		{CategoryMenus, func() (CategoryCounts, error) { return r.restoreMenus(ctx, snap, opts) }},
		{CategoryAssignments, func() (CategoryCounts, error) { return r.restoreAssignments(ctx, snap, opts) }},
		{CategoryNetPolicy, func() (CategoryCounts, error) { return r.restoreNetPolicy(ctx, snap, opts) }},
	}
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
