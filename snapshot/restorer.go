package snapshot

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/bootstrap"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
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
	Clients     sso.ClientStore       // optional
	Users       sso.UserProvider      // optional
	Permissions permissions.Provider  // optional
	NetPolicy   netpolicy.Store       // optional
	Tracker     bootstrap.Tracker     // optional, for AdvanceBootstrap
	Namespace   string                // bootstrap namespace; defaults to snapshot's
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
	Mode    RestoreMode
	DryRun  bool
	Items   map[ResourceCategory]CategoryCounts
	Bootstrap BootstrapAdvance
	Errors  []string
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
	if snap == nil {
		return nil, errors.New("snapshot: nil snapshot")
	}
	if err := snap.Validate(); err != nil {
		return nil, err
	}
	if opts.Mode == "" {
		opts.Mode = ModeMerge
	}
	if opts.Mode == ModeReplace {
		if opts.Confirm == "" {
			return nil, ErrConfirmationRequired
		}
		if opts.Confirm != snap.SnapshotID {
			return nil, ErrConfirmationMismatch
		}
	}
	rep := &Report{
		Mode:   opts.Mode,
		DryRun: opts.DryRun,
		Items:  make(map[ResourceCategory]CategoryCounts, 6),
	}

	// Apply order is dependency-order: clients/users (leaf identities)
	// → roles + menus (per-client config) → assignments (joins user×role)
	// → netpolicy (independent) → bootstrap state (terminal advance).
	type catRunner struct {
		cat ResourceCategory
		run func() (CategoryCounts, error)
	}
	plan := []catRunner{
		{CategoryClients, func() (CategoryCounts, error) { return r.restoreClients(ctx, snap, opts) }},
		{CategoryUsers, func() (CategoryCounts, error) { return r.restoreUsers(ctx, snap, opts) }},
		{CategoryRoles, func() (CategoryCounts, error) { return r.restoreRoles(ctx, snap, opts) }},
		{CategoryMenus, func() (CategoryCounts, error) { return r.restoreMenus(ctx, snap, opts) }},
		{CategoryAssignments, func() (CategoryCounts, error) { return r.restoreAssignments(ctx, snap, opts) }},
		{CategoryNetPolicy, func() (CategoryCounts, error) { return r.restoreNetPolicy(ctx, snap, opts) }},
	}

	for _, p := range plan {
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

// ============================================================
// Per-category restore funcs
// ============================================================

func (r *Restorer) restoreClients(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Clients == nil || len(snap.Resources.Clients) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		existing, err := r.Clients.List(ctx)
		if err != nil {
			return c, fmt.Errorf("list before replace: %w", err)
		}
		keep := make(map[string]bool, len(snap.Resources.Clients))
		for _, x := range snap.Resources.Clients {
			keep[x.ID] = true
		}
		for _, x := range existing {
			if keep[x.ID] {
				continue
			}
			if !opts.DryRun {
				if err := r.Clients.Delete(ctx, x.ID); err != nil {
					return c, fmt.Errorf("delete %q: %w", x.ID, err)
				}
			}
			c.Deleted++
		}
	}

	for _, cl := range snap.Resources.Clients {
		switch opts.Mode {
		case ModeMerge:
			if opts.DryRun {
				if _, err := r.Clients.Get(ctx, cl.ID); err == nil {
					c.Skipped++
				} else {
					c.Inserted++
				}
				continue
			}
			err := r.Clients.Add(ctx, cl)
			if err == nil {
				c.Inserted++
			} else if errors.Is(err, sso.ErrClientExists) {
				c.Skipped++
			} else {
				return c, fmt.Errorf("add %q: %w", cl.ID, err)
			}
		case ModeOverwrite, ModeReplace:
			if opts.DryRun {
				if _, err := r.Clients.Get(ctx, cl.ID); err == nil {
					c.Updated++
				} else {
					c.Inserted++
				}
				continue
			}
			err := r.Clients.Add(ctx, cl)
			if err == nil {
				c.Inserted++
				continue
			}
			if !errors.Is(err, sso.ErrClientExists) {
				return c, fmt.Errorf("add %q: %w", cl.ID, err)
			}
			if err := r.Clients.Update(ctx, cl); err != nil {
				return c, fmt.Errorf("update %q: %w", cl.ID, err)
			}
			c.Updated++
		}
	}
	return c, nil
}

func (r *Restorer) restoreUsers(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Users == nil || len(snap.Resources.Users) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		existing, err := r.Users.List(ctx)
		if err != nil {
			return c, fmt.Errorf("list before replace: %w", err)
		}
		keep := make(map[string]bool, len(snap.Resources.Users))
		for _, u := range snap.Resources.Users {
			keep[u.ID] = true
		}
		for _, u := range existing {
			if keep[u.ID] {
				continue
			}
			if !opts.DryRun {
				if err := r.Users.Delete(ctx, u.ID); err != nil {
					return c, fmt.Errorf("delete %q: %w", u.ID, err)
				}
			}
			c.Deleted++
		}
	}

	for _, u := range snap.Resources.Users {
		switch opts.Mode {
		case ModeMerge:
			if _, err := r.Users.GetByID(ctx, u.ID); err == nil {
				c.Skipped++
				continue
			}
			if !opts.DryRun {
				if err := r.Users.CreateOrUpdate(ctx, u); err != nil {
					return c, fmt.Errorf("create %q: %w", u.ID, err)
				}
			}
			c.Inserted++
		case ModeOverwrite, ModeReplace:
			present := false
			if _, err := r.Users.GetByID(ctx, u.ID); err == nil {
				present = true
			}
			if !opts.DryRun {
				if err := r.Users.CreateOrUpdate(ctx, u); err != nil {
					return c, fmt.Errorf("upsert %q: %w", u.ID, err)
				}
			}
			if present {
				c.Updated++
			} else {
				c.Inserted++
			}
		}
	}
	return c, nil
}

func (r *Restorer) restoreRoles(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Permissions == nil {
		return c, nil
	}
	if len(snap.Resources.Roles) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		// Wipe per-client roles before re-seeding. The Replace mode
		// applies *only* to clients that appear in the snapshot — we
		// don't drop role definitions for clients we know nothing about.
		for _, cr := range snap.Resources.Roles {
			cur, err := r.Permissions.ListAllRoles(ctx, cr.ClientID)
			if err != nil {
				return c, fmt.Errorf("list roles[%s]: %w", cr.ClientID, err)
			}
			keep := make(map[string]bool, len(cr.Roles))
			for _, x := range cr.Roles {
				keep[x.Code] = true
			}
			for _, x := range cur {
				if keep[x.Code] {
					continue
				}
				if !opts.DryRun {
					if err := r.Permissions.RemoveRole(ctx, cr.ClientID, x.Code); err != nil {
						return c, fmt.Errorf("remove role[%s/%s]: %w", cr.ClientID, x.Code, err)
					}
				}
				c.Deleted++
			}
		}
	}

	for _, cr := range snap.Resources.Roles {
		for _, role := range cr.Roles {
			switch opts.Mode {
			case ModeMerge:
				if !opts.DryRun {
					err := r.Permissions.AddRole(ctx, cr.ClientID, role)
					if err == nil {
						c.Inserted++
					} else if errors.Is(err, permissions.ErrRoleExists) {
						c.Skipped++
					} else {
						return c, fmt.Errorf("add role[%s/%s]: %w", cr.ClientID, role.Code, err)
					}
				} else {
					c.Inserted++ // can't introspect existence in dry-run without a Get
				}
			case ModeOverwrite, ModeReplace:
				if opts.DryRun {
					c.Inserted++
					continue
				}
				err := r.Permissions.AddRole(ctx, cr.ClientID, role)
				if err == nil {
					c.Inserted++
					continue
				}
				if !errors.Is(err, permissions.ErrRoleExists) {
					return c, fmt.Errorf("add role[%s/%s]: %w", cr.ClientID, role.Code, err)
				}
				if err := r.Permissions.UpdateRole(ctx, cr.ClientID, role); err != nil {
					return c, fmt.Errorf("update role[%s/%s]: %w", cr.ClientID, role.Code, err)
				}
				c.Updated++
			}
		}
	}
	return c, nil
}

func (r *Restorer) restoreMenus(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Permissions == nil || len(snap.Resources.Menus) == 0 {
		return c, nil
	}
	ml, hasLister := r.Permissions.(permissions.MenuLister)

	for _, cm := range snap.Resources.Menus {
		switch opts.Mode {
		case ModeMerge:
			if hasLister {
				existing, err := ml.GetMenus(ctx, cm.ClientID)
				if err != nil {
					return c, fmt.Errorf("get menus[%s]: %w", cm.ClientID, err)
				}
				if len(existing) > 0 {
					c.Skipped++
					continue
				}
			}
			if !opts.DryRun {
				if err := r.Permissions.SetMenus(ctx, cm.ClientID, cm.Menus); err != nil {
					return c, fmt.Errorf("set menus[%s]: %w", cm.ClientID, err)
				}
			}
			c.Inserted++
		case ModeOverwrite, ModeReplace:
			present := false
			if hasLister {
				existing, err := ml.GetMenus(ctx, cm.ClientID)
				if err == nil && len(existing) > 0 {
					present = true
				}
			}
			if !opts.DryRun {
				if err := r.Permissions.SetMenus(ctx, cm.ClientID, cm.Menus); err != nil {
					return c, fmt.Errorf("set menus[%s]: %w", cm.ClientID, err)
				}
			}
			if present {
				c.Updated++
			} else {
				c.Inserted++
			}
		}
	}
	return c, nil
}

func (r *Restorer) restoreAssignments(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Permissions == nil {
		return c, nil
	}
	if len(snap.Resources.Assignments) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		// Drop assignments for any (client, user) pair currently present
		// but absent from the snapshot.
		for _, ca := range snap.Resources.Assignments {
			existing, err := r.Permissions.ListAssignments(ctx, ca.ClientID)
			if err != nil {
				return c, fmt.Errorf("list assignments[%s]: %w", ca.ClientID, err)
			}
			keep := make(map[string]bool, len(ca.Assignments))
			for _, a := range ca.Assignments {
				keep[a.UserID] = true
			}
			for _, e := range existing {
				if keep[e.UserID] {
					continue
				}
				if !opts.DryRun {
					if err := r.Permissions.UnassignRoles(ctx, e.UserID, ca.ClientID, e.Roles); err != nil {
						return c, fmt.Errorf("unassign[%s/%s]: %w", ca.ClientID, e.UserID, err)
					}
				}
				c.Deleted++
			}
		}
	}

	for _, ca := range snap.Resources.Assignments {
		for _, a := range ca.Assignments {
			switch opts.Mode {
			case ModeMerge:
				cur, err := r.Permissions.Roles(ctx, a.UserID, ca.ClientID)
				existing := make(map[string]bool)
				if err == nil {
					for _, role := range cur {
						existing[role.Code] = true
					}
				} else if !errors.Is(err, permissions.ErrUserNotFound) {
					return c, fmt.Errorf("get roles[%s/%s]: %w", ca.ClientID, a.UserID, err)
				}
				union := append([]string(nil), a.Roles...)
				added := false
				for _, code := range a.Roles {
					if !existing[code] {
						added = true
						break
					}
				}
				// If everything in the snapshot is already assigned,
				// nothing to do.
				if !added && len(existing) > 0 {
					c.Skipped++
					continue
				}
				// Build the union: existing first, then new ones from
				// snapshot we don't yet have.
				if len(existing) > 0 {
					for code := range existing {
						union = appendUnique(union, code)
					}
				}
				if !opts.DryRun {
					if err := r.Permissions.AssignRoles(ctx, a.UserID, ca.ClientID, union); err != nil {
						return c, fmt.Errorf("assign[%s/%s]: %w", ca.ClientID, a.UserID, err)
					}
				}
				if len(existing) > 0 {
					c.Updated++
				} else {
					c.Inserted++
				}
			case ModeOverwrite, ModeReplace:
				present := false
				if cur, err := r.Permissions.Roles(ctx, a.UserID, ca.ClientID); err == nil && len(cur) > 0 {
					present = true
				}
				if !opts.DryRun {
					if err := r.Permissions.AssignRoles(ctx, a.UserID, ca.ClientID, a.Roles); err != nil {
						return c, fmt.Errorf("assign[%s/%s]: %w", ca.ClientID, a.UserID, err)
					}
				}
				if present {
					c.Updated++
				} else {
					c.Inserted++
				}
			}
		}
	}
	return c, nil
}

func (r *Restorer) restoreNetPolicy(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.NetPolicy == nil || len(snap.Resources.NetPolicy) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		existing, err := r.NetPolicy.List(ctx)
		if err != nil {
			return c, fmt.Errorf("list before replace: %w", err)
		}
		keep := make(map[string]bool, len(snap.Resources.NetPolicy))
		for _, p := range snap.Resources.NetPolicy {
			keep[p.Name] = true
		}
		for _, p := range existing {
			if keep[p.Name] {
				continue
			}
			if !opts.DryRun {
				if err := r.NetPolicy.Delete(ctx, p.Name); err != nil {
					return c, fmt.Errorf("delete %q: %w", p.Name, err)
				}
			}
			c.Deleted++
		}
	}

	for _, p := range snap.Resources.NetPolicy {
		present := false
		if _, err := r.NetPolicy.Get(ctx, p.Name); err == nil {
			present = true
		} else if !errors.Is(err, netpolicy.ErrNotFound) {
			return c, fmt.Errorf("get %q: %w", p.Name, err)
		}
		switch opts.Mode {
		case ModeMerge:
			if present {
				c.Skipped++
				continue
			}
			if !opts.DryRun {
				if _, err := r.NetPolicy.Apply(ctx, p); err != nil {
					return c, fmt.Errorf("apply %q: %w", p.Name, err)
				}
			}
			c.Inserted++
		case ModeOverwrite, ModeReplace:
			if !opts.DryRun {
				if _, err := r.NetPolicy.Apply(ctx, p); err != nil {
					return c, fmt.Errorf("apply %q: %w", p.Name, err)
				}
			}
			if present {
				c.Updated++
			} else {
				c.Inserted++
			}
		}
	}
	return c, nil
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
