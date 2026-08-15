package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/shared/security"
)

// Preview computes the entry-level diff between snap (the desired state) and
// the restorer's live backends (the current state) — the snapshot-vs-live
// preview that upgrades dry-run from counts to an item-level review surface.
// The live side is enumerated with the exact reads the restorer's apply path
// uses (per-item Get for presence + content, List/ListAllRoles/ListAssignments/
// GetMenus where the mode's writes need them), so the preview never reports
// a classification the restore cannot perform.
//
// Coverage limits (documented, not silent): categories whose backend is nil,
// whose capability the enumeration needs is absent (no MenuLister; a
// connections/pairwise backend without a Lister outside replace mode), or
// that the snapshot does not cover are omitted from the result — those
// categories keep the apply path's probe/optimistic counts instead. The
// engine never reports "inserted" for something it could not enumerate.
//
// The preview fails closed: any backend read error aborts with an error
// before a single write — a preview that cannot enumerate its evidence must
// not be silently replaced by optimistic counts.
func (r *Restorer) Preview(ctx context.Context, snap *Snapshot, opts RestoreOptions) (*DiffResult, error) {
	if snap == nil {
		return nil, errors.New("snapshot: nil snapshot")
	}
	live, err := r.liveSnapshot(ctx, snap, opts)
	if err != nil {
		return nil, err
	}
	// Diff is ordered current → desired so inserted/deleted describe the
	// restore actions, not the inverse live-state observation.
	return Diff(live, snap, DiffOptions{Exclude: opts.Exclude})
}

// liveSnapshot assembles the "current state" side of the preview from the
// restorer's own backends. In replace mode the live side is the full
// enumeration (the prunes consider every live record, so live-only entries
// surface as deleted); in merge/overwrite it is restricted to identities the
// snapshot carries (untouched live entries must not be reported as deleted —
// the restore will not remove them).
func (r *Restorer) liveSnapshot(ctx context.Context, snap *Snapshot, opts RestoreOptions) (*Snapshot, error) {
	// The live side carries an EXPLICIT category list (never nil): a nil
	// manifest means "include all" in artifact semantics, but the live
	// side is only a partial view of what this restorer can enumerate —
	// categories the diff engine cannot index (the v3 credential
	// categories, nil/unwired backends) stay out of the diff so their
	// dry-run counts keep the plan's probe counts (dry-run honesty).
	live := &Snapshot{SchemaVersion: SchemaVersion, SourceNamespace: snap.SourceNamespace, Categories: make([]ResourceCategory, 0, len(AllCategories()))}
	add := func(cat ResourceCategory, entries func() error) error {
		if r.backendFor(cat) == nil || excluded(cat, opts.Exclude) || !snap.IncludesCategory(cat) {
			return nil
		}
		if err := entries(); err != nil {
			return err
		}
		live.Categories = append(live.Categories, cat)
		return nil
	}
	if err := add(CategoryClients, func() error { return r.liveClients(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryUsers, func() error { return r.liveUsers(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryTenants, func() error { return r.liveTenants(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryTenantDomains, func() error { return r.liveTenantDomains(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryConnections, func() error { return r.liveConnections(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryPairwise, func() error { return r.livePairwise(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryRoles, func() error { return r.liveRoles(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryAssignments, func() error { return r.liveAssignments(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryMenus, func() error { return r.liveMenus(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	if err := add(CategoryNetPolicy, func() error { return r.liveNetPolicy(ctx, snap, opts, live) }); err != nil {
		return nil, err
	}
	return live, nil
}

// backendFor reports the backend the preview needs for one category (nil
// means the restore skips the category entirely, so the preview does too).
func (r *Restorer) backendFor(cat ResourceCategory) any {
	switch cat {
	case CategoryClients:
		return r.Clients
	case CategoryUsers:
		return r.Users
	case CategoryTenants, CategoryTenantDomains:
		return r.Tenants
	case CategoryConnections:
		return r.Connections
	case CategoryPairwise:
		return r.Pairwise
	case CategoryRoles, CategoryAssignments, CategoryMenus:
		return r.Permissions
	case CategoryNetPolicy:
		return r.NetPolicy
	}
	return nil
}

// liveClients fills the live clients slice: full List in replace mode (the
// prune considers every live client), per-id Get otherwise.
func (r *Restorer) liveClients(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	if opts.Mode == ModeReplace {
		all, err := r.Clients.List(ctx)
		if err != nil {
			return fmt.Errorf("snapshot preview: clients.List: %w", err)
		}
		live.Resources.Clients = all
		return nil
	}
	for _, cl := range snap.Resources.Clients {
		if cl == nil {
			continue
		}
		existing, err := r.Clients.Get(ctx, cl.ID)
		if err != nil {
			if errors.Is(err, sso.ErrNoSuchClient) {
				continue
			}
			return fmt.Errorf("snapshot preview: clients.Get(%s): %w", cl.ID, err)
		}
		live.Resources.Clients = append(live.Resources.Clients, existing)
	}
	return nil
}

// liveUsers fills the live users slice: full List in replace mode, per-id
// GetByID otherwise.
func (r *Restorer) liveUsers(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	if opts.Mode == ModeReplace {
		all, err := r.Users.List(ctx)
		if err != nil {
			return fmt.Errorf("snapshot preview: users.List: %w", err)
		}
		live.Resources.Users = all
		return nil
	}
	for _, u := range snap.Resources.Users {
		if u == nil {
			continue
		}
		existing, err := r.Users.GetByID(ctx, u.ID)
		if err != nil {
			if errors.Is(err, sso.ErrNoSuchUser) {
				continue
			}
			return fmt.Errorf("snapshot preview: users.GetByID(%s): %w", u.ID, err)
		}
		live.Resources.Users = append(live.Resources.Users, existing)
	}
	return nil
}

// liveTenants fills the live tenant slice.
func (r *Restorer) liveTenants(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	if opts.Mode == ModeReplace {
		all, err := r.Tenants.ListTenants(ctx)
		if err != nil {
			return fmt.Errorf("snapshot preview: tenants.ListTenants: %w", err)
		}
		live.Resources.Tenants = all
		return nil
	}
	for _, item := range snap.Resources.Tenants {
		if item == nil {
			continue
		}
		existing, err := r.Tenants.GetTenant(ctx, item.ID)
		if err != nil {
			if errors.Is(err, tenant.ErrTenantNotFound) {
				continue
			}
			return fmt.Errorf("snapshot preview: tenants.GetTenant(%s): %w", item.ID, err)
		}
		live.Resources.Tenants = append(live.Resources.Tenants, existing)
	}
	return nil
}

// liveTenantDomains fills the live domain slice.
func (r *Restorer) liveTenantDomains(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	if opts.Mode == ModeReplace {
		all, err := r.Tenants.ListDomains(ctx)
		if err != nil {
			return fmt.Errorf("snapshot preview: tenants.ListDomains: %w", err)
		}
		live.Resources.TenantDomains = all
		return nil
	}
	for _, item := range snap.Resources.TenantDomains {
		if item == nil {
			continue
		}
		existing, err := r.Tenants.GetDomain(ctx, item.Hostname)
		if err != nil {
			if errors.Is(err, tenant.ErrDomainNotFound) {
				continue
			}
			return fmt.Errorf("snapshot preview: tenants.GetDomain(%s): %w", item.Hostname, err)
		}
		live.Resources.TenantDomains = append(live.Resources.TenantDomains, existing)
	}
	return nil
}

// liveConnections fills the live connections slice. The replace prune needs
// a Lister (preflightReplace guarantees one before any restore reaches the
// preview); without it the category is omitted and keeps probe counting.
func (r *Restorer) liveConnections(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	if opts.Mode == ModeReplace {
		lister, ok := r.Connections.(connections.Lister)
		if !ok {
			return nil
		}
		all, err := lister.List(ctx)
		if err != nil {
			return fmt.Errorf("snapshot preview: connections.List: %w", err)
		}
		live.Resources.Connections = all
		return nil
	}
	for _, item := range snap.Resources.Connections {
		if item == nil {
			continue
		}
		existing, err := r.Connections.Get(ctx, item.ID)
		if err != nil {
			if errors.Is(err, connections.ErrNoConnection) {
				continue
			}
			return fmt.Errorf("snapshot preview: connections.Get(%s): %w", item.ID, err)
		}
		live.Resources.Connections = append(live.Resources.Connections, existing)
	}
	return nil
}

// livePairwise fills the live pairwise mapping slice. LocalSubject returns
// the local subject for a pairwise sub; the mapping entry is reconstructed
// from the snapshot's key.
func (r *Restorer) livePairwise(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	if opts.Mode == ModeReplace {
		lister, ok := r.Pairwise.(security.PairwiseSubjectLister)
		if !ok {
			return nil
		}
		all, err := lister.ListPairwiseSubjects(ctx)
		if err != nil {
			return fmt.Errorf("snapshot preview: pairwise.ListPairwiseSubjects: %w", err)
		}
		live.Resources.Pairwise = all
		return nil
	}
	for _, item := range snap.Resources.Pairwise {
		local, err := r.Pairwise.LocalSubject(ctx, item.PairwiseSub)
		if err != nil {
			if errors.Is(err, security.ErrPairwiseUnknown) {
				continue
			}
			return fmt.Errorf("snapshot preview: pairwise.LocalSubject(%s): %w", item.PairwiseSub, err)
		}
		live.Resources.Pairwise = append(live.Resources.Pairwise, security.PairwiseSubjectMapping{
			PairwiseSub: item.PairwiseSub, LocalSub: local,
		})
	}
	return nil
}

// liveRoles fills the live roles per snapshot-roster client (the exact
// enumeration the roles stage and prune use). In merge/overwrite the live
// side is restricted to role codes the snapshot carries — the restore never
// touches other live roles, so they must not surface as deleted.
func (r *Restorer) liveRoles(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	keep := map[string]bool{}
	if opts.Mode != ModeReplace {
		for _, cr := range snap.Resources.Roles {
			for _, role := range cr.Roles {
				keep[roleKeyID(cr.ClientID, role.Code)] = true
			}
		}
	}
	for _, cl := range snap.Resources.Clients {
		if cl == nil {
			continue
		}
		roles, err := r.Permissions.ListAllRoles(ctx, cl.ID)
		if err != nil {
			return fmt.Errorf("snapshot preview: roles[%s]: %w", cl.ID, err)
		}
		var matched []permissions.Role
		for _, role := range roles {
			if opts.Mode != ModeReplace && !keep[roleKeyID(cl.ID, role.Code)] {
				continue
			}
			matched = append(matched, role)
		}
		if len(matched) > 0 {
			live.Resources.Roles = append(live.Resources.Roles, ClientRoles{ClientID: cl.ID, Roles: matched})
		}
	}
	return nil
}

// liveAssignments fills the live assignments per snapshot-roster client,
// with the same merge/overwrite restriction as liveRoles.
func (r *Restorer) liveAssignments(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	keep := map[string]bool{}
	if opts.Mode != ModeReplace {
		for _, ca := range snap.Resources.Assignments {
			for _, a := range ca.Assignments {
				keep[assignmentKeyID(ca.ClientID, a.UserID)] = true
			}
		}
	}
	for _, cl := range snap.Resources.Clients {
		if cl == nil {
			continue
		}
		assignments, err := r.Permissions.ListAssignments(ctx, cl.ID)
		if err != nil {
			return fmt.Errorf("snapshot preview: assignments[%s]: %w", cl.ID, err)
		}
		var matched []permissions.Assignment
		for _, a := range assignments {
			if opts.Mode != ModeReplace && !keep[assignmentKeyID(cl.ID, a.UserID)] {
				continue
			}
			matched = append(matched, a)
		}
		if len(matched) > 0 {
			live.Resources.Assignments = append(live.Resources.Assignments, ClientAssignments{ClientID: cl.ID, Assignments: matched})
		}
	}
	return nil
}

// liveMenus fills the live menu trees per snapshot-roster client when the
// permissions provider implements MenuLister; without one the category is
// omitted (the apply path cannot detect presence either). Empty live trees
// are skipped so a zero-vs-zero pair is not misreported as a wipe.
func (r *Restorer) liveMenus(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	ml, ok := r.Permissions.(permissions.MenuLister)
	if !ok {
		return nil
	}
	keep := map[string]bool{}
	if opts.Mode != ModeReplace {
		for _, cm := range snap.Resources.Menus {
			if len(cm.Menus) > 0 {
				keep[cm.ClientID] = true
			}
		}
	}
	for _, cl := range snap.Resources.Clients {
		if cl == nil {
			continue
		}
		if opts.Mode != ModeReplace && !keep[cl.ID] {
			continue
		}
		menus, err := ml.GetMenus(ctx, cl.ID)
		if err != nil {
			return fmt.Errorf("snapshot preview: menus[%s]: %w", cl.ID, err)
		}
		if len(menus) == 0 {
			continue
		}
		live.Resources.Menus = append(live.Resources.Menus, ClientMenus{ClientID: cl.ID, Menus: menus})
	}
	return nil
}

// liveNetPolicy fills the live netpolicy slice.
func (r *Restorer) liveNetPolicy(ctx context.Context, snap *Snapshot, opts RestoreOptions, live *Snapshot) error {
	if opts.Mode == ModeReplace {
		all, err := r.NetPolicy.List(ctx)
		if err != nil {
			return fmt.Errorf("snapshot preview: netpolicy.List: %w", err)
		}
		live.Resources.NetPolicy = all
		return nil
	}
	for _, item := range snap.Resources.NetPolicy {
		if item == nil {
			continue
		}
		existing, err := r.NetPolicy.Get(ctx, item.Name)
		if err != nil {
			if errors.Is(err, netpolicy.ErrNotFound) {
				continue
			}
			return fmt.Errorf("snapshot preview: netpolicy.Get(%s): %w", item.Name, err)
		}
		live.Resources.NetPolicy = append(live.Resources.NetPolicy, existing)
	}
	return nil
}

// projectCounts maps one category diff to the counts a restore of mode will
// actually produce. The diff is content-derived and mode-independent except
// for delete enumeration (replace only); this projection is where the mode's
// write semantics land: merge never updates (present entries are Skipped
// even when content differs), overwrite/replace update on difference, and
// only replace deletes.
func projectCounts(mode RestoreMode, d CategoryDiff) CategoryCounts {
	switch mode {
	case ModeMerge:
		return CategoryCounts{Inserted: d.Inserted, Skipped: d.Updated + d.Unchanged}
	case ModeOverwrite:
		return CategoryCounts{Inserted: d.Inserted, Updated: d.Updated, Unchanged: d.Unchanged}
	default:
		return CategoryCounts{Inserted: d.Inserted, Updated: d.Updated, Deleted: d.Deleted, Unchanged: d.Unchanged}
	}
}

// overlayDryRunCounts replaces the probe/optimistic dry-run counts of every
// diff-covered category with the mode-aware projection, making the diff
// engine the single source of truth for the categories it could enumerate.
// Uncovered categories keep the plan's counts untouched.
func overlayDryRunCounts(rep *Report, mode RestoreMode, d *DiffResult) {
	if d == nil {
		return
	}
	for _, cd := range d.Categories {
		// RequiresRotation is a probe-side prediction the diff cannot
		// project (the diff knows nothing about live secrets) — carry it
		// across the overlay so dry-run stays honest.
		projected := projectCounts(mode, cd)
		projected.RequiresRotation = rep.Items[cd.Category].RequiresRotation
		rep.Items[cd.Category] = projected
	}
}
