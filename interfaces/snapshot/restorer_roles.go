package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

func (r *Restorer) restoreRoles(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Permissions == nil {
		return c, nil
	}
	if len(snap.Resources.Roles) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		if err := r.pruneRoles(ctx, snap, opts.DryRun, &c); err != nil {
			return c, err
		}
	}

	for _, cr := range snap.Resources.Roles {
		for _, role := range cr.Roles {
			switch opts.Mode {
			case ModeMerge:
				if err := r.mergeRole(ctx, cr.ClientID, role, opts.DryRun, &c); err != nil {
					return c, err
				}
			case ModeOverwrite, ModeReplace:
				if err := r.upsertRole(ctx, cr.ClientID, role, opts.DryRun, &c); err != nil {
					return c, err
				}
			}
		}
	}
	return c, nil
}

// pruneRoles wipes per-client roles before re-seeding. Replace reconciles
// EVERY client in snap.Resources.Clients — the full roster the snapshot
// covers — not just clients that happen to have a non-empty ClientRoles
// entry. A client legitimately reduced to zero roles at export time still
// needs its destination roles wiped down to nothing; keying the prune off
// snap.Resources.Roles alone would silently leave stale grants in place.
// (exportRoles only ever emits an entry for a client ID drawn from the
// exporter's client enumeration, so every ClientRoles.ClientID is already
// a member of snap.Resources.Clients — indexing by the roster can't miss
// an entry the exporter produced.)
func (r *Restorer) pruneRoles(ctx context.Context, snap *Snapshot, dryRun bool, c *CategoryCounts) error {
	rolesByClient := indexRolesByClient(snap.Resources.Roles)
	for _, cl := range snap.Resources.Clients {
		if err := r.pruneClientRoles(ctx, cl.ID, rolesByClient[cl.ID], dryRun, c); err != nil {
			return err
		}
	}
	return nil
}

// indexRolesByClient builds an O(1)-lookup map from the snapshot's flat
// ClientRoles slice, so pruneRoles doesn't linear-scan it once per client.
func indexRolesByClient(roles []ClientRoles) map[string][]permissions.Role {
	idx := make(map[string][]permissions.Role, len(roles))
	for _, cr := range roles {
		idx[cr.ClientID] = cr.Roles
	}
	return idx
}

// pruneClientRoles deletes any role currently defined under clientID that
// isn't in want (the snapshot's desired set — nil/empty means "prune
// everything").
func (r *Restorer) pruneClientRoles(ctx context.Context, clientID string, want []permissions.Role, dryRun bool, c *CategoryCounts) error {
	cur, err := r.Permissions.ListAllRoles(ctx, clientID)
	if err != nil {
		return fmt.Errorf("list roles[%s]: %w", clientID, err)
	}
	keep := make(map[string]bool, len(want))
	for _, x := range want {
		keep[x.Code] = true
	}
	for _, x := range cur {
		if keep[x.Code] {
			continue
		}
		if !dryRun {
			if err := r.Permissions.RemoveRole(ctx, clientID, x.Code); err != nil {
				return fmt.Errorf("remove role[%s/%s]: %w", clientID, x.Code, err)
			}
		}
		c.Deleted++
	}
	return nil
}

// mergeRole adds role only when absent (ModeMerge). Dry-run cannot
// introspect existence without a Get, so it optimistically counts insert.
func (r *Restorer) mergeRole(ctx context.Context, clientID string, role permissions.Role, dryRun bool, c *CategoryCounts) error {
	if dryRun {
		c.Inserted++
		return nil
	}
	err := r.Permissions.AddRole(ctx, clientID, role)
	if err == nil {
		c.Inserted++
	} else if errors.Is(err, permissions.ErrRoleExists) {
		c.Skipped++
	} else {
		return fmt.Errorf("add role[%s/%s]: %w", clientID, role.Code, err)
	}
	return nil
}

// upsertRole adds role, or updates it when present (ModeOverwrite / ModeReplace).
func (r *Restorer) upsertRole(ctx context.Context, clientID string, role permissions.Role, dryRun bool, c *CategoryCounts) error {
	if dryRun {
		c.Inserted++
		return nil
	}
	err := r.Permissions.AddRole(ctx, clientID, role)
	if err == nil {
		c.Inserted++
		return nil
	}
	if !errors.Is(err, permissions.ErrRoleExists) {
		return fmt.Errorf("add role[%s/%s]: %w", clientID, role.Code, err)
	}
	if err := r.Permissions.UpdateRole(ctx, clientID, role); err != nil {
		return fmt.Errorf("update role[%s/%s]: %w", clientID, role.Code, err)
	}
	c.Updated++
	return nil
}
