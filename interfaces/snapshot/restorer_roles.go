package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso/domains/permissions"
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

// pruneRoles wipes per-client roles before re-seeding. Replace applies
// *only* to clients that appear in the snapshot — role definitions for
// clients absent from the snapshot are left intact.
func (r *Restorer) pruneRoles(ctx context.Context, snap *Snapshot, dryRun bool, c *CategoryCounts) error {
	for _, cr := range snap.Resources.Roles {
		cur, err := r.Permissions.ListAllRoles(ctx, cr.ClientID)
		if err != nil {
			return fmt.Errorf("list roles[%s]: %w", cr.ClientID, err)
		}
		keep := make(map[string]bool, len(cr.Roles))
		for _, x := range cr.Roles {
			keep[x.Code] = true
		}
		for _, x := range cur {
			if keep[x.Code] {
				continue
			}
			if !dryRun {
				if err := r.Permissions.RemoveRole(ctx, cr.ClientID, x.Code); err != nil {
					return fmt.Errorf("remove role[%s/%s]: %w", cr.ClientID, x.Code, err)
				}
			}
			c.Deleted++
		}
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
