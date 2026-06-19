package snapshot

import (
	"context"
	"fmt"

	"github.com/snaplink/sso/permissions"
)

func (r *Restorer) restoreMenus(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Permissions == nil || len(snap.Resources.Menus) == 0 {
		return c, nil
	}
	ml, hasLister := r.Permissions.(permissions.MenuLister)

	for _, cm := range snap.Resources.Menus {
		switch opts.Mode {
		case ModeMerge:
			if err := r.mergeMenus(ctx, cm, ml, hasLister, opts.DryRun, &c); err != nil {
				return c, err
			}
		case ModeOverwrite, ModeReplace:
			if err := r.upsertMenus(ctx, cm, ml, hasLister, opts.DryRun, &c); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// mergeMenus sets cm's menus only when the client has none yet (ModeMerge).
// Without a MenuLister we cannot detect existing menus, so we always set.
func (r *Restorer) mergeMenus(ctx context.Context, cm ClientMenus, ml permissions.MenuLister, hasLister, dryRun bool, c *CategoryCounts) error {
	if hasLister {
		existing, err := ml.GetMenus(ctx, cm.ClientID)
		if err != nil {
			return fmt.Errorf("get menus[%s]: %w", cm.ClientID, err)
		}
		if len(existing) > 0 {
			c.Skipped++
			return nil
		}
	}
	if !dryRun {
		if err := r.Permissions.SetMenus(ctx, cm.ClientID, cm.Menus); err != nil {
			return fmt.Errorf("set menus[%s]: %w", cm.ClientID, err)
		}
	}
	c.Inserted++
	return nil
}

// upsertMenus sets cm's menus unconditionally (ModeOverwrite / ModeReplace),
// counting update vs insert by prior presence when detectable.
func (r *Restorer) upsertMenus(ctx context.Context, cm ClientMenus, ml permissions.MenuLister, hasLister, dryRun bool, c *CategoryCounts) error {
	present := false
	if hasLister {
		existing, err := ml.GetMenus(ctx, cm.ClientID)
		if err == nil && len(existing) > 0 {
			present = true
		}
	}
	if !dryRun {
		if err := r.Permissions.SetMenus(ctx, cm.ClientID, cm.Menus); err != nil {
			return fmt.Errorf("set menus[%s]: %w", cm.ClientID, err)
		}
	}
	if present {
		c.Updated++
	} else {
		c.Inserted++
	}
	return nil
}
