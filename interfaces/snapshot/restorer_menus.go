package snapshot

import (
	"context"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

func (r *Restorer) restoreMenus(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Permissions == nil {
		return c, nil
	}
	ml, hasLister := r.Permissions.(permissions.MenuLister)

	// ModeReplace reconciles EVERY client in snap.Resources.Clients, not
	// just clients with a ClientMenus entry — see replaceMenus. This MUST
	// run even when snap.Resources.Menus is entirely empty (every exported
	// client happened to have zero menus): that's exactly the case a
	// client's menus were legitimately cleared before the snapshot was
	// taken, and the destination's stale tree still needs wiping.
	if opts.Mode == ModeReplace {
		err := r.replaceMenus(ctx, snap, ml, hasLister, opts.DryRun, &c)
		return c, err
	}

	if len(snap.Resources.Menus) == 0 {
		return c, nil
	}
	for _, cm := range snap.Resources.Menus {
		switch opts.Mode {
		case ModeMerge:
			if err := r.mergeMenus(ctx, cm, ml, hasLister, opts.DryRun, &c); err != nil {
				return c, err
			}
		case ModeOverwrite:
			if err := r.upsertMenus(ctx, cm, ml, hasLister, opts.DryRun, &c); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// replaceMenus sets every client's menu tree from the snapshot's full
// client roster (snap.Resources.Clients) under ModeReplace — including
// clients the snapshot's Menus slice omitted because they had zero menus
// at export time. Those clients get an empty/nil tree via upsertMenus,
// which SetMenus's replace semantics (see permissions.Provider.SetMenus)
// correctly wipe down to nothing rather than leaving stale destination
// menus untouched. (exportMenus only ever emits an entry for a client ID
// drawn from the exporter's client enumeration, so every ClientMenus.ClientID
// is already a member of snap.Resources.Clients.)
func (r *Restorer) replaceMenus(ctx context.Context, snap *Snapshot, ml permissions.MenuLister, hasLister, dryRun bool, c *CategoryCounts) error {
	menusByClient := indexMenusByClient(snap.Resources.Menus)
	for _, cl := range snap.Resources.Clients {
		cm := ClientMenus{ClientID: cl.ID, Menus: menusByClient[cl.ID]}
		if err := r.upsertMenus(ctx, cm, ml, hasLister, dryRun, c); err != nil {
			return err
		}
	}
	return nil
}

// indexMenusByClient builds an O(1)-lookup map from the snapshot's flat
// ClientMenus slice, so replaceMenus doesn't linear-scan it once per client.
func indexMenusByClient(menus []ClientMenus) map[string]permissions.MenuTree {
	idx := make(map[string]permissions.MenuTree, len(menus))
	for _, cm := range menus {
		idx[cm.ClientID] = cm.Menus
	}
	return idx
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
