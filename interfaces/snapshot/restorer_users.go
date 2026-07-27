package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func (r *Restorer) restoreUsers(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Users == nil || len(snap.Resources.Users) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		if err := r.pruneUsers(ctx, snap, opts.DryRun, &c); err != nil {
			return c, err
		}
	}

	for _, u := range snap.Resources.Users {
		switch opts.Mode {
		case ModeMerge:
			if err := r.mergeUser(ctx, u, opts.DryRun, &c); err != nil {
				return c, err
			}
		case ModeOverwrite, ModeReplace:
			if err := r.upsertUser(ctx, u, opts.DryRun, &c); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// pruneUsers deletes destination users absent from the snapshot
// (ModeReplace only).
func (r *Restorer) pruneUsers(ctx context.Context, snap *Snapshot, dryRun bool, c *CategoryCounts) error {
	existing, err := r.Users.List(ctx)
	if err != nil {
		return fmt.Errorf("list before replace: %w", err)
	}
	keep := make(map[string]bool, len(snap.Resources.Users))
	for _, u := range snap.Resources.Users {
		keep[u.ID] = true
	}
	for _, u := range existing {
		if keep[u.ID] {
			continue
		}
		if !dryRun {
			if err := r.Users.Delete(ctx, u.ID); err != nil {
				return fmt.Errorf("delete %q: %w", u.ID, err)
			}
		}
		c.Deleted++
	}
	return nil
}

// mergeUser inserts u only when absent (ModeMerge).
func (r *Restorer) mergeUser(ctx context.Context, u *sso.User, dryRun bool, c *CategoryCounts) error {
	present, err := r.userPresent(ctx, u.ID)
	if err != nil {
		return err
	}
	if present {
		c.Skipped++
		return nil
	}
	if !dryRun {
		if err := r.Users.CreateOrUpdate(ctx, u); err != nil {
			return fmt.Errorf("create %q: %w", u.ID, err)
		}
	}
	c.Inserted++
	return nil
}

// upsertUser inserts or updates u (ModeOverwrite / ModeReplace).
func (r *Restorer) upsertUser(ctx context.Context, u *sso.User, dryRun bool, c *CategoryCounts) error {
	present, err := r.userPresent(ctx, u.ID)
	if err != nil {
		return err
	}
	if !dryRun {
		if err := r.Users.CreateOrUpdate(ctx, u); err != nil {
			return fmt.Errorf("upsert %q: %w", u.ID, err)
		}
	}
	if present {
		c.Updated++
	} else {
		c.Inserted++
	}
	return nil
}

// userPresent reports whether a user with id exists in the destination.
// ErrNoSuchUser maps to absent; any other error (a transient backend
// failure — connection reset, timeout) propagates instead of being
// silently treated as "doesn't exist." Without this distinction a
// transient GetByID failure during ModeMerge would fall through to
// CreateOrUpdate and clobber a live user's data with the snapshot's
// stale copy — exactly the destructive behavior ModeMerge promises not
// to do ("leave existing untouched").
func (r *Restorer) userPresent(ctx context.Context, id string) (bool, error) {
	if _, err := r.Users.GetByID(ctx, id); err == nil {
		return true, nil
	} else if !errors.Is(err, sso.ErrNoSuchUser) {
		return false, fmt.Errorf("get %q: %w", id, err)
	}
	return false, nil
}
