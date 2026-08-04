package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func (r *Restorer) stageClients(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Clients == nil || len(snap.Resources.Clients) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	for _, cl := range snap.Resources.Clients {
		switch opts.Mode {
		case ModeMerge:
			if err := r.mergeClient(ctx, cl, opts.DryRun, &c); err != nil {
				return c, err
			}
		case ModeOverwrite, ModeReplace:
			if err := r.upsertClient(ctx, cl, opts.DryRun, &c); err != nil {
				return c, err
			}
		}
	}
	return c, nil
}

// pruneClients deletes destination clients absent from the snapshot
// (ModeReplace, Phase B). The snapshot's IDs form the keep-set.
func (r *Restorer) pruneClients(ctx context.Context, snap *Snapshot, dryRun bool) (CategoryCounts, error) {
	var c CategoryCounts
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
		c.Deleted++
		if !dryRun {
			if err := r.Clients.Delete(ctx, x.ID); err != nil {
				return c, fmt.Errorf("delete %q: %w", x.ID, err)
			}
		}
	}
	return c, nil
}

// mergeClient inserts cl only when absent; existing clients are left
// untouched (ModeMerge).
func (r *Restorer) mergeClient(ctx context.Context, cl *sso.Client, dryRun bool, c *CategoryCounts) error {
	if dryRun {
		if _, err := r.Clients.Get(ctx, cl.ID); err == nil {
			c.Skipped++
		} else {
			c.Inserted++
		}
		return nil
	}
	err := r.Clients.Add(ctx, cl)
	if err == nil {
		c.Inserted++
	} else if errors.Is(err, sso.ErrClientExists) {
		c.Skipped++
	} else {
		return fmt.Errorf("add %q: %w", cl.ID, err)
	}
	return nil
}

// upsertClient inserts cl, or updates it when it already exists
// (ModeOverwrite / ModeReplace), preserving live credentials the
// snapshot can't carry.
func (r *Restorer) upsertClient(ctx context.Context, cl *sso.Client, dryRun bool, c *CategoryCounts) error {
	if dryRun {
		if _, err := r.Clients.Get(ctx, cl.ID); err == nil {
			c.Updated++
		} else {
			c.Inserted++
		}
		return nil
	}
	err := r.Clients.Add(ctx, cl)
	if err == nil {
		c.Inserted++
		return nil
	}
	if !errors.Is(err, sso.ErrClientExists) {
		return fmt.Errorf("add %q: %w", cl.ID, err)
	}
	// Client.Secret + RegistrationAccessToken are json:"-", so a
	// serialized snapshot never carries them. A wholesale Update
	// with the empty incoming values would destroy the live
	// hashed credentials — preserve them from the existing record
	// when the snapshot omits them.
	upd, err := r.preserveClientSecrets(ctx, cl)
	if err != nil {
		return fmt.Errorf("update %q: %w", cl.ID, err)
	}
	if err := r.Clients.Update(ctx, upd); err != nil {
		return fmt.Errorf("update %q: %w", cl.ID, err)
	}
	c.Updated++
	return nil
}

// preserveClientSecrets returns cl with its Secret and
// RegistrationAccessToken backfilled from the live store whenever the
// incoming (snapshot-sourced) values are empty. Because both fields are
// json:"-", a deserialized snapshot always omits them; restoring without
// this would overwrite live credentials with empty strings. The returned
// value is a copy so the snapshot's in-memory client is left untouched
// (a caller may reuse the snapshot). When neither field needs
// backfilling the original cl is returned unchanged.
func (r *Restorer) preserveClientSecrets(ctx context.Context, cl *sso.Client) (*sso.Client, error) {
	if cl == nil || (cl.Secret != "" && cl.RegistrationAccessToken != "") {
		return cl, nil
	}
	existing, err := r.Clients.Get(ctx, cl.ID)
	if err != nil {
		// No live record to carry credentials from (e.g. deleted between
		// the ErrClientExists probe and here): nothing to preserve.
		if errors.Is(err, sso.ErrNoSuchClient) {
			return cl, nil
		}
		return nil, err
	}
	out := *cl
	if out.Secret == "" {
		out.Secret = existing.Secret
	}
	if out.RegistrationAccessToken == "" {
		out.RegistrationAccessToken = existing.RegistrationAccessToken
	}
	return &out, nil
}

func (r *Restorer) stageUsers(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Users == nil || len(snap.Resources.Users) == 0 && opts.Mode != ModeReplace {
		return c, nil
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
// (ModeReplace, Phase B).
func (r *Restorer) pruneUsers(ctx context.Context, snap *Snapshot, dryRun bool) (CategoryCounts, error) {
	var c CategoryCounts
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
		if !dryRun {
			if err := r.Users.Delete(ctx, u.ID); err != nil {
				return c, fmt.Errorf("delete %q: %w", u.ID, err)
			}
		}
		c.Deleted++
	}
	return c, nil
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
