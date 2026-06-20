package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso/interfaces/sso"
)

func (r *Restorer) restoreClients(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Clients == nil || len(snap.Resources.Clients) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		if err := r.pruneClients(ctx, snap, opts.DryRun, &c); err != nil {
			return c, err
		}
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
// (ModeReplace only). The snapshot's IDs form the keep-set.
func (r *Restorer) pruneClients(ctx context.Context, snap *Snapshot, dryRun bool, c *CategoryCounts) error {
	existing, err := r.Clients.List(ctx)
	if err != nil {
		return fmt.Errorf("list before replace: %w", err)
	}
	keep := make(map[string]bool, len(snap.Resources.Clients))
	for _, x := range snap.Resources.Clients {
		keep[x.ID] = true
	}
	for _, x := range existing {
		if keep[x.ID] {
			continue
		}
		if !dryRun {
			if err := r.Clients.Delete(ctx, x.ID); err != nil {
				return fmt.Errorf("delete %q: %w", x.ID, err)
			}
		}
		c.Deleted++
	}
	return nil
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
