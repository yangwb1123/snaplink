package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/platform/netpolicy"
)

func (r *Restorer) stageNetPolicy(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.NetPolicy == nil || len(snap.Resources.NetPolicy) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	for _, p := range snap.Resources.NetPolicy {
		present, err := r.netPolicyPresent(ctx, p.Name)
		if err != nil {
			return c, err
		}
		switch opts.Mode {
		case ModeMerge:
			if present {
				c.Skipped++
				continue
			}
			if err := r.applyNetPolicy(ctx, p, opts.DryRun); err != nil {
				return c, err
			}
			c.Inserted++
		case ModeOverwrite, ModeReplace:
			if err := r.applyNetPolicy(ctx, p, opts.DryRun); err != nil {
				return c, err
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

// pruneNetPolicy deletes destination policies absent from the snapshot
// (ModeReplace, Phase B).
func (r *Restorer) pruneNetPolicy(ctx context.Context, snap *Snapshot, dryRun bool) (CategoryCounts, error) {
	var c CategoryCounts
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
		if !dryRun {
			if err := r.NetPolicy.Delete(ctx, p.Name); err != nil {
				return c, fmt.Errorf("delete %q: %w", p.Name, err)
			}
		}
		c.Deleted++
	}
	return c, nil
}

// netPolicyPresent reports whether a policy with the given name exists.
// ErrNotFound maps to absent; any other error propagates.
func (r *Restorer) netPolicyPresent(ctx context.Context, name string) (bool, error) {
	if _, err := r.NetPolicy.Get(ctx, name); err == nil {
		return true, nil
	} else if !errors.Is(err, netpolicy.ErrNotFound) {
		return false, fmt.Errorf("get %q: %w", name, err)
	}
	return false, nil
}

// applyNetPolicy applies p unless dry-run.
func (r *Restorer) applyNetPolicy(ctx context.Context, p *netpolicy.Policy, dryRun bool) error {
	if dryRun {
		return nil
	}
	if _, err := r.NetPolicy.Apply(ctx, p); err != nil {
		return fmt.Errorf("apply %q: %w", p.Name, err)
	}
	return nil
}
