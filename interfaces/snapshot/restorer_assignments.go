package snapshot

import (
	"context"
	"errors"
	"fmt"

	"github.com/snaplink/sso/domains/permissions"
)

func (r *Restorer) restoreAssignments(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var c CategoryCounts
	if r.Permissions == nil {
		return c, nil
	}
	if len(snap.Resources.Assignments) == 0 && opts.Mode != ModeReplace {
		return c, nil
	}

	if opts.Mode == ModeReplace {
		if err := r.pruneAssignments(ctx, snap, opts.DryRun, &c); err != nil {
			return c, err
		}
	}

	for _, ca := range snap.Resources.Assignments {
		for _, a := range ca.Assignments {
			switch opts.Mode {
			case ModeMerge:
				if err := r.mergeAssignment(ctx, ca.ClientID, a, opts.DryRun, &c); err != nil {
					return c, err
				}
			case ModeOverwrite, ModeReplace:
				if err := r.upsertAssignment(ctx, ca.ClientID, a, opts.DryRun, &c); err != nil {
					return c, err
				}
			}
		}
	}
	return c, nil
}

// pruneAssignments drops assignments for any (client, user) pair currently
// present but absent from the snapshot. Replace reconciles EVERY client in
// snap.Resources.Clients — not just clients with a non-empty
// ClientAssignments entry — for the same reason pruneRoles does: a client
// legitimately reduced to zero assignments at export time must still have
// its destination assignments wiped, not left untouched. (exportAssignments
// only ever emits an entry for a client ID drawn from the exporter's client
// enumeration, so every ClientAssignments.ClientID is already a member of
// snap.Resources.Clients.)
func (r *Restorer) pruneAssignments(ctx context.Context, snap *Snapshot, dryRun bool, c *CategoryCounts) error {
	assignmentsByClient := indexAssignmentsByClient(snap.Resources.Assignments)
	for _, cl := range snap.Resources.Clients {
		if err := r.pruneClientAssignments(ctx, cl.ID, assignmentsByClient[cl.ID], dryRun, c); err != nil {
			return err
		}
	}
	return nil
}

// indexAssignmentsByClient builds an O(1)-lookup map from the snapshot's
// flat ClientAssignments slice, so pruneAssignments doesn't linear-scan it
// once per client.
func indexAssignmentsByClient(as []ClientAssignments) map[string][]permissions.Assignment {
	idx := make(map[string][]permissions.Assignment, len(as))
	for _, ca := range as {
		idx[ca.ClientID] = ca.Assignments
	}
	return idx
}

// pruneClientAssignments unassigns any (user, roles) currently held under
// clientID that isn't in want (the snapshot's desired set — nil/empty
// means "prune everything").
func (r *Restorer) pruneClientAssignments(ctx context.Context, clientID string, want []permissions.Assignment, dryRun bool, c *CategoryCounts) error {
	existing, err := r.Permissions.ListAssignments(ctx, clientID)
	if err != nil {
		return fmt.Errorf("list assignments[%s]: %w", clientID, err)
	}
	keep := make(map[string]bool, len(want))
	for _, a := range want {
		keep[a.UserID] = true
	}
	for _, e := range existing {
		if keep[e.UserID] {
			continue
		}
		if !dryRun {
			if err := r.Permissions.UnassignRoles(ctx, e.UserID, clientID, e.Roles); err != nil {
				return fmt.Errorf("unassign[%s/%s]: %w", clientID, e.UserID, err)
			}
		}
		c.Deleted++
	}
	return nil
}

// mergeAssignment unions the snapshot's roles with whatever the user
// already holds (ModeMerge); a no-op when the snapshot adds nothing new.
func (r *Restorer) mergeAssignment(ctx context.Context, clientID string, a permissions.Assignment, dryRun bool, c *CategoryCounts) error {
	existing, err := r.existingRoleSet(ctx, clientID, a.UserID)
	if err != nil {
		return err
	}
	// If everything in the snapshot is already assigned, nothing to do.
	if !rolesAddAny(a.Roles, existing) && len(existing) > 0 {
		c.Skipped++
		return nil
	}
	// Build the union: snapshot roles first, then existing ones we don't
	// already carry from the snapshot.
	union := append([]string(nil), a.Roles...)
	if len(existing) > 0 {
		for code := range existing {
			union = appendUnique(union, code)
		}
	}
	if !dryRun {
		if err := r.Permissions.AssignRoles(ctx, a.UserID, clientID, union); err != nil {
			return fmt.Errorf("assign[%s/%s]: %w", clientID, a.UserID, err)
		}
	}
	if len(existing) > 0 {
		c.Updated++
	} else {
		c.Inserted++
	}
	return nil
}

// existingRoleSet returns the set of role codes the user currently holds
// for clientID. A missing user is not an error (empty set).
func (r *Restorer) existingRoleSet(ctx context.Context, clientID, userID string) (map[string]bool, error) {
	cur, err := r.Permissions.Roles(ctx, userID, clientID)
	existing := make(map[string]bool)
	if err == nil {
		for _, role := range cur {
			existing[role.Code] = true
		}
		return existing, nil
	}
	if !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, fmt.Errorf("get roles[%s/%s]: %w", clientID, userID, err)
	}
	return existing, nil
}

// rolesAddAny reports whether any code in roles is not already in have.
func rolesAddAny(roles []string, have map[string]bool) bool {
	for _, code := range roles {
		if !have[code] {
			return true
		}
	}
	return false
}

// upsertAssignment replaces the user's roles with the snapshot's set
// (ModeOverwrite / ModeReplace).
func (r *Restorer) upsertAssignment(ctx context.Context, clientID string, a permissions.Assignment, dryRun bool, c *CategoryCounts) error {
	present := false
	if cur, err := r.Permissions.Roles(ctx, a.UserID, clientID); err == nil && len(cur) > 0 {
		present = true
	}
	if !dryRun {
		if err := r.Permissions.AssignRoles(ctx, a.UserID, clientID, a.Roles); err != nil {
			return fmt.Errorf("assign[%s/%s]: %w", clientID, a.UserID, err)
		}
	}
	if present {
		c.Updated++
	} else {
		c.Inserted++
	}
	return nil
}
