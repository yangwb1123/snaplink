package snapshot

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// PruneOldest deletes snapshots in storage beyond the keep most-
// recent, returning the names that were deleted (caller logs / audits
// as appropriate). The "most recent" ordering relies on the
// timestamp-prefixed SnapshotID convention emitted by
// newSnapshotID (snap_2006-01-02T15-04-05Z_xxx), which sorts
// lexicographically in time order — operators using a custom name
// generator that doesn't preserve this property MUST not rely on
// this helper without writing their own ordering.
//
// keep <= 0 deletes EVERYTHING in storage (consistent with "retain
// no snapshots"). Caller should guard with a config validation
// rather than passing 0 by accident.
//
// Idempotent: re-running with the same keep value when no new
// snapshots have been added is a no-op (returns empty slice).
// Errors during individual Delete calls don't stop the loop —
// the helper reports the partial-success list and the first
// error. Operators alerting on the error log line can intervene.
func PruneOldest(ctx context.Context, storage Storage, keep int) ([]string, error) {
	if storage == nil {
		return nil, errors.New("snapshot/retention: nil storage")
	}
	names, err := storage.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot/retention: list: %w", err)
	}
	// Filter to names matching the snap_ prefix so custom files in
	// the same directory (operator notes, README, etc.) don't get
	// deleted by mistake.
	snapNames := make([]string, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "snap_") {
			snapNames = append(snapNames, n)
		}
	}
	if len(snapNames) <= keep {
		return nil, nil
	}
	// Sort ascending: oldest first. Delete the first (len - keep)
	// entries; the last `keep` survive.
	sort.Strings(snapNames)
	victims := snapNames[:len(snapNames)-keep]

	var deleted []string
	var firstErr error
	for _, name := range victims {
		select {
		case <-ctx.Done():
			return deleted, ctx.Err()
		default:
		}
		if err := storage.Delete(ctx, name); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("snapshot/retention: delete %s: %w", name, err)
			}
			continue
		}
		deleted = append(deleted, name)
	}
	return deleted, firstErr
}
