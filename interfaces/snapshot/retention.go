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
// Safety-kind envelopes (header kind == KindSafetySnapshot, read via
// Get + PeekEnvelope) are NEVER pruned: they are the undo artifact of
// a restore and must survive until an operator deletes them explicitly
// via the Delete RPC. keep <= 0 therefore no longer flushes safety
// artifacts — the flush path for those is the explicit Delete RPC.
// This is a behavior change for SDK-direct callers that previously
// used keep <= 0 as "delete everything"; stock wiring already rejects
// keep <= 0 at boot (snapshot.retention.keep must be > 0).
//
// Idempotent: re-running with the same keep value when no new
// snapshots have been added is a no-op (returns empty slice).
// Errors during individual Get/Delete calls don't stop the loop —
// the helper reports the partial-success list and the first error.
// A victim whose header cannot be READ (transient Get fault) is
// SKIPPED — never deleted blind, because a safety envelope that
// cannot be classified must be assumed to be one; a missing envelope
// (ErrSnapshotNotFound) is deletable (Delete is idempotent).
// Operators alerting on the error log line can intervene.
func PruneOldest(ctx context.Context, storage Storage, keep int) ([]string, error) {
	if storage == nil {
		return nil, errors.New("snapshot/retention: nil storage")
	}
	names, err := storage.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("snapshot/retention: list: %w", err)
	}
	victims := retentionVictims(names, keep)
	return pruneSnapshotVictims(ctx, storage, victims)
}

func retentionVictims(names []string, keep int) []string {
	snapNames := make([]string, 0, len(names))
	for _, n := range names {
		if strings.HasPrefix(n, "snap_") {
			snapNames = append(snapNames, n)
		}
	}
	keep = max(keep, 0)
	if len(snapNames) <= keep {
		return nil
	}
	sort.Strings(snapNames)
	return snapNames[:len(snapNames)-keep]
}

func pruneSnapshotVictims(ctx context.Context, storage Storage, victims []string) ([]string, error) {
	var deleted []string
	var firstErr error
	for _, name := range victims {
		select {
		case <-ctx.Done():
			return deleted, ctx.Err()
		default:
		}
		skip, err := victimIsSafety(ctx, storage, name)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("snapshot/retention: get %s: %w", name, err)
			}
			continue
		}
		if skip {
			continue
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

// victimIsSafety classifies one victim via its envelope header without
// decryption. It returns skip=true for safety-kind envelopes. A missing
// envelope (ErrSnapshotNotFound) is NOT safety (nothing to protect) and
// proceeds to delete (idempotent no-op). A transient Get fault returns
// an error so the caller keeps the victim AND reports the fault. An
// undecodable envelope (Get succeeded) is deletable: it is pre-kind-era
// corruption or a half-written Put, and a half-written envelope is never
// a referenced safety net — a capture that failed mid-Put is not
// recorded by any operation.
func victimIsSafety(ctx context.Context, storage Storage, name string) (bool, error) {
	raw, err := storage.Get(ctx, name)
	if err != nil {
		if errors.Is(err, ErrSnapshotNotFound) {
			return false, nil
		}
		return false, err
	}
	env, err := PeekEnvelope(raw)
	if err != nil {
		return false, nil
	}
	return env.Kind == KindSafetySnapshot, nil
}
