package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/configaudit"
)

const canarySchema = `
CREATE TABLE IF NOT EXISTS config_canary (
    slot                INTEGER PRIMARY KEY CHECK (slot = 1),
    id                  TEXT NOT NULL,
    version_id          TEXT NOT NULL,
    previous_version_id TEXT NOT NULL DEFAULT '',
    actor               TEXT NOT NULL,
    digest              TEXT NOT NULL,
    reason              TEXT NOT NULL,
    started_at          INTEGER NOT NULL,
    deadline            INTEGER NOT NULL,
    status              TEXT NOT NULL,
    detail              TEXT NOT NULL DEFAULT ''
);`

var _ configaudit.CanaryStore = (*Store)(nil)

func observingCanary(ctx context.Context, q queryer) (bool, error) {
	var status string
	err := q.QueryRowContext(ctx, `SELECT status FROM config_canary WHERE slot = 1`).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("configaudit/sqlite: scan canary status: %w", err)
	}
	return status == string(configaudit.CanaryObserving), nil
}

func rejectObservingCanary(ctx context.Context, q queryer) error {
	active, err := observingCanary(ctx, q)
	if err != nil {
		return err
	}
	if active {
		return configaudit.ErrCanaryInProgress
	}
	return nil
}

func rollbackPrevious(ctx context.Context, q queryer, cur configaudit.AppliedVersion) (configaudit.AppliedVersion, error) {
	if cur.PrevID == "" {
		return configaudit.AppliedVersion{}, configaudit.ErrNoAppliedVersion
	}
	return appliedByID(ctx, q, cur.PrevID)
}

// BeginCanary atomically writes the candidate baseline and observing record.
func (s *Store) BeginCanary(ctx context.Context, v configaudit.AppliedVersion, state configaudit.CanaryState) (configaudit.AppliedVersion, configaudit.CanaryState, error) {
	if s == nil || s.db == nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, errors.New("configaudit/sqlite: closed")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, fmt.Errorf("configaudit/sqlite: canary begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := rejectObservingCanary(ctx, tx); err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, err
	}
	prev, err := latestApplied(ctx, tx)
	if errors.Is(err, configaudit.ErrNoAppliedVersion) {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, configaudit.ErrCanaryNoBaseline
	}
	if err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, err
	}
	if v.ID == "" {
		v.ID = newEntryID()
	}
	if v.AppliedAt.IsZero() {
		v.AppliedAt = time.Now().UTC()
	}
	v.PrevID = prev.ID
	state = normalizeState(state, v, prev)
	if err := insertVersion(ctx, tx, v, prev); err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, err
	}
	if err := replaceCanary(ctx, tx, state); err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, err
	}
	if err := tx.Commit(); err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, fmt.Errorf("configaudit/sqlite: canary commit: %w", err)
	}
	return v, state, nil
}

// Canary returns the latest persisted lifecycle record.
func (s *Store) Canary(ctx context.Context) (configaudit.CanaryState, error) {
	if s == nil || s.db == nil {
		return configaudit.CanaryState{}, errors.New("configaudit/sqlite: closed")
	}
	return loadCanary(ctx, s.db)
}

// ConfirmCanary transitions one observing record to confirmed.
func (s *Store) ConfirmCanary(ctx context.Context, id string) error {
	if s == nil || s.db == nil {
		return errors.New("configaudit/sqlite: closed")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("configaudit/sqlite: confirm begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	state, err := loadCanary(ctx, tx)
	if err != nil {
		return err
	}
	if state.ID != id || state.Status != configaudit.CanaryObserving {
		return configaudit.ErrCanaryConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE config_canary SET status = ? WHERE slot = 1`, string(configaudit.CanaryConfirmed)); err != nil {
		return fmt.Errorf("configaudit/sqlite: confirm update: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("configaudit/sqlite: confirm commit: %w", err)
	}
	return nil
}

// RollbackCanary restores the candidate's predecessor and marks the state
// rolled_back in one transaction.
func (s *Store) RollbackCanary(ctx context.Context, id, actor, reason string) (configaudit.AppliedVersion, configaudit.CanaryState, error) {
	if s == nil || s.db == nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, errors.New("configaudit/sqlite: closed")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, fmt.Errorf("configaudit/sqlite: canary rollback begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	state, err := loadCanary(ctx, tx)
	if err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, err
	}
	cur, err := latestApplied(ctx, tx)
	if err != nil {
		return configaudit.AppliedVersion{}, configaudit.CanaryState{}, err
	}
	if state.ID != id || state.Status != configaudit.CanaryObserving || cur.ID != state.VersionID || cur.PrevID != state.PreviousVersionID {
		return configaudit.AppliedVersion{}, state, configaudit.ErrCanaryConflict
	}
	prev, err := rollbackPrevious(ctx, tx, cur)
	if err != nil {
		return configaudit.AppliedVersion{}, state, err
	}
	v := configaudit.AppliedVersion{
		ID: newEntryID(), AppliedAt: time.Now().UTC(), Actor: actor,
		Digest: prev.Digest, Reason: reason, PrevID: cur.ID, Snapshot: prev.Snapshot,
	}
	if err := insertVersion(ctx, tx, v, cur); err != nil {
		return configaudit.AppliedVersion{}, state, err
	}
	state.Status = configaudit.CanaryRolledBack
	state.Detail = reason
	if err := replaceCanary(ctx, tx, state); err != nil {
		return configaudit.AppliedVersion{}, state, err
	}
	if err := tx.Commit(); err != nil {
		return configaudit.AppliedVersion{}, state, fmt.Errorf("configaudit/sqlite: canary rollback commit: %w", err)
	}
	return v, state, nil
}

func normalizeState(state configaudit.CanaryState, v, prev configaudit.AppliedVersion) configaudit.CanaryState {
	if state.ID == "" {
		state.ID = newEntryID()
	}
	state.VersionID, state.PreviousVersionID = v.ID, prev.ID
	if state.StartedAt.IsZero() {
		state.StartedAt = v.AppliedAt
	}
	if state.Deadline.IsZero() {
		state.Deadline = state.StartedAt.Add(configaudit.DefaultCanaryWindow)
	}
	state.Status = configaudit.CanaryObserving
	return state
}

func insertVersion(ctx context.Context, tx *sql.Tx, v, prev configaudit.AppliedVersion) error {
	snapshotJSON, err := jsonMarshal(v.Snapshot)
	if err != nil {
		return fmt.Errorf("configaudit/sqlite: canary marshal snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO config_applied (id, applied_at, actor, digest, reason, prev_id, snapshot_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.AppliedAt.UnixNano(), v.Actor, v.Digest, v.Reason, v.PrevID, snapshotJSON,
	); err != nil {
		return fmt.Errorf("configaudit/sqlite: canary insert baseline: %w", err)
	}
	return insertApplyEntry(ctx, tx, v, prev)
}

func replaceCanary(ctx context.Context, tx *sql.Tx, state configaudit.CanaryState) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM config_canary WHERE slot = 1`); err != nil {
		return fmt.Errorf("configaudit/sqlite: canary clear state: %w", err)
	}
	_, err := tx.ExecContext(ctx, `
        INSERT INTO config_canary (slot, id, version_id, previous_version_id, actor, digest, reason, started_at, deadline, status, detail)
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		state.ID, state.VersionID, state.PreviousVersionID, state.Actor, state.Digest,
		state.Reason, state.StartedAt.UnixNano(), state.Deadline.UnixNano(), state.Status, state.Detail,
	)
	if err != nil {
		return fmt.Errorf("configaudit/sqlite: canary save state: %w", err)
	}
	return nil
}

func loadCanary(ctx context.Context, q queryer) (configaudit.CanaryState, error) {
	var (
		state                   configaudit.CanaryState
		startedAtNS, deadlineNS int64
		status                  string
	)
	err := q.QueryRowContext(ctx, `
        SELECT id, version_id, previous_version_id, actor, digest, reason, started_at, deadline, status, detail
        FROM config_canary WHERE slot = 1`).Scan(
		&state.ID, &state.VersionID, &state.PreviousVersionID, &state.Actor, &state.Digest,
		&state.Reason, &startedAtNS, &deadlineNS, &status, &state.Detail,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return configaudit.CanaryState{}, configaudit.ErrNoCanary
	}
	if err != nil {
		return configaudit.CanaryState{}, fmt.Errorf("configaudit/sqlite: scan canary: %w", err)
	}
	state.StartedAt = time.Unix(0, startedAtNS).UTC()
	state.Deadline = time.Unix(0, deadlineNS).UTC()
	state.Status = configaudit.CanaryStatus(status)
	return state, nil
}

// Keep JSON encoding in this file's small helper so all canary writes share
// the same error wrapping without importing implementation details elsewhere.
func jsonMarshal(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
