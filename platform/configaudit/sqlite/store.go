// Package sqlite is a SQLite-backed [configaudit.Store] for durable,
// cross-restart, multi-replica config-change history.
//
// MemoryStore (the package default) is a process-local ring buffer — it
// loses history on restart and isn't shared across replicas. This backend
// persists to the same SQLite file the rest of the SDK already uses for
// identity/OAuth/audit state. Pure-Go via modernc.org/sqlite; no CGO.
package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/configaudit"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite"
)

// migrations is the ordered schema history for this backend. Mirrors
// platform/audit/sqlite's versioned-migration shape: future column/index
// changes append v2, v3, ... here rather than editing the baseline.
var migrations = []migrate.Migration{
	{Version: 1, Name: "baseline_config_history", SQL: schema},
	{Version: 2, Name: "applied_config_baseline", SQL: appliedSchema},
	{Version: 3, Name: "config_canary_state", SQL: canarySchema},
}

// schema mirrors configaudit.Entry field-by-field. The patch (a []Op slice)
// is stored as a JSON blob — it is never queried by field, only rendered
// back whole, so a JSON column avoids a child table for a variable-length
// list.
const schema = `
CREATE TABLE IF NOT EXISTS config_history (
    id          TEXT PRIMARY KEY,
    recorded_at INTEGER NOT NULL,
    actor       TEXT NOT NULL,
    tenant_id   TEXT NOT NULL DEFAULT '',
    resource    TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    patch_json  TEXT NOT NULL,
    prev_hash   TEXT NOT NULL DEFAULT '',
    reason      TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_config_history_recorded_at ON config_history(recorded_at);
CREATE INDEX IF NOT EXISTS idx_config_history_resource     ON config_history(resource);
`

// appliedSchema mirrors configaudit.AppliedVersion field-by-field; the
// redacted snapshot is stored as a JSON blob. Rows are append-only (the
// version chain), with the latest = the highest rowid.
const appliedSchema = `
CREATE TABLE IF NOT EXISTS config_applied (
    id          TEXT PRIMARY KEY,
    applied_at  INTEGER NOT NULL,
    actor       TEXT NOT NULL,
    digest      TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    prev_id     TEXT NOT NULL DEFAULT '',
    snapshot_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_config_applied_applied_at ON config_applied(applied_at);
`

// Store is the SQLite-backed [configaudit.Store].
type Store struct {
	db *sql.DB
}

var _ configaudit.Store = (*Store)(nil)
var _ configaudit.ConditionalRollbackStore = (*Store)(nil)

// New opens dsn, migrates the schema, and returns the store. Caller owns
// Close().
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("configaudit/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configaudit/sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "config_history", migrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("configaudit/sqlite: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB — shared-pool deployments reuse the
// same connection across SDK subsystems.
func NewWithDB(db *sql.DB) (*Store, error) {
	if err := migrate.Run(context.Background(), db, "config_history", migrations); err != nil {
		return nil, fmt.Errorf("configaudit/sqlite: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Record persists e, assigning ID/RecordedAt when the caller left them zero
// (matching MemoryStore's contract).
func (s *Store) Record(ctx context.Context, e configaudit.Entry) error {
	if s == nil || s.db == nil {
		return errors.New("configaudit/sqlite: closed")
	}
	if e.ID == "" {
		e.ID = newEntryID()
	}
	if e.RecordedAt.IsZero() {
		e.RecordedAt = time.Now().UTC()
	}
	patchJSON, err := json.Marshal(e.Patch)
	if err != nil {
		return fmt.Errorf("configaudit/sqlite: marshal patch: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO config_history (
            id, recorded_at, actor, tenant_id, resource, resource_id, patch_json, prev_hash, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.RecordedAt.UnixNano(), e.Actor, e.TenantID, e.Resource, e.ResourceID,
		string(patchJSON), e.PrevHash, e.Reason,
	)
	if err != nil {
		return fmt.Errorf("configaudit/sqlite: insert: %w", err)
	}
	return nil
}

// List returns entries matching f, newest first.
func (s *Store) List(ctx context.Context, f configaudit.Filter) ([]configaudit.Entry, error) {
	if s == nil || s.db == nil {
		return nil, errors.New("configaudit/sqlite: closed")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = configaudit.DefaultMemoryCapacity
	}
	query := `SELECT id, recorded_at, actor, tenant_id, resource, resource_id, patch_json, prev_hash, reason
              FROM config_history WHERE 1=1`
	var args []any
	if f.Resource != "" {
		query += ` AND resource = ?`
		args = append(args, f.Resource)
	}
	if !f.Since.IsZero() {
		query += ` AND recorded_at >= ?`
		args = append(args, f.Since.UnixNano())
	}
	query += ` ORDER BY recorded_at DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("configaudit/sqlite: query: %w", err)
	}
	defer rows.Close()
	return scanEntries(rows)
}

// scanEntries drains rows into Entry values, decoding each row's JSON patch
// blob back into []configaudit.Op.
func scanEntries(rows *sql.Rows) ([]configaudit.Entry, error) {
	var out []configaudit.Entry
	for rows.Next() {
		var (
			e            configaudit.Entry
			recordedAtNS int64
			patchJSON    string
		)
		if err := rows.Scan(&e.ID, &recordedAtNS, &e.Actor, &e.TenantID, &e.Resource, &e.ResourceID, &patchJSON, &e.PrevHash, &e.Reason); err != nil {
			return nil, fmt.Errorf("configaudit/sqlite: scan: %w", err)
		}
		e.RecordedAt = time.Unix(0, recordedAtNS).UTC()
		if patchJSON != "" {
			if err := json.Unmarshal([]byte(patchJSON), &e.Patch); err != nil {
				return nil, fmt.Errorf("configaudit/sqlite: unmarshal patch: %w", err)
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Apply atomically replaces the applied-config baseline with v (linking
// v.PrevID to the current latest) and appends the matching config_history
// entry in ONE transaction: any failure rolls back both, so there is no
// half-state. The history entry's patch is the redacted Diff of the
// redacted baselines (the only forms ever stored).
func (s *Store) Apply(ctx context.Context, v configaudit.AppliedVersion) (configaudit.AppliedVersion, error) {
	if s == nil || s.db == nil {
		return v, errors.New("configaudit/sqlite: closed")
	}
	if v.ID == "" {
		v.ID = newEntryID()
	}
	if v.AppliedAt.IsZero() {
		v.AppliedAt = time.Now().UTC()
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return v, fmt.Errorf("configaudit/sqlite: apply begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	prev, err := latestApplied(ctx, tx)
	if err != nil && !errors.Is(err, configaudit.ErrNoAppliedVersion) {
		return v, err
	}
	if err := rejectObservingCanary(ctx, tx); err != nil {
		return v, err
	}
	v.PrevID = prev.ID
	snapshotJSON, err := json.Marshal(v.Snapshot)
	if err != nil {
		return v, fmt.Errorf("configaudit/sqlite: apply marshal snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO config_applied (id, applied_at, actor, digest, reason, prev_id, snapshot_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.AppliedAt.UnixNano(), v.Actor, v.Digest, v.Reason, v.PrevID, string(snapshotJSON),
	); err != nil {
		return v, fmt.Errorf("configaudit/sqlite: apply insert baseline: %w", err)
	}
	if err := insertApplyEntry(ctx, tx, v, prev); err != nil {
		return v, err
	}
	if err := tx.Commit(); err != nil {
		return v, fmt.Errorf("configaudit/sqlite: apply commit: %w", err)
	}
	return v, nil
}

// Applied returns the latest applied-config baseline, or
// configaudit.ErrNoAppliedVersion before the first Apply.
func (s *Store) Applied(ctx context.Context) (configaudit.AppliedVersion, error) {
	if s == nil || s.db == nil {
		return configaudit.AppliedVersion{}, errors.New("configaudit/sqlite: closed")
	}
	return latestApplied(ctx, s.db)
}

// Rollback re-declares the previous baseline as the new latest (a NEW
// version whose Snapshot is the previous version's), appending the
// config_history entry in the same transaction. ErrNoAppliedVersion when
// there is no baseline or no predecessor.
func (s *Store) Rollback(ctx context.Context, actor, reason string) (configaudit.AppliedVersion, error) {
	return s.rollback(ctx, "", actor, reason)
}

// RollbackIfCurrent performs the atomic expected-version guarded rollback
// used by the explicit operator path.
func (s *Store) RollbackIfCurrent(ctx context.Context, expectedID, actor, reason string) (configaudit.AppliedVersion, error) {
	return s.rollback(ctx, expectedID, actor, reason)
}

func (s *Store) rollback(ctx context.Context, expectedID, actor, reason string) (configaudit.AppliedVersion, error) {
	if s == nil || s.db == nil {
		return configaudit.AppliedVersion{}, errors.New("configaudit/sqlite: closed")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return configaudit.AppliedVersion{}, fmt.Errorf("configaudit/sqlite: rollback begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	cur, err := latestApplied(ctx, tx)
	if err != nil {
		return configaudit.AppliedVersion{}, err
	}
	if err := rejectObservingCanary(ctx, tx); err != nil {
		return configaudit.AppliedVersion{}, err
	}
	if expectedID != "" && cur.ID != expectedID {
		return configaudit.AppliedVersion{}, configaudit.ErrRollbackConflict
	}
	prev, err := rollbackPrevious(ctx, tx, cur)
	if err != nil {
		return configaudit.AppliedVersion{}, err
	}
	v := configaudit.AppliedVersion{
		ID:        newEntryID(),
		AppliedAt: time.Now().UTC(),
		Actor:     actor,
		Digest:    prev.Digest,
		Reason:    reason,
		PrevID:    cur.ID,
		Snapshot:  prev.Snapshot,
	}
	if err := insertRollbackVersion(ctx, tx, v, cur); err != nil {
		return configaudit.AppliedVersion{}, err
	}
	if err := tx.Commit(); err != nil {
		return configaudit.AppliedVersion{}, fmt.Errorf("configaudit/sqlite: rollback commit: %w", err)
	}
	return v, nil
}

func insertRollbackVersion(ctx context.Context, tx *sql.Tx, v, cur configaudit.AppliedVersion) error {
	snapshotJSON, err := json.Marshal(v.Snapshot)
	if err != nil {
		return fmt.Errorf("configaudit/sqlite: rollback marshal snapshot: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO config_applied (id, applied_at, actor, digest, reason, prev_id, snapshot_json)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.AppliedAt.UnixNano(), v.Actor, v.Digest, v.Reason, cur.ID, string(snapshotJSON),
	); err != nil {
		return fmt.Errorf("configaudit/sqlite: rollback insert baseline: %w", err)
	}
	return insertApplyEntry(ctx, tx, v, cur)
}

// latestApplied reads the newest config_applied row from db (a *sql.DB or
// *sql.Tx — both satisfy the queryer interface). ErrNoAppliedVersion when
// the table is empty.
func latestApplied(ctx context.Context, q queryer) (configaudit.AppliedVersion, error) {
	return scanApplied(ctx, q, `SELECT id, applied_at, actor, digest, reason, prev_id, snapshot_json
        FROM config_applied ORDER BY applied_at DESC, rowid DESC LIMIT 1`)
}

// appliedByID reads one config_applied row by id.
func appliedByID(ctx context.Context, q queryer, id string) (configaudit.AppliedVersion, error) {
	return scanApplied(ctx, q, `SELECT id, applied_at, actor, digest, reason, prev_id, snapshot_json
        FROM config_applied WHERE id = ?`, id)
}

// scanApplied runs query and scans the first row into an AppliedVersion.
func scanApplied(ctx context.Context, q queryer, query string, args ...any) (configaudit.AppliedVersion, error) {
	var (
		v            configaudit.AppliedVersion
		appliedAtNS  int64
		snapshotJSON string
	)
	row := q.QueryRowContext(ctx, query, args...)
	err := row.Scan(&v.ID, &appliedAtNS, &v.Actor, &v.Digest, &v.Reason, &v.PrevID, &snapshotJSON)
	if errors.Is(err, sql.ErrNoRows) {
		return configaudit.AppliedVersion{}, configaudit.ErrNoAppliedVersion
	}
	if err != nil {
		return configaudit.AppliedVersion{}, fmt.Errorf("configaudit/sqlite: scan applied: %w", err)
	}
	v.AppliedAt = time.Unix(0, appliedAtNS).UTC()
	if snapshotJSON != "" {
		if err := json.Unmarshal([]byte(snapshotJSON), &v.Snapshot); err != nil {
			return configaudit.AppliedVersion{}, fmt.Errorf("configaudit/sqlite: unmarshal snapshot: %w", err)
		}
	}
	return v, nil
}

// insertApplyEntry appends the config_history row for an apply/rollback:
// resource "config", the redacted patch Diff(prev, new) — computed here,
// inside the store's transaction, so a concurrent apply can never link the
// wrong before/after pair (the read-modify-write is atomic).
func insertApplyEntry(ctx context.Context, tx *sql.Tx, v configaudit.AppliedVersion, prev configaudit.AppliedVersion) error {
	entry := configaudit.Entry{
		ID:         newEntryID(),
		RecordedAt: v.AppliedAt,
		Actor:      v.Actor,
		Resource:   "config",
		ResourceID: v.ID,
		Patch:      configaudit.RedactOps(configaudit.Diff(prev.Snapshot, v.Snapshot)),
		Reason:     v.Reason,
	}
	patchJSON, err := json.Marshal(entry.Patch)
	if err != nil {
		return fmt.Errorf("configaudit/sqlite: marshal patch: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
        INSERT INTO config_history (
            id, recorded_at, actor, tenant_id, resource, resource_id, patch_json, prev_hash, reason
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.ID, entry.RecordedAt.UnixNano(), entry.Actor, entry.TenantID, entry.Resource,
		entry.ResourceID, string(patchJSON), entry.PrevHash, entry.Reason,
	); err != nil {
		return fmt.Errorf("configaudit/sqlite: insert apply history: %w", err)
	}
	return nil
}

// queryer is the minimal *sql.DB / *sql.Tx shared interface scanApplied and
// latestApplied need.
type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// newEntryID mints a random hex ID, mirroring configaudit.MemoryStore's
// (unexported) ID generation so IDs from either backend look the same.
func newEntryID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
