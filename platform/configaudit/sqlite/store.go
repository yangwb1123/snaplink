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

	"github.com/snaplink/sso/platform/configaudit"
	"github.com/snaplink/sso/platform/migrate"

	_ "modernc.org/sqlite"
)

// migrations is the ordered schema history for this backend. Mirrors
// platform/audit/sqlite's versioned-migration shape: future column/index
// changes append v2, v3, ... here rather than editing the baseline.
var migrations = []migrate.Migration{
	{Version: 1, Name: "baseline_config_history", SQL: schema},
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

// Store is the SQLite-backed [configaudit.Store].
type Store struct {
	db *sql.DB
}

var _ configaudit.Store = (*Store)(nil)

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

// newEntryID mints a random hex ID, mirroring configaudit.MemoryStore's
// (unexported) ID generation so IDs from either backend look the same.
func newEntryID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
