package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
)

// connectionHealthSchema is migration v3: one row per connection holding the
// LAST recorded admin-triggered probe outcome. A single UPSERT keeps this
// simple (unlike connection_domain_claims, health has no multi-row history —
// only "the current state" is exposed).
const connectionHealthSchema = `
CREATE TABLE IF NOT EXISTS connection_health (
    connection_id   TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'unknown',
    last_checked_at TEXT,
    last_success_at TEXT,
    last_error      TEXT NOT NULL DEFAULT ''
);
`

// Health implements connections.Store. Never a store-miss: an id with no
// recorded probe yet (no row) reads back connections.DefaultConnectionHealth.
func (s *Store) Health(ctx context.Context, id string) (*connections.ConnectionHealth, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT connection_id, status, last_checked_at, last_success_at, last_error
		 FROM connection_health WHERE connection_id = ?`, id)
	h, err := scanHealth(row)
	if errors.Is(err, sql.ErrNoRows) {
		return connections.DefaultConnectionHealth(id), nil
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: health: %w", err)
	}
	return h, nil
}

// RecordHealth implements connections.Store.
func (s *Store) RecordHealth(ctx context.Context, id string, h *connections.ConnectionHealth) error {
	if h == nil {
		return errors.New("connections: health record required")
	}
	if _, err := s.db.ExecContext(ctx, `
        INSERT INTO connection_health (connection_id, status, last_checked_at, last_success_at, last_error)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(connection_id) DO UPDATE SET
            status=excluded.status, last_checked_at=excluded.last_checked_at,
            last_success_at=excluded.last_success_at, last_error=excluded.last_error`,
		id, string(h.Status), timeOrNull(h.LastCheckedAt), timeOrNull(h.LastSuccessAt), h.LastError); err != nil {
		return fmt.Errorf("sqlite: record health: %w", err)
	}
	return nil
}

// timeOrNull renders a zero time.Time as SQL NULL (rather than the epoch
// string) so scanHealth can round-trip "never" distinctly from "checked at
// the Unix epoch".
func timeOrNull(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func scanHealth(sc scanner) (*connections.ConnectionHealth, error) {
	var (
		h                            connections.ConnectionHealth
		status                       string
		lastCheckedAt, lastSuccessAt sql.NullString
	)
	if err := sc.Scan(&h.ConnectionID, &status, &lastCheckedAt, &lastSuccessAt, &h.LastError); err != nil {
		return nil, err
	}
	h.Status = connections.HealthStatus(status)
	if lastCheckedAt.Valid {
		h.LastCheckedAt = parseTime(lastCheckedAt.String)
	}
	if lastSuccessAt.Valid {
		h.LastSuccessAt = parseTime(lastSuccessAt.String)
	}
	return &h, nil
}
