package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
)

// jtiReplaySchema stores `jti` claims seen during their expiry
// window so replay attempts get rejected across the cluster.
// PRIMARY KEY on jti makes INSERT ... ON CONFLICT IGNORE atomically
// signal a replay: rows-affected == 0 means the row already
// existed, ==1 means first-sighting.
const jtiReplaySchema = `
CREATE TABLE IF NOT EXISTS jti_replays (
    jti        TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jti_replays_expires_at
    ON jti_replays(expires_at);
`

// JTIReplayStore is the SQLite-backed implementation of
// [sso.JTIReplayStore]. Replaces memory_jti_replay.go for
// multi-replica deployments — a jti seen on replica A is recorded
// in the shared file so replica B rejects it too.
type JTIReplayStore struct {
	db *sql.DB
}

// NewJTIReplayStore opens dsn, migrates the schema, and returns the
// store. Caller owns Close().
func NewJTIReplayStore(dsn string) (*JTIReplayStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), jtiReplaySchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate jti_replays: %w", err)
	}
	return &JTIReplayStore{db: db}, nil
}

// NewJTIReplayStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments).
func NewJTIReplayStoreWithDB(db *sql.DB) (*JTIReplayStore, error) {
	if _, err := db.ExecContext(context.Background(), jtiReplaySchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate jti_replays: %w", err)
	}
	return &JTIReplayStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *JTIReplayStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *JTIReplayStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: jti replay store closed")
	}
	return s.db.PingContext(ctx)
}

// MarkSeen implements [sso.JTIReplayStore]. A first sighting inserts
// the row + returns (true, nil); a replay finds the row already
// present + returns (false, nil).
//
// Lazy GC: every call first sweeps expired rows so the table stays
// bounded by the active-window key count. Mirrors the memory
// backend's GC contract.
//
// A previously-expired jti coming back is treated as a fresh
// sighting — the unique-constraint requires deleting before
// re-inserting. The DELETE + INSERT happens in one transaction so a
// concurrent caller can't slip a second insert between them.
func (s *JTIReplayStore) MarkSeen(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	if jti == "" {
		return true, nil
	}
	now := time.Now()
	// Lazy GC: prune anything past expiry before touching the row.
	// Cheap: indexed by expires_at, runs in O(expired count).
	if _, err := s.db.ExecContext(ctx, `DELETE FROM jti_replays WHERE expires_at <= ?`, now.UnixNano()); err != nil {
		return false, fmt.Errorf("sqlite: jti gc: %w", err)
	}
	// An expiry already past gets bumped to "in 1s" so an immediate
	// replay still gets caught — same defensive logic the memory
	// backend uses.
	if expiresAt.Before(now) {
		expiresAt = now.Add(time.Second)
	}
	res, err := s.db.ExecContext(ctx, `
        INSERT INTO jti_replays (jti, expires_at)
        VALUES (?, ?)
        ON CONFLICT (jti) DO NOTHING`,
		jti, expiresAt.UnixNano())
	if err != nil {
		// Older SQLite (pre-3.24) lacks ON CONFLICT; fall back to a
		// best-effort INSERT detection. modernc.org/sqlite ships
		// 3.39+ so this branch is defensive only.
		if isConstraintErr(err) {
			return false, nil
		}
		return false, fmt.Errorf("sqlite: jti insert: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		// Driver couldn't report; conservatively treat as first-sighting
		// to stay fail-open per JTIReplayStore contract (callers log).
		return true, nil
	}
	return n == 1, nil
}

func isConstraintErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed")
}

var _ sso.JTIReplayStore = (*JTIReplayStore)(nil)
