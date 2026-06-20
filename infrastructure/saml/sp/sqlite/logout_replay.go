package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	samlsp "github.com/snaplink/sso/saml/sp"
)

// spLogoutReplaySchema dedups inbound IdP-initiated LogoutRequest IDs on the SP
// side, across replicas. Same shape as the assertion-replay table (PRIMARY KEY
// id + expires_at) but a SEPARATE table/namespace so the two distinct ID spaces
// (AssertionID vs LogoutRequest ID) can never collide — wiring AssertionIDs and
// LogoutRequest IDs into one table would let a LogoutRequest whose id happened to
// equal a prior AssertionID read as a replay (or vice versa).
const spLogoutReplaySchema = `
CREATE TABLE IF NOT EXISTS saml_sp_logout_replays (
    id         TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_sp_logout_replays_expires_at
    ON saml_sp_logout_replays(expires_at);
`

// LogoutReplayStore is the SQLite-backed, cross-replica peer of the SP-side
// in-memory logout replay store (the second *replayStore the SPAuthenticator
// holds, for inbound IdP-initiated LogoutRequest IDs). Wire via
// sp.SPConfig.LogoutReplayStore. It shares the AssertionReplayStore's race-free
// atomic + FAIL-CLOSED posture (see CheckAndRemember / checkAndRemember) — a
// LogoutRequest is a destructive action, so an unconfirmable freshness check
// rejects.
type LogoutReplayStore struct {
	db     *sql.DB
	logger logger
}

// NewLogoutReplayStore opens dsn, migrates the schema under the
// "saml_sp_logout_replay" namespace, and returns the store. Caller owns Close().
func NewLogoutReplayStore(dsn string, opts ...Option) (*LogoutReplayStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("saml/sp/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/sp/sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "saml_sp_logout_replay", spLogoutReplaySchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/sp/sqlite: migrate saml_sp_logout_replays: %w", err)
	}
	c := newStoreConfig(opts...)
	return &LogoutReplayStore{db: db, logger: c.logger}, nil
}

// NewLogoutReplayStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewLogoutReplayStoreWithDB(db *sql.DB, opts ...Option) (*LogoutReplayStore, error) {
	if err := ensureSchema(db, "saml_sp_logout_replay", spLogoutReplaySchema); err != nil {
		return nil, fmt.Errorf("saml/sp/sqlite: migrate saml_sp_logout_replays: %w", err)
	}
	c := newStoreConfig(opts...)
	return &LogoutReplayStore{db: db, logger: c.logger}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *LogoutReplayStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for migrate.Status. Nil after Close.
func (s *LogoutReplayStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for a readycheck wiring.
func (s *LogoutReplayStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("saml/sp/sqlite: logout replay store closed")
	}
	return s.db.PingContext(ctx)
}

// CheckAndRemember implements sp.ReplayStore: true ⇒ fresh, false ⇒ replay (or a
// fail-closed DB error). Race-free single-transaction GC + ON CONFLICT insert,
// shared with the assertion store.
func (s *LogoutReplayStore) CheckAndRemember(id string, expires, now time.Time) bool {
	return checkAndRemember(s.db, s.logger, "saml_sp_logout_replays", id, expires, now)
}

// PruneExpired drops rows whose freshness window has lapsed (operator/scheduler
// hook; CheckAndRemember already GCs per call).
func (s *LogoutReplayStore) PruneExpired(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("saml/sp/sqlite: logout replay store closed")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_sp_logout_replays WHERE expires_at <= ?`, now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("saml/sp/sqlite: prune logout replays: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

var _ samlsp.ReplayStore = (*LogoutReplayStore)(nil)
