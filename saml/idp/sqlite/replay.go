package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	samlidp "github.com/snaplink/sso/saml/idp"
)

// logoutReplaySchema dedups inbound SP-initiated LogoutRequest IDs on the IdP
// side, across replicas. PRIMARY KEY on the id makes INSERT ... ON CONFLICT DO
// NOTHING atomically signal a replay (rows-affected 1 ⇒ fresh, 0 ⇒ replay);
// expires_at (the request's freshness deadline, Unix-ns) bounds the table so a
// lapsed id can be pruned — matching the memory store.
const logoutReplaySchema = `
CREATE TABLE IF NOT EXISTS saml_idp_logout_replays (
    id         TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_idp_logout_replays_expires_at
    ON saml_idp_logout_replays(expires_at);
`

// LogoutReplayStore is the SQLite-backed, cross-replica peer of the IdP's
// in-memory logoutReplayStore. It lets a multi-replica IdP catch a captured,
// validly-signed LogoutRequest replayed to a DIFFERENT replica — a targeted-
// logout DoS defense that the per-replica store can't provide. Wire via
// idp.Deps.LogoutReplayStore.
//
// It satisfies idp.LogoutReplayStore, whose CheckAndRemember is synchronous and
// returns a bare bool to keep the SLO call site unchanged. A DB error can't be
// surfaced, so the store FAILS CLOSED (returns false = "treat as replay /
// reject") — a LogoutRequest is destructive, so an unconfirmable freshness check
// MUST reject. The error is logged via the configured Logger seam.
type LogoutReplayStore struct {
	db     *sql.DB
	logger logger
}

// logger is the minimal sink the fail-closed path logs to (the bool-returning
// seam can't propagate the error). Nil Logger option ⇒ silent.
type logger interface {
	Error(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Error(string, ...any) {}

// Option configures a store at construction.
type Option func(*storeConfig)

type storeConfig struct {
	logger logger
}

// WithLogger sets the sink a fail-closed DB error is logged to. Nil ⇒ silent.
func WithLogger(l logger) Option {
	return func(c *storeConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

func newStoreConfig(opts ...Option) storeConfig {
	c := storeConfig{logger: nopLogger{}}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// NewLogoutReplayStore opens dsn (e.g. "file:/var/lib/sso/saml.db?_journal=WAL";
// tests use "file::memory:?cache=shared"), migrates the schema under the
// "saml_idp_logout_replay" namespace, and returns the store. Caller owns
// Close().
func NewLogoutReplayStore(dsn string, opts ...Option) (*LogoutReplayStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("saml/idp/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/idp/sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "saml_idp_logout_replay", logoutReplaySchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/idp/sqlite: migrate saml_idp_logout_replays: %w", err)
	}
	c := newStoreConfig(opts...)
	return &LogoutReplayStore{db: db, logger: c.logger}, nil
}

// NewLogoutReplayStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewLogoutReplayStoreWithDB(db *sql.DB, opts ...Option) (*LogoutReplayStore, error) {
	if err := ensureSchema(db, "saml_idp_logout_replay", logoutReplaySchema); err != nil {
		return nil, fmt.Errorf("saml/idp/sqlite: migrate saml_idp_logout_replays: %w", err)
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
		return errors.New("saml/idp/sqlite: logout replay store closed")
	}
	return s.db.PingContext(ctx)
}

// CheckAndRemember implements idp.LogoutReplayStore. true ⇒ fresh, false ⇒
// replay (or a fail-closed DB error). The dedup is race-free: a lazy GC of
// lapsed rows then an INSERT ... ON CONFLICT DO NOTHING in ONE transaction, so
// two concurrent calls for the same id can't both read it as fresh. Mirrors the
// memory store (a lapsed id is GC'd first and reads fresh again — by then the
// IssueInstant-freshness check rejects it anyway).
func (s *LogoutReplayStore) CheckAndRemember(id string, expires, now time.Time) bool {
	if id == "" {
		return true
	}
	if s == nil || s.db == nil {
		s.logErr("store closed", nil)
		return false
	}
	ctx := context.Background()

	// Pin one connection so the BEGIN IMMEDIATE / COMMIT pair runs on one session.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		s.logErr("acquire conn", err)
		return false
	}
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		s.logErr("begin", err)
		return false
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	// Lazy GC: drop lapsed rows (memory parity + table bound).
	if _, err := conn.ExecContext(ctx,
		`DELETE FROM saml_idp_logout_replays WHERE expires_at <= ?`, now.UnixNano()); err != nil {
		s.logErr("gc", err)
		return false
	}

	res, err := conn.ExecContext(ctx,
		`INSERT INTO saml_idp_logout_replays (id, expires_at) VALUES (?, ?) ON CONFLICT (id) DO NOTHING`,
		id, expires.UnixNano())
	if err != nil {
		if isConstraintErr(err) {
			committed = true
			_, _ = conn.ExecContext(ctx, "COMMIT")
			return false // row already existed ⇒ replay
		}
		s.logErr("insert", err)
		return false
	}
	n, err := res.RowsAffected()
	if err != nil {
		// FAIL CLOSED: a SAML logout replay dedup guards a destructive action, so
		// an unconfirmable result rejects (unlike the JTI store's fail-open).
		s.logErr("rows-affected", err)
		return false
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		s.logErr("commit", err)
		return false
	}
	committed = true
	return n == 1
}

func (s *LogoutReplayStore) logErr(stage string, err error) {
	if s == nil || s.logger == nil {
		return
	}
	s.logger.Error("saml/idp/sqlite logout replay: "+stage+"; failing closed (rejecting)", "err", err)
}

func isConstraintErr(err error) bool {
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed")
}

// PruneExpired drops rows whose freshness window has lapsed (operator/scheduler
// hook; CheckAndRemember already GCs per call). Returns the rows removed.
func (s *LogoutReplayStore) PruneExpired(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("saml/idp/sqlite: logout replay store closed")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_idp_logout_replays WHERE expires_at <= ?`, now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("saml/idp/sqlite: prune logout replays: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

var _ samlidp.LogoutReplayStore = (*LogoutReplayStore)(nil)
