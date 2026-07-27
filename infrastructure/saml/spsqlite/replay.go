package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	samlsp "github.com/yangwb1123/snaplink/saml/sp"
)

// assertionReplaySchema dedups SAML AssertionIDs across replicas. PRIMARY KEY
// on the id makes INSERT ... ON CONFLICT DO NOTHING atomically signal a replay:
// rows-affected == 1 ⇒ first-sighting (fresh), == 0 ⇒ the row already existed
// (replay). expires_at (the assertion's replay deadline, Unix-ns) bounds the
// table so a lapsed id can be pruned — matching the memory store, which prunes
// by the same deadline before each check. A namespace column is NOT needed: the
// SP-side assertion replay and SP-side logout replay run in SEPARATE namespaces
// (distinct version tables / callers wire distinct stores), so AssertionIDs and
// LogoutRequest IDs never share this table.
const assertionReplaySchema = `
CREATE TABLE IF NOT EXISTS saml_sp_assertion_replays (
    id         TEXT    PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_saml_sp_assertion_replays_expires_at
    ON saml_sp_assertion_replays(expires_at);
`

// AssertionReplayStore is the SQLite-backed, cross-replica peer of the in-memory
// SP assertion replayStore. It lets a multi-replica SP catch an AssertionID
// replayed to a DIFFERENT replica — closing the replay-across-replicas gap the
// per-replica store leaves open. Wire via sp.SPConfig.AssertionReplayStore.
//
// It satisfies sp.ReplayStore, whose CheckAndRemember is synchronous and
// returns a bare bool (no error) to keep the assertion-validation call site
// unchanged. A DB error therefore can't be surfaced; the store FAILS CLOSED
// (returns false = "treat as replay / reject") so a freshness check that cannot
// be confirmed never lets a possibly-replayed assertion through — the
// security-correct posture for a replay dedup (and consistent with the SDK's
// fail-closed-on-validation-failure rule). The error is logged via the
// configured Logger seam, never swallowed silently.
type AssertionReplayStore struct {
	db     *sql.DB
	logger logger
}

// logger is the minimal sink AssertionReplayStore uses to surface a fail-closed
// DB error (the bool-returning seam can't propagate it). A nil Logger option ⇒
// the no-op logger, so the store is silent by default.
type logger interface {
	Error(msg string, args ...any)
}

type nopLogger struct{}

func (nopLogger) Error(string, ...any) {}

// Option configures an AssertionReplayStore / LogoutReplayStore at construction.
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

// NewAssertionReplayStore opens dsn (e.g.
// "file:/var/lib/sso/saml.db?_journal=WAL"; tests use
// "file::memory:?cache=shared"), migrates the schema under the
// "saml_sp_assertion_replay" namespace, and returns the store. Caller owns
// Close().
func NewAssertionReplayStore(dsn string, opts ...Option) (*AssertionReplayStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("saml/sp/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/sp/sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "saml_sp_assertion_replay", assertionReplaySchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/sp/sqlite: migrate saml_sp_assertion_replays: %w", err)
	}
	c := newStoreConfig(opts...)
	return &AssertionReplayStore{db: db, logger: c.logger}, nil
}

// NewAssertionReplayStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments — several SAML stores on one sso.db). Caller owns the connection
// lifecycle.
func NewAssertionReplayStoreWithDB(db *sql.DB, opts ...Option) (*AssertionReplayStore, error) {
	if err := ensureSchema(db, "saml_sp_assertion_replay", assertionReplaySchema); err != nil {
		return nil, fmt.Errorf("saml/sp/sqlite: migrate saml_sp_assertion_replays: %w", err)
	}
	c := newStoreConfig(opts...)
	return &AssertionReplayStore{db: db, logger: c.logger}, nil
}

// Close releases the SQLite connection. Idempotent. No-op for a WithDB store the
// caller owns (it still nils the handle so a later Ping reports closed).
func (s *AssertionReplayStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for an operator-facing schema reporter
// (migrate.Status). Nil after Close; callers MUST NOT close it.
func (s *AssertionReplayStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for a readycheck wiring.
func (s *AssertionReplayStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("saml/sp/sqlite: assertion replay store closed")
	}
	return s.db.PingContext(ctx)
}

// CheckAndRemember implements sp.ReplayStore. It returns true when id is FRESH
// (first sighting within its window) and false when it is a REPLAY. The dedup is
// race-free: a lazy GC of lapsed rows then an INSERT ... ON CONFLICT DO NOTHING
// in ONE transaction, so two concurrent calls for the same id can't both read it
// as fresh (one wins the INSERT, the other sees rows-affected 0). Mirrors the
// memory store: an id whose previous sighting has lapsed (expires_at <= now) is
// GC'd first and so reads fresh again (by then the assertion's own expiry check
// rejects it anyway). On any DB error the store FAILS CLOSED (returns false).
func (s *AssertionReplayStore) CheckAndRemember(id string, expires, now time.Time) bool {
	return checkAndRemember(s.db, s.logger, "saml_sp_assertion_replays", id, expires, now)
}

// checkAndRemember is the shared dedup body for every SAML sqlite replay store
// (assertion + logout, SP + IdP) so the race-free atomic + fail-closed posture
// live in ONE place and can't drift between stores. namespace tables differ; the
// logic is identical.
func checkAndRemember(db *sql.DB, log logger, table, id string, expires, now time.Time) bool {
	// A blank id is treated as fresh (the caller already guards `id != ""`; this
	// matches the memory store, which never records a blank key).
	if id == "" {
		return true
	}
	if db == nil {
		log.Error("saml sqlite replay: store closed; failing closed (rejecting)", "table", table)
		return false
	}
	ctx := context.Background()

	// Pin one connection so the BEGIN IMMEDIATE / COMMIT pair runs on one session
	// (database/sql may otherwise spread the GC + INSERT across pooled conns,
	// breaking the single-transaction guarantee).
	conn, err := db.Conn(ctx)
	if err != nil {
		log.Error("saml sqlite replay: acquire conn; failing closed", "table", table, "err", err)
		return false
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		log.Error("saml sqlite replay: begin; failing closed", "table", table, "err", err)
		return false
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	// Lazy GC: drop lapsed rows so a previously-seen-but-now-expired id reads
	// fresh again (memory parity) and the table stays bounded by the active
	// window. Indexed by expires_at, so O(expired count).
	if _, err := conn.ExecContext(ctx,
		"DELETE FROM "+table+" WHERE expires_at <= ?", now.UnixNano()); err != nil {
		log.Error("saml sqlite replay: gc; failing closed", "table", table, "err", err)
		return false
	}

	res, err := conn.ExecContext(ctx,
		"INSERT INTO "+table+" (id, expires_at) VALUES (?, ?) ON CONFLICT (id) DO NOTHING",
		id, expires.UnixNano())
	if err != nil {
		// modernc.org/sqlite ships SQLite 3.39+ (ON CONFLICT supported), so this
		// is defensive: a UNIQUE-constraint error from a degraded build still
		// means the row exists ⇒ replay.
		if isConstraintErr(err) {
			committed = true // the row already existed; nothing to commit, release the lock
			_, _ = conn.ExecContext(ctx, "COMMIT")
			return false
		}
		log.Error("saml sqlite replay: insert; failing closed", "table", table, "err", err)
		return false
	}
	n, err := res.RowsAffected()
	if err != nil {
		// Driver couldn't report affected rows: FAIL CLOSED (reject). Unlike the
		// JTI store (which fails OPEN for availability), a SAML replay dedup is a
		// security gate guarding a destructive/auth action, so an unconfirmable
		// result must reject.
		log.Error("saml sqlite replay: rows-affected; failing closed", "table", table, "err", err)
		return false
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		log.Error("saml sqlite replay: commit; failing closed", "table", table, "err", err)
		return false
	}
	committed = true
	return n == 1 // 1 ⇒ inserted (fresh); 0 ⇒ conflict (replay)
}

func isConstraintErr(err error) bool {
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint failed") ||
		strings.Contains(msg, "constraint failed")
}

// PruneExpired opportunistically drops rows whose replay window has lapsed
// (expires_at <= now). CheckAndRemember already GCs per call, so this is an
// optional operator/scheduler hook for a store that sees no traffic. Returns the
// number of rows removed.
func (s *AssertionReplayStore) PruneExpired(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("saml/sp/sqlite: assertion replay store closed")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_sp_assertion_replays WHERE expires_at <= ?`, now.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("saml/sp/sqlite: prune assertion replays: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

var _ samlsp.ReplayStore = (*AssertionReplayStore)(nil)
