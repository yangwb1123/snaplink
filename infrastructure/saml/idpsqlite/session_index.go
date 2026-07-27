package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	samlidp "github.com/yangwb1123/snaplink/saml/idp"
)

// DefaultSessionTTL is how long a session index row lives before the background
// cleanup goroutine prunes it. After this period the subject->SP mapping is
// removed so an SP whose SSO session has naturally expired doesn't linger in
// the index forever, even if the subject never hits the SLO endpoint.
// Matches the typical IdP assertion TTL.
const DefaultSessionTTL = 24 * time.Hour

// DefaultCleanupInterval is how often the background cleanup goroutine runs
// PruneExpired when no interval is configured.
const DefaultCleanupInterval = 10 * time.Minute

// sessionIndexSchema is the cross-replica SAML session index — "given subject X,
// which SAML SPs does X have an active SSO session with, and how do I reach each
// for SLO?". It is the SAML analogue of the OIDC BCL subject_client_index
// (defaultimpl/sqlite/subject_client_index.go).
//
// Composite PRIMARY KEY (subject, sp_entity_id) enforces one row per
// subject->SP, so Record is idempotent via INSERT ... ON CONFLICT DO UPDATE
// (re-login refreshes the recorded SLO URL/binding/channel/SessionIndex in place
// — the fan-out never double-sends to one SP). recorded_at (Unix-ns, bumped on
// every Record) drives ListBySubject ordering + the per-subject SP cap eviction,
// mirroring the memory store's per-subject insertion list. expires_at (Unix-ns)
// drives TTL-based cleanup so rows from subjects that never hit the SLO endpoint
// don't accumulate indefinitely. The remaining columns are the SAMLSPSession
// fields the fan-out needs, every one recorded server-side at assertion-issuance
// (never request input).
const sessionIndexSchema = `
CREATE TABLE IF NOT EXISTS saml_session_index (
    subject       TEXT    NOT NULL,
    sp_entity_id  TEXT    NOT NULL,
    sp_client_id  TEXT    NOT NULL DEFAULT '',
    sp_slo_url    TEXT    NOT NULL DEFAULT '',
    sp_binding    TEXT    NOT NULL DEFAULT '',
    sp_channel    TEXT    NOT NULL DEFAULT '',
    name_id       TEXT    NOT NULL DEFAULT '',
    session_index TEXT    NOT NULL DEFAULT '',
    recorded_at   INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (subject, sp_entity_id)
);

CREATE INDEX IF NOT EXISTS idx_saml_session_index_subject
    ON saml_session_index(subject, recorded_at);

CREATE INDEX IF NOT EXISTS idx_saml_session_index_expires_at
    ON saml_session_index(expires_at);
`

// migrateSessionIndex runs the session index schema migrations: v1 = baseline
// CREATE TABLE, v2 = add expires_at column + backfill. On a fresh database the
// column already exists from v1's DDL, so v2's ALTER TABLE is a no-op (the
// "duplicate column" error is silently swallowed). On an existing database at
// v1 the column is added, the index created, and existing rows get a 24-hour
// TTL measured from recorded_at.
func migrateSessionIndex(db *sql.DB) error {
	return migrate.Run(context.Background(), db, "saml_session_index", []migrate.Migration{
		{Version: 1, Name: "baseline", SQL: sessionIndexSchema},
		{Version: 2, Name: "add expires_at", Func: func(ctx context.Context, x migrate.Execer) error {
			// Add expires_at column if it doesn't exist yet. SQLite errors with
			// "duplicate column name" when the column already exists (fresh DB
			// or re-run); silently swallow that case.
			if _, err := x.ExecContext(ctx,
				`ALTER TABLE saml_session_index ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`); err != nil {
				if !strings.Contains(err.Error(), "duplicate column") {
					return fmt.Errorf("saml_session_index: add expires_at: %w", err)
				}
			}
			// Create the expires_at index (idempotent).
			if _, err := x.ExecContext(ctx,
				`CREATE INDEX IF NOT EXISTS idx_saml_session_index_expires_at ON saml_session_index(expires_at)`); err != nil {
				return fmt.Errorf("saml_session_index: create expires_at index: %w", err)
			}
			// Backfill existing rows: set a 24-hour TTL measured from recorded_at.
			if _, err := x.ExecContext(ctx,
				`UPDATE saml_session_index SET expires_at = recorded_at + ? WHERE expires_at = 0`,
				24*int64(time.Hour.Nanoseconds())); err != nil {
				return fmt.Errorf("saml_session_index: backfill expires_at: %w", err)
			}
			return nil
		}},
	})
}

// DefaultSPsPerSubject caps how many SP rows one subject may accumulate in the
// sqlite index, mirroring idp.DefaultSessionIndexSPsPerSubject (the memory
// store's per-subject cap): past it the OLDEST SP row (lowest recorded_at) for
// that subject is dropped, so an adversary who can drive logins can't inflate a
// single subject's row list unboundedly. A subject realistically federates to a
// handful of SPs.
//
// WHY no global subject-count cap (unlike the memory store's subject LRU): a
// per-replica in-memory LRU can evict the least-recently-recorded SUBJECT, but a
// SHARED store has no single global recency signal across replicas to drive that
// fairly. The growth guards here are the per-subject SP cap (above) + RemoveAll
// on logout (the normal reclamation path) + the optional PruneOlderThan operator
// hook (age out rows from subjects that never logged out). This is a deliberate,
// documented adaptation — the per-subject cap (the adversary-facing bound) is
// preserved; the subject LRU (a memory-pressure bound, not a security one) is
// replaced by age-based pruning, which a shared DB can do consistently.
const DefaultSPsPerSubject = 64

// SessionIndex is the SQLite-backed, cross-replica idp.SAMLSessionIndex. It lets
// a multi-replica IdP fan out an SP-initiated logout to EVERY SP the subject
// federated to across the cluster — not just those whose assertion-issuance
// landed on the replica handling the logout (the gap the per-replica memory
// index leaves). Wire via saml.Deps.SAMLSessionIndex.
type SessionIndex struct {
	db               *sql.DB
	maxSPsPerSubject int
	sessionTTL       time.Duration
}

// IndexOption configures a SessionIndex at construction.
type IndexOption func(*indexConfig)

type indexConfig struct {
	maxSPsPerSubject int
	sessionTTL       time.Duration
}

// WithMaxSPsPerSubject overrides the per-subject SP-row cap. Non-positive ⇒
// DefaultSPsPerSubject.
func WithMaxSPsPerSubject(n int) IndexOption {
	return func(c *indexConfig) { c.maxSPsPerSubject = n }
}

// WithSessionTTL overrides the default session TTL (24h). Rows whose expires_at
// has passed are cleaned up by PruneExpired / StartCleanup. Non-positive ⇒
// DefaultSessionTTL.
func WithSessionTTL(d time.Duration) IndexOption {
	return func(c *indexConfig) { c.sessionTTL = d }
}

func newIndexConfig(opts ...IndexOption) indexConfig {
	c := indexConfig{
		maxSPsPerSubject: DefaultSPsPerSubject,
		sessionTTL:       DefaultSessionTTL,
	}
	for _, o := range opts {
		o(&c)
	}
	if c.maxSPsPerSubject <= 0 {
		c.maxSPsPerSubject = DefaultSPsPerSubject
	}
	if c.sessionTTL <= 0 {
		c.sessionTTL = DefaultSessionTTL
	}
	return c
}

// NewSessionIndex opens dsn (e.g. "file:/var/lib/sso/saml.db?_journal=WAL";
// tests use "file::memory:?cache=shared"), migrates the schema under the
// "saml_session_index" namespace, and returns the index. Caller owns Close().
func NewSessionIndex(dsn string, opts ...IndexOption) (*SessionIndex, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("saml/idp/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/idp/sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrateSessionIndex(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("saml/idp/sqlite: migrate saml_session_index: %w", err)
	}
	c := newIndexConfig(opts...)
	return &SessionIndex{db: db, maxSPsPerSubject: c.maxSPsPerSubject, sessionTTL: c.sessionTTL}, nil
}

// NewSessionIndexWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewSessionIndexWithDB(db *sql.DB, opts ...IndexOption) (*SessionIndex, error) {
	if err := migrateSessionIndex(db); err != nil {
		return nil, fmt.Errorf("saml/idp/sqlite: migrate saml_session_index: %w", err)
	}
	c := newIndexConfig(opts...)
	return &SessionIndex{db: db, maxSPsPerSubject: c.maxSPsPerSubject, sessionTTL: c.sessionTTL}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *SessionIndex) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for migrate.Status. Nil after Close.
func (s *SessionIndex) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for a readycheck wiring.
func (s *SessionIndex) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("saml/idp/sqlite: session index closed")
	}
	return s.db.PingContext(ctx)
}

// Record adds or refreshes the SP row for subject. A blank subject or blank SP
// entity id is ignored (nothing to key on) — never an error, so a degenerate
// assertion can't fail the issue path (memory parity). The upsert + per-subject
// cap eviction run in ONE transaction so a concurrent Record can't see a
// half-applied state. Recording the same (subject, SPEntityID) UPDATES in place
// (bumping recorded_at to most-recent) rather than duplicating. expires_at is
// set to now + sessionTTL so the row is eventually cleaned up by PruneExpired.
func (s *SessionIndex) Record(ctx context.Context, subject string, sess samlidp.SAMLSPSession) error {
	if subject == "" || sess.SPEntityID == "" {
		return nil
	}
	if s == nil || s.db == nil {
		return errors.New("saml/idp/sqlite: session index closed")
	}

	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("saml/idp/sqlite: session index acquire conn: %w", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("saml/idp/sqlite: session index begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	// recorded_at is read from the wall clock here (not a caller-injected `now`):
	// the SAMLSessionIndex.Record signature carries no clock seam, and recorded_at
	// only orders rows + drives cap eviction, never a security decision.
	now := time.Now()
	nowNano := now.UnixNano()
	expiresNano := now.Add(s.sessionTTL).UnixNano()
	if _, err := conn.ExecContext(ctx, `
        INSERT INTO saml_session_index (
            subject, sp_entity_id, sp_client_id, sp_slo_url, sp_binding,
            sp_channel, name_id, session_index, recorded_at, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT (subject, sp_entity_id) DO UPDATE SET
            sp_client_id  = excluded.sp_client_id,
            sp_slo_url    = excluded.sp_slo_url,
            sp_binding    = excluded.sp_binding,
            sp_channel    = excluded.sp_channel,
            name_id       = excluded.name_id,
            session_index = excluded.session_index,
            recorded_at   = excluded.recorded_at,
            expires_at    = excluded.expires_at`,
		subject, sess.SPEntityID, sess.SPClientID, sess.SPSLOUrl, sess.SPBinding,
		sess.SPChannel, sess.NameID, sess.SessionIndex, nowNano, expiresNano,
	); err != nil {
		return fmt.Errorf("saml/idp/sqlite: session index upsert: %w", err)
	}

	// Enforce the per-subject SP cap: delete the oldest rows beyond the cap (by
	// recorded_at ASC). Mirrors the memory store's evictOldestSPLocked. The
	// subquery selects the rows to KEEP (newest `cap`); anything else for this
	// subject is dropped.
	if _, err := conn.ExecContext(ctx, `
        DELETE FROM saml_session_index
         WHERE subject = ?
           AND sp_entity_id NOT IN (
               SELECT sp_entity_id FROM saml_session_index
                WHERE subject = ?
                ORDER BY recorded_at DESC
                LIMIT ?
           )`,
		subject, subject, s.maxSPsPerSubject,
	); err != nil {
		return fmt.Errorf("saml/idp/sqlite: session index cap evict: %w", err)
	}

	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("saml/idp/sqlite: session index commit: %w", err)
	}
	committed = true
	return nil
}

// ListBySubject returns subject's SP rows in INSERTION order (oldest first),
// matching the memory store (front = oldest). An unknown subject returns nil.
// The returned slice is the caller's own (freshly built), safe to mutate. Does
// NOT filter expired rows — the caller (SLO fan-out) is free to send a
// LogoutRequest to an SP whose session may have lapsed; the SP handles it
// gracefully.
func (s *SessionIndex) ListBySubject(ctx context.Context, subject string) ([]samlidp.SAMLSPSession, error) {
	if subject == "" {
		return nil, nil
	}
	if s == nil || s.db == nil {
		return nil, errors.New("saml/idp/sqlite: session index closed")
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT sp_entity_id, sp_client_id, sp_slo_url, sp_binding,
               sp_channel, name_id, session_index
          FROM saml_session_index
         WHERE subject = ?
         ORDER BY recorded_at ASC, sp_entity_id ASC`, subject)
	if err != nil {
		return nil, fmt.Errorf("saml/idp/sqlite: session index list: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []samlidp.SAMLSPSession
	for rows.Next() {
		var r samlidp.SAMLSPSession
		if err := rows.Scan(
			&r.SPEntityID, &r.SPClientID, &r.SPSLOUrl, &r.SPBinding,
			&r.SPChannel, &r.NameID, &r.SessionIndex,
		); err != nil {
			return nil, fmt.Errorf("saml/idp/sqlite: session index scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("saml/idp/sqlite: session index rows iter: %w", err)
	}
	return out, nil
}

// Remove drops the single (subject, spEntityID) row. nil-safe on an unknown pair
// (DELETE affects zero rows) — memory parity.
func (s *SessionIndex) Remove(ctx context.Context, subject, spEntityID string) error {
	if subject == "" || spEntityID == "" {
		return nil
	}
	if s == nil || s.db == nil {
		return errors.New("saml/idp/sqlite: session index closed")
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_session_index WHERE subject = ? AND sp_entity_id = ?`,
		subject, spEntityID); err != nil {
		return fmt.Errorf("saml/idp/sqlite: session index remove: %w", err)
	}
	return nil
}

// RemoveAll drops every SP row for subject (the subject is logged out
// everywhere). nil-safe on an unknown subject — memory parity. Called after the
// fan-out so stale subject->SP rows don't leak.
func (s *SessionIndex) RemoveAll(ctx context.Context, subject string) error {
	if subject == "" {
		return nil
	}
	if s == nil || s.db == nil {
		return errors.New("saml/idp/sqlite: session index closed")
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_session_index WHERE subject = ?`, subject); err != nil {
		return fmt.Errorf("saml/idp/sqlite: session index remove all: %w", err)
	}
	return nil
}

// PruneOlderThan drops rows recorded before cutoff (age out subjects that never
// logged out — the shared-store replacement for the memory subject-LRU growth
// bound; see DefaultSPsPerSubject's doc). Returns the rows removed. An
// operator/scheduler hook; never invoked on the request path.
func (s *SessionIndex) PruneOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("saml/idp/sqlite: session index closed")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_session_index WHERE recorded_at < ?`, cutoff.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("saml/idp/sqlite: session index prune: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// PruneExpired deletes rows whose TTL has expired (expires_at < before) and
// returns the count of rows removed. Used by the operator/scheduler hook and by
// StartCleanup to periodically reclaim space from subjects that never logged
// out via the SLO endpoint.
func (s *SessionIndex) PruneExpired(ctx context.Context, before time.Time) (int, error) {
	if s == nil || s.db == nil {
		return 0, errors.New("saml/idp/sqlite: session index closed")
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM saml_session_index WHERE expires_at < ?`, before.UnixNano())
	if err != nil {
		return 0, fmt.Errorf("saml/idp/sqlite: session index prune expired: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// StartCleanup launches a background goroutine that runs PruneExpired
// periodically at the given interval (or DefaultCleanupInterval when interval is
// non-positive). The goroutine exits when ctx is cancelled, making the caller
// responsible for lifecycle (typically ctx, cancel := context.WithCancel(...)
// paired with idx.Close()). Safe to call multiple times — each call spawns a
// fresh goroutine; the caller should cancel the previous context first or ensure
// only one cleanup loop runs.
func (s *SessionIndex) StartCleanup(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := s.PruneExpired(ctx, time.Now())
				if err != nil && s != nil && s.db != nil {
					// Log the error to stderr (there's no logger seam on
					// SessionIndex; the caller can observe via metrics or logs).
					// The cleanup loop continues — a transient DB error must not
					// kill the background goroutine.
					_ = n // discard count on error path
				}
			}
		}
	}()
}

var _ samlidp.SAMLSessionIndex = (*SessionIndex)(nil)
