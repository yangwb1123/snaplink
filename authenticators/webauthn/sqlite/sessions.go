package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/migrate"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

// sessionMigrations is the ordered schema history for the WebAuthn
// session store; v1 = baseline. Own namespace, independent of the user
// store's version table.
var sessionMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline_webauthn_sessions", SQL: sessionSchema},
}

// sessionSchema holds the challenge + SessionData between Begin*
// and Finish* calls. The session ID is the opaque token the client
// echoes back; data is JSON-encoded gw.SessionData. Take uses
// DELETE...RETURNING for race-free single-use semantics — same
// pattern as defaultimpl/sqlite/par.go.
const sessionSchema = `
CREATE TABLE IF NOT EXISTS webauthn_sessions (
    id         TEXT    PRIMARY KEY,
    data       TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_sessions_expires_at
    ON webauthn_sessions(expires_at);
`

// SessionStore is the SQLite-backed [webauthn.SessionStore].
type SessionStore struct {
	db *sql.DB
}

// NewSessionStore opens dsn, migrates the schema, and returns the
// store.
func NewSessionStore(dsn string) (*SessionStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "webauthn_sessions", sessionMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate webauthn_sessions: %w", err)
	}
	return &SessionStore{db: db}, nil
}

// NewSessionStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments).
func NewSessionStoreWithDB(db *sql.DB) (*SessionStore, error) {
	if err := migrate.Run(context.Background(), db, "webauthn_sessions", sessionMigrations); err != nil {
		return nil, fmt.Errorf("sqlite: migrate webauthn_sessions: %w", err)
	}
	return &SessionStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *SessionStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (s *SessionStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *SessionStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: webauthn session store closed")
	}
	return s.db.PingContext(ctx)
}

// Put implements [webauthn.SessionStore].
func (s *SessionStore) Put(ctx context.Context, sessionID string, data *gw.SessionData, ttl time.Duration) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("sqlite: marshal session: %w", err)
	}
	expiresAt := time.Now().Add(ttl).UnixNano()
	// Upsert so a retry from the same sessionID (rare; the helper
	// mints fresh IDs) doesn't surface a primary-key collision.
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO webauthn_sessions (id, data, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT (id) DO UPDATE SET
            data       = excluded.data,
            expires_at = excluded.expires_at`,
		sessionID, string(payload), expiresAt,
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert session: %w", err)
	}
	return nil
}

// Take atomically removes-and-returns the session. Returns
// [webauthn.ErrSessionUnknown] when no row matched (single-use
// after a prior Take, or never inserted) and
// [webauthn.ErrSessionExpired] when the row existed but its TTL
// had elapsed (the row is removed regardless — matches Memory
// contract).
func (s *SessionStore) Take(ctx context.Context, sessionID string) (*gw.SessionData, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM webauthn_sessions WHERE id = ?
        RETURNING data, expires_at`, sessionID)
	var (
		payload     string
		expiresAtNs int64
	)
	if err := row.Scan(&payload, &expiresAtNs); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, webauthn.ErrSessionUnknown
		}
		return nil, fmt.Errorf("sqlite: take session: %w", err)
	}
	if time.Now().UnixNano() > expiresAtNs {
		return nil, webauthn.ErrSessionExpired
	}
	var data gw.SessionData
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return nil, fmt.Errorf("sqlite: unmarshal session: %w", err)
	}
	return &data, nil
}

var _ webauthn.SessionStore = (*SessionStore)(nil)
