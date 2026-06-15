package sqlite

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/migrate"
)

const sessionIDBytes = 32

// sessionMigrations is the versioned schema history for the session store
// (TokenStrategySession opaque-token state). The ID is an opaque hex string the
// client sees as its bearer token, so this is effectively the access-token store
// for the session strategy; multi-replica deployments need it so a session
// minted on replica A is redeemable on replica B.
//
// v1: baseline (matches the original ensureSchema schema byte-for-byte, so a DB
//
//	already stamped v1 by ensureSchema is a no-op here).
//
// v2: ADD COLUMN ip + user_agent — best-effort device/location context for the
//
//	self-service session list. Default '' so existing rows are unaffected.
var sessionMigrations = []migrate.Migration{
	{
		Version: 1,
		Name:    "baseline",
		SQL: `
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);
`,
	},
	{
		Version: 2,
		Name:    "session-device-context",
		SQL: `
ALTER TABLE sessions ADD COLUMN ip         TEXT NOT NULL DEFAULT '';
ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';`,
	},
}

// SessionManager is the SQLite-backed implementation of
// [sso.SessionManager]. Suitable for multi-replica deployments and
// session-strategy clients.
type SessionManager struct {
	db  *sql.DB
	ttl time.Duration
}

// NewSessionManager opens dsn, migrates the schema, and returns the
// manager. ttl is the lifetime applied on Create + Refresh; pass 0
// to take [sso.DefaultSessionDuration].
func NewSessionManager(dsn string, ttl time.Duration) (*SessionManager, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "sessions", sessionMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate sessions: %w", err)
	}
	if ttl <= 0 {
		ttl = sso.DefaultSessionDuration
	}
	return &SessionManager{db: db, ttl: ttl}, nil
}

// NewSessionManagerWithDB wraps an existing *sql.DB. Caller owns
// the connection lifecycle (shared-pool deployments).
func NewSessionManagerWithDB(db *sql.DB, ttl time.Duration) (*SessionManager, error) {
	if err := migrate.Run(context.Background(), db, "sessions", sessionMigrations); err != nil {
		return nil, fmt.Errorf("sqlite: migrate sessions: %w", err)
	}
	if ttl <= 0 {
		ttl = sso.DefaultSessionDuration
	}
	return &SessionManager{db: db, ttl: ttl}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *SessionManager) Close() error {
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
func (s *SessionManager) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *SessionManager) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: session manager closed")
	}
	return s.db.PingContext(ctx)
}

func (s *SessionManager) Create(ctx context.Context, userID string) (*sso.Session, error) {
	return s.CreateWithMeta(ctx, userID, sso.SessionMeta{})
}

// CreateWithMeta implements sso.SessionMetaCreator: it persists the device/
// location context (IP, user-agent) on the new session for the self-service
// session list.
func (s *SessionManager) CreateWithMeta(ctx context.Context, userID string, meta sso.SessionMeta) (*sso.Session, error) {
	id, err := randomSessionID()
	if err != nil {
		return nil, fmt.Errorf("sqlite: random session id: %w", err)
	}
	now := time.Now().UTC()
	session := &sso.Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
		IP:        meta.IP,
		UserAgent: meta.UserAgent,
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO sessions (id, user_id, created_at, expires_at, revoked, ip, user_agent)
        VALUES (?, ?, ?, ?, 0, ?, ?)`,
		session.ID, session.UserID, session.CreatedAt.UnixNano(), session.ExpiresAt.UnixNano(),
		session.IP, session.UserAgent,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: insert session: %w", err)
	}
	return session, nil
}

func (s *SessionManager) Get(ctx context.Context, sessionID string) (*sso.Session, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT id, user_id, created_at, expires_at, revoked, ip, user_agent
          FROM sessions WHERE id = ?`, sessionID)
	out, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get session: %w", err)
	}
	return out, nil
}

func (s *SessionManager) Destroy(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("sqlite: destroy session: %w", err)
	}
	return nil
}

// Refresh extends ExpiresAt by ttl. Returns ErrSessionNotFound when
// the row is missing — matches MemorySessionManager's contract.
// UPDATE ... RETURNING gives us the post-update row in one round-
// trip + atomically tests existence.
func (s *SessionManager) Refresh(ctx context.Context, sessionID string) (*sso.Session, error) {
	// Refresh MUST NOT resurrect expired or revoked sessions —
	// otherwise a captured session id is valid forever to anyone
	// who can call Refresh. The WHERE clause filters out both
	// failure modes BEFORE the UPDATE fires; combined with
	// RETURNING, an attempted resurrect surfaces as sql.ErrNoRows
	// (mapped to ErrSessionNotFound) instead of silent extension.
	now := time.Now()
	row := s.db.QueryRowContext(ctx, `
        UPDATE sessions SET expires_at = ?
          WHERE id = ? AND revoked = 0 AND expires_at > ?
        RETURNING id, user_id, created_at, expires_at, revoked, ip, user_agent`,
		now.Add(s.ttl).UnixNano(), sessionID, now.UnixNano(),
	)
	out, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: refresh session: %w", err)
	}
	return out, nil
}

func (s *SessionManager) ListByUser(ctx context.Context, userID string) ([]*sso.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, created_at, expires_at, revoked, ip, user_agent
          FROM sessions WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

func (s *SessionManager) ListAll(ctx context.Context) ([]*sso.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, created_at, expires_at, revoked, ip, user_agent
          FROM sessions`)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list all: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

func scanSession(s scanner) (*sso.Session, error) {
	var (
		out                              sso.Session
		createdAtUnixNs, expiresAtUnixNs int64
		revokedInt                       int64
	)
	if err := s.Scan(&out.ID, &out.UserID, &createdAtUnixNs, &expiresAtUnixNs, &revokedInt, &out.IP, &out.UserAgent); err != nil {
		return nil, err
	}
	out.CreatedAt = time.Unix(0, createdAtUnixNs).UTC()
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	out.Revoked = revokedInt != 0
	return &out, nil
}

func scanSessionList(rows *sql.Rows) ([]*sso.Session, error) {
	out := make([]*sso.Session, 0)
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan session: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows iter: %w", err)
	}
	return out, nil
}

func randomSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

var (
	_ sso.SessionManager     = (*SessionManager)(nil)
	_ sso.SessionMetaCreator = (*SessionManager)(nil)
)
