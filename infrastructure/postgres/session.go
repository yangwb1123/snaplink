package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/migrate"
)

const sessionIDBytes = 32

// sessionSchema is the baseline sessions table (Postgres dialect). Every column
// mirrors the SQLite peer exactly (including BIGINT Unix-nanosecond timestamps)
// so dual-backend deployments can reason about the storage in one format.
// The composite PK guarantee would be (id) alone; tenant_id + user_id indexes
// support DeleteByTenant and ListByUser respectively.
const sessionSchema = `
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    created_at BIGINT NOT NULL,
    expires_at BIGINT NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0,
    ip         TEXT    NOT NULL DEFAULT '',
    user_agent TEXT    NOT NULL DEFAULT '',
    tenant_id  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id
    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_tenant_id
    ON sessions(tenant_id);
`

var sessionMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: sessionSchema},
}

// SessionManager is the Postgres-backed implementation of [sso.SessionManager].
// Suitable for multi-replica deployments that want a single DB tech stack
// (Postgres for both durable and hot stores).
//
// Hot-store note: Postgres is not as fast as Redis for session creation/lookup
// at scale. For high-traffic deployments, prefer Redis or SQLite for the session
// backend. This implementation targets unified-stack deployments where the
// operational simplicity of one DB outweighs peak throughput.
type SessionManager struct {
	db      *sql.DB
	dialect Dialect
	ttl     time.Duration
}

// NewSessionManager opens cfg.DSN, migrates the schema, and returns the
// manager. ttl is the lifetime applied on Create + Refresh; pass 0 to take
// sso.DefaultSessionDuration.
func NewSessionManager(cfg Config, ttl time.Duration) (*SessionManager, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewSessionManagerWithDB(db, cfg.Dialect, ttl)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewSessionManagerWithDB wraps an existing *sql.DB (shared-pool deployments).
// Caller owns the connection lifecycle.
func NewSessionManagerWithDB(db *sql.DB, dialect Dialect, ttl time.Duration) (*SessionManager, error) {
	if err := Run(context.Background(), db, "sessions", sessionMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate sessions: %w", err)
	}
	if ttl <= 0 {
		ttl = sso.DefaultSessionDuration
	}
	return &SessionManager{
		db:      db,
		dialect: dialect,
		ttl:     ttl,
	}, nil
}

// Close releases the connection. Idempotent.
func (s *SessionManager) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *SessionManager) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *SessionManager) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: session manager closed")
	}
	return s.db.PingContext(ctx)
}

func (s *SessionManager) Create(ctx context.Context, userID string) (*sso.Session, error) {
	return s.CreateWithMeta(ctx, userID, sso.SessionMeta{})
}

func (s *SessionManager) CreateWithMeta(ctx context.Context, userID string, meta sso.SessionMeta) (*sso.Session, error) {
	id, err := randomSessionID()
	if err != nil {
		return nil, fmt.Errorf("postgres: random session id: %w", err)
	}
	now := time.Now().UTC()
	session := &sso.Session{
		ID:        id,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: now.Add(s.ttl),
		IP:        meta.IP,
		UserAgent: meta.UserAgent,
		TenantID:  meta.TenantID,
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO sessions (id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id)
        VALUES ($1, $2, $3, $4, 0, $5, $6, $7)`,
		session.ID, session.UserID, session.CreatedAt.UnixNano(), session.ExpiresAt.UnixNano(),
		session.IP, session.UserAgent, session.TenantID,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: insert session: %w", err)
	}
	return session, nil
}

func (s *SessionManager) Get(ctx context.Context, sessionID string) (*sso.Session, error) {
	now := time.Now().UnixNano()
	row := s.db.QueryRowContext(ctx, `
        SELECT id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id
          FROM sessions WHERE id = $1 AND revoked = 0 AND expires_at > $2`, sessionID, now)
	out, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get session: %w", err)
	}
	return out, nil
}

func (s *SessionManager) Destroy(ctx context.Context, sessionID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	if err != nil {
		return fmt.Errorf("postgres: destroy session: %w", err)
	}
	return nil
}

// Refresh extends ExpiresAt by ttl. Uses UPDATE ... RETURNING to atomically
// test existence + return the refreshed row. Expired or revoked sessions are
// refused before the UPDATE fires (WHERE clause), matching MemorySessionManager.
func (s *SessionManager) Refresh(ctx context.Context, sessionID string) (*sso.Session, error) {
	now := time.Now()
	row := s.db.QueryRowContext(ctx, `
        UPDATE sessions SET expires_at = $1
          WHERE id = $2 AND revoked = 0 AND expires_at > $3
        RETURNING id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id`,
		now.Add(s.ttl).UnixNano(), sessionID, now.UnixNano(),
	)
	out, err := scanSession(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: refresh session: %w", err)
	}
	return out, nil
}

func (s *SessionManager) ListByUser(ctx context.Context, userID string) ([]*sso.Session, error) {
	now := time.Now().UnixNano()
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id
          FROM sessions WHERE user_id = $1 AND revoked = 0 AND expires_at > $2`, userID, now)
	if err != nil {
		return nil, fmt.Errorf("postgres: list by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

func (s *SessionManager) ListAll(ctx context.Context) ([]*sso.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id
          FROM sessions`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list all: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

func (s *SessionManager) ListByTenant(ctx context.Context, tenantID string) ([]*sso.Session, error) {
	if tenantID == "" {
		return []*sso.Session{}, nil
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, user_id, created_at, expires_at, revoked, ip, user_agent, tenant_id
          FROM sessions WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanSessionList(rows)
}

func (s *SessionManager) DeleteByTenant(ctx context.Context, tenantID string) (int, error) {
	if tenantID == "" {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return 0, fmt.Errorf("postgres: delete sessions by tenant: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func scanSession(s scanner) (*sso.Session, error) {
	var (
		out                              sso.Session
		createdAtUnixNs, expiresAtUnixNs int64
		revokedInt                       int64
	)
	if err := s.Scan(&out.ID, &out.UserID, &createdAtUnixNs, &expiresAtUnixNs, &revokedInt, &out.IP, &out.UserAgent, &out.TenantID); err != nil {
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
			return nil, fmt.Errorf("postgres: scan session: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows iter: %w", err)
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
	_ sso.SessionManager      = (*SessionManager)(nil)
	_ sso.SessionMetaCreator  = (*SessionManager)(nil)
	_ sso.SessionTenantIndex  = (*SessionManager)(nil)
	_ sso.SessionTenantLister = (*SessionManager)(nil)
)
