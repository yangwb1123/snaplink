package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
)

// passwordResetSchema is the forgot-password reset-token store: a server-issued
// opaque token bound to a user, short-lived and single-use-on-reset
// (Consume = DELETE … RETURNING).
const passwordResetSchema = `
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token      TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_expires_at
    ON password_reset_tokens(expires_at);
`

// PasswordResetStore is the SQLite-backed core.PasswordResetStore — durable
// across restarts and safe for multi-replica (every replica issues + consumes
// against the same DB; the single-use DELETE…RETURNING is atomic).
type PasswordResetStore struct {
	db *sql.DB
}

// NewPasswordResetStore opens dsn, migrates the schema, and returns the store.
func NewPasswordResetStore(dsn string) (*PasswordResetStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "password_reset_tokens", passwordResetSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate password_reset_tokens: %w", err)
	}
	return &PasswordResetStore{db: db}, nil
}

// NewPasswordResetStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewPasswordResetStoreWithDB(db *sql.DB) (*PasswordResetStore, error) {
	if err := ensureSchema(db, "password_reset_tokens", passwordResetSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate password_reset_tokens: %w", err)
	}
	return &PasswordResetStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *PasswordResetStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *PasswordResetStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for /readyz wiring.
func (s *PasswordResetStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: password reset store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue stores a token. INSERT OR REPLACE keeps it idempotent by token value.
func (s *PasswordResetStore) Issue(ctx context.Context, rt *core.PasswordResetToken) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO password_reset_tokens (token, user_id, expires_at)
        VALUES (?, ?, ?)`,
		rt.Token, rt.UserID, rt.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: issue password_reset_token: %w", err)
	}
	return nil
}

// Consume atomically deletes and returns the token. Missing/expired/
// already-consumed all return core.ErrResetTokenNotFound (oracle-safe — the
// row is gone either way).
func (s *PasswordResetStore) Consume(ctx context.Context, token string) (*core.PasswordResetToken, error) {
	var userID string
	var expNanos int64
	err := s.db.QueryRowContext(ctx, `
        DELETE FROM password_reset_tokens WHERE token = ?
        RETURNING user_id, expires_at`, token).
		Scan(&userID, &expNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrResetTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume password_reset_token: %w", err)
	}
	rt := &core.PasswordResetToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: time.Unix(0, expNanos),
	}
	if rt.IsExpired() {
		return nil, core.ErrResetTokenNotFound
	}
	return rt, nil
}

// RevokeByUser deletes all pending reset tokens bound to userID (admin-plane
// invalidation) and returns the count removed.
func (s *PasswordResetStore) RevokeByUser(ctx context.Context, userID string) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM password_reset_tokens WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke password_reset_tokens by user: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

var (
	_ core.PasswordResetStore   = (*PasswordResetStore)(nil)
	_ core.PasswordResetRevoker = (*PasswordResetStore)(nil)
)
