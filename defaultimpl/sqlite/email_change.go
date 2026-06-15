package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
)

// emailChangeSchema is the verified-email-change store: a server-issued opaque
// token bound to (user, new_email), short-lived and single-use-on-verify
// (Consume = DELETE … RETURNING).
const emailChangeSchema = `
CREATE TABLE IF NOT EXISTS email_change_tokens (
    token      TEXT    PRIMARY KEY,
    user_id    TEXT    NOT NULL,
    new_email  TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_change_tokens_expires_at
    ON email_change_tokens(expires_at);
`

// EmailChangeStore is the SQLite-backed core.EmailChangeStore — durable across
// restarts and safe for multi-replica (the single-use DELETE…RETURNING is
// atomic).
type EmailChangeStore struct {
	db *sql.DB
}

// NewEmailChangeStore opens dsn, migrates the schema, and returns the store.
func NewEmailChangeStore(dsn string) (*EmailChangeStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "email_change_tokens", emailChangeSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate email_change_tokens: %w", err)
	}
	return &EmailChangeStore{db: db}, nil
}

// NewEmailChangeStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewEmailChangeStoreWithDB(db *sql.DB) (*EmailChangeStore, error) {
	if err := ensureSchema(db, "email_change_tokens", emailChangeSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate email_change_tokens: %w", err)
	}
	return &EmailChangeStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *EmailChangeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *EmailChangeStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for /readyz wiring.
func (s *EmailChangeStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: email change store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue stores a token. INSERT OR REPLACE keeps it idempotent by token value.
func (s *EmailChangeStore) Issue(ctx context.Context, tok *core.EmailChangeToken) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO email_change_tokens (token, user_id, new_email, expires_at)
        VALUES (?, ?, ?, ?)`,
		tok.Token, tok.UserID, tok.NewEmail, tok.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: issue email_change_token: %w", err)
	}
	return nil
}

// Consume atomically deletes and returns the token. Missing/expired/
// already-consumed all return core.ErrEmailChangeTokenNotFound (oracle-safe).
func (s *EmailChangeStore) Consume(ctx context.Context, token string) (*core.EmailChangeToken, error) {
	var userID, newEmail string
	var expNanos int64
	err := s.db.QueryRowContext(ctx, `
        DELETE FROM email_change_tokens WHERE token = ?
        RETURNING user_id, new_email, expires_at`, token).
		Scan(&userID, &newEmail, &expNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrEmailChangeTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume email_change_token: %w", err)
	}
	tok := &core.EmailChangeToken{
		Token:     token,
		UserID:    userID,
		NewEmail:  newEmail,
		ExpiresAt: time.Unix(0, expNanos),
	}
	if tok.IsExpired() {
		return nil, core.ErrEmailChangeTokenNotFound
	}
	return tok, nil
}

// RevokeByUser deletes all pending email-change tokens bound to userID
// (admin-plane invalidation) and returns the count removed.
func (s *EmailChangeStore) RevokeByUser(ctx context.Context, userID string) (int, error) {
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM email_change_tokens WHERE user_id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: revoke email_change_tokens by user: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

var (
	_ core.EmailChangeStore   = (*EmailChangeStore)(nil)
	_ core.EmailChangeRevoker = (*EmailChangeStore)(nil)
)
