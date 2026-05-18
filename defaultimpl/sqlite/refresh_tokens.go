package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
)

// refreshTokenSchema mirrors the in-memory contract — same fields,
// JSON-encoded scope + attribute blobs, single table. Tokens live
// for days/weeks (30 day default) so the table can grow large for
// big fleets; the (expires_at) index is there for periodic
// background GC, not currently invoked by the store itself.
const refreshTokenSchema = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token       TEXT    PRIMARY KEY,
    user_id     TEXT    NOT NULL,
    client_id   TEXT    NOT NULL,
    provider    TEXT    NOT NULL DEFAULT '',
    scopes      TEXT    NOT NULL DEFAULT '[]',
    attributes  TEXT    NOT NULL DEFAULT '{}',
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client
    ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens(expires_at);
`

// RefreshTokenStore is the SQLite-backed implementation. Implements
// both [sso.RefreshTokenStore] AND [sso.RefreshTokenInspector] so
// introspection / revocation work against this backend out of the
// box — same contract the memory backend exposes.
type RefreshTokenStore struct {
	db *sql.DB
}

func NewRefreshTokenStore(dsn string) (*RefreshTokenStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), refreshTokenSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate refresh_tokens: %w", err)
	}
	return &RefreshTokenStore{db: db}, nil
}

func NewRefreshTokenStoreWithDB(db *sql.DB) *RefreshTokenStore {
	return &RefreshTokenStore{db: db}
}

func (s *RefreshTokenStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

func (s *RefreshTokenStore) Issue(ctx context.Context, token string, info *sso.RefreshToken) error {
	if token == "" || info == nil {
		return sso.ErrRefreshTokenNotFound
	}
	scopes, err := json.Marshal(info.Scopes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal scopes: %w", err)
	}
	attrs, err := json.Marshal(info.Attributes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal attributes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO refresh_tokens (token, user_id, client_id, provider,
            scopes, attributes, issued_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		token, info.UserID, info.ClientID, info.Provider,
		string(scopes), string(attrs),
		info.IssuedAt.UnixNano(), info.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert refresh_token: %w", err)
	}
	return nil
}

// Consume atomically deletes + returns the row. Single-use rotation
// semantics enforced via DELETE...RETURNING.
func (s *RefreshTokenStore) Consume(ctx context.Context, token string) (*sso.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM refresh_tokens WHERE token = ?
        RETURNING user_id, client_id, provider, scopes, attributes,
                  issued_at, expires_at`, token)
	out, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume refresh_token: %w", err)
	}
	if out.IsExpired() {
		return nil, sso.ErrRefreshTokenNotFound
	}
	return out, nil
}

// Inspect implements [sso.RefreshTokenInspector] — non-destructive
// SELECT. Expired entries are deleted opportunistically (single-row
// GC) so the table self-trims as it's read.
func (s *RefreshTokenStore) Inspect(ctx context.Context, token string) (*sso.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT user_id, client_id, provider, scopes, attributes,
               issued_at, expires_at
        FROM refresh_tokens WHERE token = ?`, token)
	out, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: inspect refresh_token: %w", err)
	}
	if out.IsExpired() {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = ?`, token)
		return nil, sso.ErrRefreshTokenNotFound
	}
	return out, nil
}

// Delete is idempotent per RFC 7009 §2.2 — unknown tokens return nil.
func (s *RefreshTokenStore) Delete(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("sqlite: delete refresh_token: %w", err)
	}
	return nil
}

// DeleteAllForSubject implements [sso.RefreshTokenSubjectIndex]. Empty
// clientID = revoke across every client the user has tokens for —
// useful for admin "kill all sessions" actions. Returns the count of
// deleted rows.
func (s *RefreshTokenStore) DeleteAllForSubject(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	var res sql.Result
	var err error
	if clientID == "" {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM refresh_tokens WHERE user_id = ?`, userID)
	} else {
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM refresh_tokens WHERE user_id = ? AND client_id = ?`,
			userID, clientID)
	}
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete by subject: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func scanRefreshToken(s scanner) (*sso.RefreshToken, error) {
	var (
		out                             sso.RefreshToken
		provider, scopesJSON, attrsJSON string
		issuedAtUnixNs, expiresAtUnixNs int64
	)
	if err := s.Scan(
		&out.UserID, &out.ClientID, &provider,
		&scopesJSON, &attrsJSON,
		&issuedAtUnixNs, &expiresAtUnixNs,
	); err != nil {
		return nil, err
	}
	out.Provider = provider
	out.IssuedAt = time.Unix(0, issuedAtUnixNs).UTC()
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	if scopesJSON != "" && scopesJSON != "[]" {
		if err := json.Unmarshal([]byte(scopesJSON), &out.Scopes); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal scopes: %w", err)
		}
	}
	if attrsJSON != "" && attrsJSON != "{}" {
		if err := json.Unmarshal([]byte(attrsJSON), &out.Attributes); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal attributes: %w", err)
		}
	}
	return &out, nil
}

var (
	_ sso.RefreshTokenStore        = (*RefreshTokenStore)(nil)
	_ sso.RefreshTokenInspector    = (*RefreshTokenStore)(nil)
	_ sso.RefreshTokenSubjectIndex = (*RefreshTokenStore)(nil)
)
