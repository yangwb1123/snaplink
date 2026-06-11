package sqlite

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/migrate"
)

// authCodeSchema covers the OAuth 2.0 authorization_code grant data
// model — short-lived (10 min default), single-use, optionally bound
// to a PKCE challenge. Single table, no separate scopes/attributes
// tables (those are JSON-encoded blobs since we never query into
// them — full row reads only).
const authCodeSchema = `
CREATE TABLE IF NOT EXISTS auth_codes (
    code                  TEXT    PRIMARY KEY,
    user_id               TEXT    NOT NULL,
    client_id             TEXT    NOT NULL,
    redirect_uri          TEXT    NOT NULL DEFAULT '',
    scopes                TEXT    NOT NULL DEFAULT '[]',
    nonce                 TEXT    NOT NULL DEFAULT '',
    provider              TEXT    NOT NULL DEFAULT '',
    attributes            TEXT    NOT NULL DEFAULT '{}',
    code_challenge        TEXT    NOT NULL DEFAULT '',
    code_challenge_method TEXT    NOT NULL DEFAULT '',
    expires_at            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at
    ON auth_codes(expires_at);
`

// authCodeMigrations evolves the auth_codes schema. v1 is the original
// baseline; v2 adds auth_time — the real /auth/login moment (Unix-ns, 0 =
// unset) replayed into the minted token's auth_time claim at redemption
// (OIDC Core §2) rather than the exchange time. v3/v4 add amr (JSON-encoded
// RFC 8176 method tags) + acr (the satisfied ACR), likewise captured at
// issue and replayed into the token's amr/acr instead of collapsing amr to
// the provider id and dropping acr.
var authCodeMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: authCodeSchema},
	{Version: 2, Name: "auth_code_auth_time", SQL: `ALTER TABLE auth_codes ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0`},
	{Version: 3, Name: "auth_code_amr", SQL: `ALTER TABLE auth_codes ADD COLUMN amr TEXT NOT NULL DEFAULT '[]'`},
	{Version: 4, Name: "auth_code_acr", SQL: `ALTER TABLE auth_codes ADD COLUMN acr TEXT NOT NULL DEFAULT ''`},
}

// oauth.AuthCodeStore is the SQLite-backed implementation of
// [oauth.AuthCodeStore]. Suitable for multi-replica deployments since
// every replica can issue + consume against the same database.
type AuthCodeStore struct {
	db *sql.DB
}

// NewAuthCodeStore opens dsn, migrates the schema, and returns the
// store. The provider owns the *sql.DB — Close() releases it. See
// sqlite/users.go for DSN cookbook.
func NewAuthCodeStore(dsn string) (*AuthCodeStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "auth_codes", authCodeMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate auth_codes: %w", err)
	}
	return &AuthCodeStore{db: db}, nil
}

// NewAuthCodeStoreWithDB wraps an existing *sql.DB. Caller owns the
// connection lifecycle (matches the UserProvider pattern for
// shared-pool deployments).
func NewAuthCodeStoreWithDB(db *sql.DB) *AuthCodeStore {
	// Best-effort schema convergence on the shared-pool path (matches the
	// refresh-token store); a migration error surfaces later as an Issue
	// failure rather than here, since this constructor has no error return.
	_ = migrate.Run(context.Background(), db, "auth_codes", authCodeMigrations)
	return &AuthCodeStore{db: db}
}

// Close releases the SQLite connection. Idempotent.
func (s *AuthCodeStore) Close() error {
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
func (s *AuthCodeStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *AuthCodeStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: auth code store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue persists the auth code. Caller-supplied slices / maps are
// JSON-marshaled at this point so subsequent caller mutations don't
// leak into stored state.
func (s *AuthCodeStore) Issue(ctx context.Context, code string, info *oauth.AuthCode) error {
	if code == "" || info == nil {
		return oauth.ErrAuthCodeNotFound
	}
	scopes, err := json.Marshal(info.Scopes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal scopes: %w", err)
	}
	attrs, err := json.Marshal(info.Attributes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal attributes: %w", err)
	}
	var authTimeNs int64
	if !info.AuthTime.IsZero() {
		authTimeNs = info.AuthTime.UnixNano()
	}
	amr, err := json.Marshal(info.AuthMethods)
	if err != nil {
		return fmt.Errorf("sqlite: marshal amr: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO auth_codes (
            code, user_id, client_id, redirect_uri, scopes, nonce,
            provider, attributes, code_challenge, code_challenge_method,
            auth_time, amr, acr, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code, info.UserID, info.ClientID, info.RedirectURI,
		string(scopes), info.Nonce, info.Provider, string(attrs),
		info.CodeChallenge, info.CodeChallengeMethod, authTimeNs, string(amr), info.ACR, info.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert auth_code: %w", err)
	}
	return nil
}

// Consume atomically returns + deletes the row. Uses SQLite's
// RETURNING clause (>=3.35) for true atomicity — the standard
// SELECT-then-DELETE pattern has a race where two concurrent
// Consume calls could each return the code before either delete
// fires.
func (s *AuthCodeStore) Consume(ctx context.Context, code string) (*oauth.AuthCode, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM auth_codes WHERE code = ?
        RETURNING user_id, client_id, redirect_uri, scopes, nonce,
                  provider, attributes, code_challenge, code_challenge_method,
                  auth_time, amr, acr, expires_at`, code)
	out, err := scanAuthCode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauth.ErrAuthCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume auth_code: %w", err)
	}
	// Expired entries indistinguishable from missing — same oracle-
	// resistance the memory backend enforces. The row is already
	// deleted at this point, so no separate cleanup needed.
	if out.IsExpired() {
		return nil, oauth.ErrAuthCodeNotFound
	}
	return out, nil
}

func scanAuthCode(s scanner) (*oauth.AuthCode, error) {
	var (
		out                                                                                     oauth.AuthCode
		redirectURI, nonce, provider, codeChallenge, codeChallengeMethod, scopesJSON, attrsJSON string
		expiresAtUnixNs                                                                         int64
	)
	var authTimeUnixNs int64
	var amrJSON, acr string
	if err := s.Scan(
		&out.UserID, &out.ClientID, &redirectURI, &scopesJSON, &nonce,
		&provider, &attrsJSON, &codeChallenge, &codeChallengeMethod,
		&authTimeUnixNs, &amrJSON, &acr, &expiresAtUnixNs,
	); err != nil {
		return nil, err
	}
	out.RedirectURI = redirectURI
	out.Nonce = nonce
	out.Provider = provider
	out.CodeChallenge = codeChallenge
	out.CodeChallengeMethod = codeChallengeMethod
	if authTimeUnixNs != 0 {
		out.AuthTime = time.Unix(0, authTimeUnixNs).UTC()
	}
	out.ACR = acr
	if amrJSON != "" && amrJSON != "[]" {
		if err := json.Unmarshal([]byte(amrJSON), &out.AuthMethods); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal amr: %w", err)
		}
	}
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

var _ oauth.AuthCodeStore = (*AuthCodeStore)(nil)
