package sqlite

import "github.com/snaplink/sso/protocols/oauth"

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/platform/migrate"
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
    confirmation_jkt      TEXT    NOT NULL DEFAULT '',
    requested_claims      TEXT    NOT NULL DEFAULT '',
    expires_at            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at
    ON auth_codes(expires_at);
`

// authCodeMigrations is the schema history. v1 is the original baseline
// (equivalent to the single-migration contract ensureSchema used to apply
// implicitly). v2 backfills the RFC 9449 §10 DPoP authorization-code-
// binding column onto a pre-existing database — SQLite has no ADD COLUMN
// IF NOT EXISTS, so the Func checks first; a fresh database already has
// the column from the v1 baseline DDL above and skips the add. Mirrors
// refresh_tokens_schema.go's addRefreshTokenDPoPBinding (v4) exactly.
//
// v3 backfills the RFC 9068 authentication-context columns (auth_time, amr,
// acr, resources, authorization_details, sid) that issueAuthCode
// (interfaces/sso/server_oauth.go) already populates on the in-memory
// oauth.AuthCode struct but that this store previously silently dropped —
// a SQLite deployment falls back to token-exchange time for auth_time and
// loses acr/amr/resources/authorization_details entirely without this.
// SID is included for schema parity with refresh_tokens even though the
// authorization_code flow never actually stamps it at issue time (a
// separate, already-tracked design gap, not a storage bug); it round-trips
// whatever the caller supplies, same as every other column here.
var authCodeMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: authCodeSchema},
	{Version: 2, Name: "auth_code_dpop_binding", Func: addAuthCodeDPoPBinding},
	{Version: 3, Name: "auth_code_requested_claims", Func: addAuthCodeRequestedClaims},
	{Version: 4, Name: "auth_code_context", Func: addAuthCodeAuthContext},
}

func addAuthCodeDPoPBinding(ctx context.Context, x migrate.Execer) error {
	has, err := authCodeColumnExists(ctx, x, "confirmation_jkt")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = x.ExecContext(ctx,
		`ALTER TABLE auth_codes ADD COLUMN confirmation_jkt TEXT NOT NULL DEFAULT ''`)
	return err
}

// addAuthCodeRequestedClaims (v3) backfills the OIDC Core §5.5 claims-
// parameter column (raw JSON; empty string = none) onto a pre-existing database so
// the /token exchange can honor the RP's claims request — same
// check-then-add shape as the v2 DPoP column since SQLite has no ADD
// COLUMN IF NOT EXISTS; a fresh database already has it from the v1
// baseline DDL and skips the add.
func addAuthCodeRequestedClaims(ctx context.Context, x migrate.Execer) error {
	has, err := authCodeColumnExists(ctx, x, "requested_claims")
	if err != nil {
		return err
	}
	if has {
		return nil
	}
	_, err = x.ExecContext(ctx,
		`ALTER TABLE auth_codes ADD COLUMN requested_claims TEXT NOT NULL DEFAULT ''`)
	return err
}

// addAuthCodeAuthContext (v4) adds auth_time/amr/acr/resources/authorization_details/sid
// (RFC 9068 §2.2 authentication-context propagation — mirrors
// refresh_tokens_schema.go's addRefreshTokenAuthContext) to a pre-existing
// auth_codes table, each only when missing.
func addAuthCodeAuthContext(ctx context.Context, x migrate.Execer) error {
	addColumns := []struct{ name, ddl string }{
		{"auth_time", `ALTER TABLE auth_codes ADD COLUMN auth_time INTEGER NOT NULL DEFAULT 0`},
		{"amr", `ALTER TABLE auth_codes ADD COLUMN amr TEXT NOT NULL DEFAULT '[]'`},
		{"acr", `ALTER TABLE auth_codes ADD COLUMN acr TEXT NOT NULL DEFAULT ''`},
		{"resources", `ALTER TABLE auth_codes ADD COLUMN resources TEXT NOT NULL DEFAULT '[]'`},
		{"authorization_details", `ALTER TABLE auth_codes ADD COLUMN authorization_details TEXT NOT NULL DEFAULT ''`},
		{"sid", `ALTER TABLE auth_codes ADD COLUMN sid TEXT NOT NULL DEFAULT ''`},
	}
	for _, c := range addColumns {
		has, err := authCodeColumnExists(ctx, x, c.name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := x.ExecContext(ctx, c.ddl); err != nil {
			return fmt.Errorf("add column %s: %w", c.name, err)
		}
	}
	return nil
}

// authCodeColumnExists reports whether auth_codes already has the named
// column, via PRAGMA table_info (the table name is a constant, not user
// input).
func authCodeColumnExists(ctx context.Context, x migrate.Execer, column string) (bool, error) {
	rows, err := x.QueryContext(ctx, `PRAGMA table_info(auth_codes)`)
	if err != nil {
		return false, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			cid         int
			name, ctype string
			notnull, pk int
			dflt        sql.NullString
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
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
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
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
	resources, err := json.Marshal(info.Resources)
	if err != nil {
		return fmt.Errorf("sqlite: marshal resources: %w", err)
	}
	amr, err := json.Marshal(info.AuthMethods)
	if err != nil {
		return fmt.Errorf("sqlite: marshal amr: %w", err)
	}
	// Zero-sentinel discipline (matches refresh_tokens.go): a zero AuthTime
	// stores 0 so the /token exchange falls back to now rather than emitting
	// the Unix epoch — see the AuthCode.AuthTime doc comment.
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO auth_codes (
            code, user_id, client_id, redirect_uri, scopes, nonce,
            provider, attributes, code_challenge, code_challenge_method,
            confirmation_jkt, auth_time, amr, acr, resources,
            authorization_details, sid, requested_claims, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		code, info.UserID, info.ClientID, info.RedirectURI,
		string(scopes), info.Nonce, info.Provider, string(attrs),
		info.CodeChallenge, info.CodeChallengeMethod, info.ConfirmationJKT,
		unixNanoOrZero(info.AuthTime), string(amr), info.ACR, string(resources),
		string(info.AuthorizationDetails), info.SID,
		string(info.RequestedClaims), // raw §5.5 claims JSON; '' = none
		info.ExpiresAt.UnixNano(),
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
                  confirmation_jkt, auth_time, amr, acr, resources,
                  authorization_details, sid, requested_claims, expires_at`, code)
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
		confirmationJKT                                                                         string
		amrJSON, acr, resourcesJSON, authDetails, sid, requestedClaims                          string
		authTimeUnixNs, expiresAtUnixNs                                                         int64
	)
	if err := s.Scan(
		&out.UserID, &out.ClientID, &redirectURI, &scopesJSON, &nonce,
		&provider, &attrsJSON, &codeChallenge, &codeChallengeMethod,
		&confirmationJKT, &authTimeUnixNs, &amrJSON, &acr, &resourcesJSON,
		&authDetails, &sid, &requestedClaims, &expiresAtUnixNs,
	); err != nil {
		return nil, err
	}
	out.RedirectURI = redirectURI
	out.Nonce = nonce
	out.Provider = provider
	out.CodeChallenge = codeChallenge
	out.CodeChallengeMethod = codeChallengeMethod
	out.ConfirmationJKT = confirmationJKT
	out.ACR = acr
	out.SID = sid
	if authDetails != "" {
		out.AuthorizationDetails = json.RawMessage(authDetails)
	}
	if requestedClaims != "" {
		out.RequestedClaims = json.RawMessage(requestedClaims)
	}
	// 0 sentinel = no auth_time captured (pre-v3/v4 row, or a caller that never
	// threaded it); leave the zero time so the /token exchange falls back to
	// now rather than emitting the Unix epoch — mirrors refresh_tokens.go.
	if authTimeUnixNs != 0 {
		out.AuthTime = time.Unix(0, authTimeUnixNs).UTC()
	}
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	if err := decodeAuthCodeJSONCols(&out, scopesJSON, attrsJSON, resourcesJSON, amrJSON); err != nil {
		return nil, err
	}
	return &out, nil
}

// decodeAuthCodeJSONCols unmarshals the JSON-encoded columns onto out.
// Extracted from scanAuthCode for the function-length/cyclo budget — mirrors
// refresh_tokens.go's decodeRefreshJSONCols. The empty / empty-collection
// sentinels ("", "[]", "{}") are left as the zero value rather than
// allocating an empty slice/map.
func decodeAuthCodeJSONCols(out *oauth.AuthCode, scopesJSON, attrsJSON, resourcesJSON, amrJSON string) error {
	if scopesJSON != "" && scopesJSON != "[]" {
		if err := json.Unmarshal([]byte(scopesJSON), &out.Scopes); err != nil {
			return fmt.Errorf("sqlite: unmarshal scopes: %w", err)
		}
	}
	if attrsJSON != "" && attrsJSON != "{}" {
		if err := json.Unmarshal([]byte(attrsJSON), &out.Attributes); err != nil {
			return fmt.Errorf("sqlite: unmarshal attributes: %w", err)
		}
	}
	if resourcesJSON != "" && resourcesJSON != "[]" {
		if err := json.Unmarshal([]byte(resourcesJSON), &out.Resources); err != nil {
			return fmt.Errorf("sqlite: unmarshal resources: %w", err)
		}
	}
	if amrJSON != "" && amrJSON != "[]" {
		if err := json.Unmarshal([]byte(amrJSON), &out.AuthMethods); err != nil {
			return fmt.Errorf("sqlite: unmarshal amr: %w", err)
		}
	}
	return nil
}

var _ oauth.AuthCodeStore = (*AuthCodeStore)(nil)
