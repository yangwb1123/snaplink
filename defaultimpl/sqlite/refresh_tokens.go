package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
)

// refreshTokenSchema mirrors the in-memory contract — same fields,
// JSON-encoded scope + attribute blobs, single table. Tokens live
// for days/weeks (30 day default) so the table can grow large for
// big fleets; the (expires_at) index is there for periodic
// background GC, not currently invoked by the store itself.
//
// refresh_token_families is the OAuth Security BCP §4.13 reuse-
// detection ledger: every Issue mirrors the (token, family_id) pair
// here AND keeps it after Consume removed the active row, so a
// presented-after-rotation token can be recognized as a replay and
// the entire family killed.
const refreshTokenSchema = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
    token                  TEXT    PRIMARY KEY,
    user_id                TEXT    NOT NULL,
    client_id              TEXT    NOT NULL,
    provider               TEXT    NOT NULL DEFAULT '',
    scopes                 TEXT    NOT NULL DEFAULT '[]',
    attributes             TEXT    NOT NULL DEFAULT '{}',
    issued_at              INTEGER NOT NULL,
    expires_at             INTEGER NOT NULL,
    family_id              TEXT    NOT NULL DEFAULT '',
    resources              TEXT    NOT NULL DEFAULT '[]',
    authorization_details  TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_client
    ON refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_expires_at
    ON refresh_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_family
    ON refresh_tokens(family_id);

CREATE TABLE IF NOT EXISTS refresh_token_families (
    token     TEXT PRIMARY KEY,
    family_id TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_refresh_token_families_family
    ON refresh_token_families(family_id);
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
	// Idempotent column add for pre-family-tracker schemas. SQLite
	// rejects ALTER TABLE ADD COLUMN if the column already exists;
	// the duplicate-column error is the no-op signal we want.
	if _, err := db.ExecContext(context.Background(),
		`ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT ''`); err != nil &&
		!isDuplicateColumnErr(err) {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate refresh_tokens.family_id: %w", err)
	}
	if _, err := db.ExecContext(context.Background(),
		`ALTER TABLE refresh_tokens ADD COLUMN resources TEXT NOT NULL DEFAULT '[]'`); err != nil &&
		!isDuplicateColumnErr(err) {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate refresh_tokens.resources: %w", err)
	}
	if _, err := db.ExecContext(context.Background(),
		`ALTER TABLE refresh_tokens ADD COLUMN authorization_details TEXT NOT NULL DEFAULT ''`); err != nil &&
		!isDuplicateColumnErr(err) {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate refresh_tokens.authorization_details: %w", err)
	}
	return &RefreshTokenStore{db: db}, nil
}

func NewRefreshTokenStoreWithDB(db *sql.DB) *RefreshTokenStore {
	// Same idempotent column adds on the shared-DB path so this
	// constructor doesn't regress against legacy schemas.
	_, _ = db.ExecContext(context.Background(), refreshTokenSchema)
	if _, err := db.ExecContext(context.Background(),
		`ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT ''`); err != nil &&
		!isDuplicateColumnErr(err) {
		_ = err
	}
	if _, err := db.ExecContext(context.Background(),
		`ALTER TABLE refresh_tokens ADD COLUMN resources TEXT NOT NULL DEFAULT '[]'`); err != nil &&
		!isDuplicateColumnErr(err) {
		_ = err
	}
	if _, err := db.ExecContext(context.Background(),
		`ALTER TABLE refresh_tokens ADD COLUMN authorization_details TEXT NOT NULL DEFAULT ''`); err != nil &&
		!isDuplicateColumnErr(err) {
		_ = err
	}
	return &RefreshTokenStore{db: db}
}

// isDuplicateColumnErr matches the SQLite ALTER TABLE error message
// for "column already exists". Pure-Go driver, message-stable.
func isDuplicateColumnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "duplicate column") ||
		strings.Contains(msg, "already exists")
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
	resources, err := json.Marshal(info.Resources)
	if err != nil {
		return fmt.Errorf("sqlite: marshal resources: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO refresh_tokens (token, user_id, client_id, provider,
            scopes, attributes, issued_at, expires_at, family_id, resources,
            authorization_details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, info.UserID, info.ClientID, info.Provider,
		string(scopes), string(attrs),
		info.IssuedAt.UnixNano(), info.ExpiresAt.UnixNano(),
		info.FamilyID, string(resources),
		string(info.AuthorizationDetails),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert refresh_token: %w", err)
	}
	// Mirror into the family ledger so reuse detection survives the
	// active row's Consume DELETE. Empty FamilyID = caller opted out
	// of family tracking; skip the bookkeeping write.
	if info.FamilyID != "" {
		_, err = s.db.ExecContext(ctx,
			`INSERT OR REPLACE INTO refresh_token_families (token, family_id) VALUES (?, ?)`,
			token, info.FamilyID,
		)
		if err != nil {
			return fmt.Errorf("sqlite: insert refresh_token_families: %w", err)
		}
	}
	return nil
}

// Consume atomically deletes + returns the row. Single-use rotation
// semantics enforced via DELETE...RETURNING.
//
// On a miss, falls back to the families ledger: if the token is
// known there but not in refresh_tokens it's a reuse-after-rotation
// — return ErrRefreshTokenReused with the family_id stamped on the
// returned RefreshToken so the handler can kill the entire family.
func (s *RefreshTokenStore) Consume(ctx context.Context, token string) (*sso.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM refresh_tokens WHERE token = ?
        RETURNING user_id, client_id, provider, scopes, attributes,
                  issued_at, expires_at, family_id, resources,
                  authorization_details`, token)
	out, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		// Reuse-detection path.
		var familyID string
		ferr := s.db.QueryRowContext(ctx,
			`SELECT family_id FROM refresh_token_families WHERE token = ?`, token,
		).Scan(&familyID)
		if errors.Is(ferr, sql.ErrNoRows) {
			return nil, sso.ErrRefreshTokenNotFound
		}
		if ferr != nil {
			return nil, fmt.Errorf("sqlite: family lookup: %w", ferr)
		}
		return &sso.RefreshToken{FamilyID: familyID}, sso.ErrRefreshTokenReused
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
               issued_at, expires_at, family_id, resources,
               authorization_details
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
		_, _ = s.db.ExecContext(ctx, `DELETE FROM refresh_token_families WHERE token = ?`, token)
		return nil, sso.ErrRefreshTokenNotFound
	}
	return out, nil
}

// Delete is idempotent per RFC 7009 §2.2 — unknown tokens return nil.
// Wipes the families ledger too so an explicit /token/revoke can't
// subsequently mis-trigger a reuse-detection event on the same token.
func (s *RefreshTokenStore) Delete(ctx context.Context, token string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = ?`, token); err != nil {
		return fmt.Errorf("sqlite: delete refresh_token: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM refresh_token_families WHERE token = ?`, token); err != nil {
		return fmt.Errorf("sqlite: delete refresh_token_families: %w", err)
	}
	return nil
}

// DeleteAllForSubject implements [sso.RefreshTokenSubjectIndex]. Empty
// clientID = revoke across every client the user has tokens for —
// useful for admin "kill all sessions" actions. Returns the count of
// deleted rows.
//
// Wipes the families ledger for every removed entry so future
// presentations of those tokens look like vanilla invalid_grant
// rather than stale reuse-detection events.
func (s *RefreshTokenStore) DeleteAllForSubject(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	var res sql.Result
	var err error
	if clientID == "" {
		_, _ = s.db.ExecContext(ctx, `
            DELETE FROM refresh_token_families
            WHERE token IN (SELECT token FROM refresh_tokens WHERE user_id = ?)`,
			userID)
		res, err = s.db.ExecContext(ctx,
			`DELETE FROM refresh_tokens WHERE user_id = ?`, userID)
	} else {
		_, _ = s.db.ExecContext(ctx, `
            DELETE FROM refresh_token_families
            WHERE token IN (
                SELECT token FROM refresh_tokens
                WHERE user_id = ? AND client_id = ?
            )`, userID, clientID)
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

// DeleteFamily implements [sso.RefreshTokenFamilyTracker] — kills
// every active refresh token sharing the FamilyID and wipes the
// matching reuse-detection ledger rows. Returns the count of active
// tokens removed; the ledger wipe is bookkeeping and doesn't add to
// the count.
func (s *RefreshTokenStore) DeleteFamily(ctx context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE family_id = ?`, familyID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete family: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_token_families WHERE family_id = ?`, familyID); err != nil {
		return 0, fmt.Errorf("sqlite: delete family ledger: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

func scanRefreshToken(s scanner) (*sso.RefreshToken, error) {
	var (
		out                                        sso.RefreshToken
		provider, scopesJSON, attrsJSON, resources string
		familyID, authDetails                      string
		issuedAtUnixNs, expiresAtUnixNs            int64
	)
	if err := s.Scan(
		&out.UserID, &out.ClientID, &provider,
		&scopesJSON, &attrsJSON,
		&issuedAtUnixNs, &expiresAtUnixNs,
		&familyID, &resources,
		&authDetails,
	); err != nil {
		return nil, err
	}
	if authDetails != "" {
		out.AuthorizationDetails = json.RawMessage(authDetails)
	}
	out.Provider = provider
	out.FamilyID = familyID
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
	if resources != "" && resources != "[]" {
		if err := json.Unmarshal([]byte(resources), &out.Resources); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal resources: %w", err)
		}
	}
	return &out, nil
}

var (
	_ sso.RefreshTokenStore         = (*RefreshTokenStore)(nil)
	_ sso.RefreshTokenInspector     = (*RefreshTokenStore)(nil)
	_ sso.RefreshTokenSubjectIndex  = (*RefreshTokenStore)(nil)
	_ sso.RefreshTokenFamilyTracker = (*RefreshTokenStore)(nil)
)
