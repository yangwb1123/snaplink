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
// refreshTokensTableDDL creates the table with the full current column
// set. Kept separate from the index DDL so the Func migration can run
// it BEFORE backfilling columns on a legacy DB — an index that
// references a not-yet-added column (family_id) can't be created first.
const refreshTokensTableDDL = `
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
    authorization_details  TEXT    NOT NULL DEFAULT '',
    sid                    TEXT    NOT NULL DEFAULT ''
);`

// refreshTokensIndexDDL creates indexes + the family ledger. Runs AFTER
// the column backfill so idx_refresh_tokens_family(family_id) is valid
// even on a database upgraded from the pre-family-tracker schema.
const refreshTokensIndexDDL = `
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

// oauth.RefreshTokenStore is the SQLite-backed implementation. Implements
// both [oauth.RefreshTokenStore] AND [oauth.RefreshTokenInspector] so
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
	if err := migrate.Run(context.Background(), db, "refresh_tokens", refreshTokenMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate refresh_tokens: %w", err)
	}
	return &RefreshTokenStore{db: db}, nil
}

func NewRefreshTokenStoreWithDB(db *sql.DB) *RefreshTokenStore {
	// Best-effort on the shared-DB path (mirrors the historical
	// contract — this constructor never returned an error).
	_ = migrate.Run(context.Background(), db, "refresh_tokens", refreshTokenMigrations)
	return &RefreshTokenStore{db: db}
}

// refreshTokenMigrations is the schema history. v1 is a Func migration
// rather than plain SQL because legacy databases predate the
// family_id / resources / authorization_details / sid columns and
// SQLite has no ADD COLUMN IF NOT EXISTS: the func creates the table
// then adds each column only when it's missing. Fresh databases get the
// full table from the CREATE and skip every add; pre-family-tracker
// databases get the missing columns backfilled — the same outcome the
// old error-tolerant ALTER dance produced, now version-tracked + atomic.
var refreshTokenMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline_refresh_tokens", Func: ensureRefreshTokenSchema},
}

func ensureRefreshTokenSchema(ctx context.Context, x migrate.Execer) error {
	// 1. Table first (fresh DBs get all columns; legacy DBs no-op here).
	if _, err := x.ExecContext(ctx, refreshTokensTableDDL); err != nil {
		return err
	}
	// 2. Backfill columns a pre-family-tracker DB is missing.
	addColumns := []struct{ name, ddl string }{
		{"family_id", `ALTER TABLE refresh_tokens ADD COLUMN family_id TEXT NOT NULL DEFAULT ''`},
		{"resources", `ALTER TABLE refresh_tokens ADD COLUMN resources TEXT NOT NULL DEFAULT '[]'`},
		{"authorization_details", `ALTER TABLE refresh_tokens ADD COLUMN authorization_details TEXT NOT NULL DEFAULT ''`},
		{"sid", `ALTER TABLE refresh_tokens ADD COLUMN sid TEXT NOT NULL DEFAULT ''`},
	}
	for _, c := range addColumns {
		has, err := refreshTokenColumnExists(ctx, x, c.name)
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
	// 3. Indexes + family ledger last — idx_refresh_tokens_family needs
	// family_id to exist, which step 2 guarantees.
	if _, err := x.ExecContext(ctx, refreshTokensIndexDDL); err != nil {
		return err
	}
	return nil
}

// refreshTokenColumnExists reports whether refresh_tokens already has the
// named column, via PRAGMA table_info (the table name is a constant, not
// user input).
func refreshTokenColumnExists(ctx context.Context, x migrate.Execer, column string) (bool, error) {
	rows, err := x.QueryContext(ctx, `PRAGMA table_info(refresh_tokens)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
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

func (s *RefreshTokenStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Ping reports SQLite connection health for [sso.WithReadyCheck]
// wiring.
func (s *RefreshTokenStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: refresh token store closed")
	}
	return s.db.PingContext(ctx)
}

func (s *RefreshTokenStore) Issue(ctx context.Context, token string, info *oauth.RefreshToken) error {
	if token == "" || info == nil {
		return oauth.ErrRefreshTokenNotFound
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
            authorization_details, sid)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, info.UserID, info.ClientID, info.Provider,
		string(scopes), string(attrs),
		info.IssuedAt.UnixNano(), info.ExpiresAt.UnixNano(),
		info.FamilyID, string(resources),
		string(info.AuthorizationDetails), info.SID,
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
// — return oauth.ErrRefreshTokenReused with the family_id stamped on the
// returned oauth.RefreshToken so the handler can kill the entire family.
func (s *RefreshTokenStore) Consume(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM refresh_tokens WHERE token = ?
        RETURNING user_id, client_id, provider, scopes, attributes,
                  issued_at, expires_at, family_id, resources,
                  authorization_details, sid`, token)
	out, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		// Reuse-detection path.
		var familyID string
		ferr := s.db.QueryRowContext(ctx,
			`SELECT family_id FROM refresh_token_families WHERE token = ?`, token,
		).Scan(&familyID)
		if errors.Is(ferr, sql.ErrNoRows) {
			return nil, oauth.ErrRefreshTokenNotFound
		}
		if ferr != nil {
			return nil, fmt.Errorf("sqlite: family lookup: %w", ferr)
		}
		return &oauth.RefreshToken{FamilyID: familyID}, oauth.ErrRefreshTokenReused
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume refresh_token: %w", err)
	}
	if out.IsExpired() {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	return out, nil
}

// Inspect implements [oauth.RefreshTokenInspector] — non-destructive
// SELECT. Expired entries are deleted opportunistically (single-row
// GC) so the table self-trims as it's read.
func (s *RefreshTokenStore) Inspect(ctx context.Context, token string) (*oauth.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT user_id, client_id, provider, scopes, attributes,
               issued_at, expires_at, family_id, resources,
               authorization_details, sid
        FROM refresh_tokens WHERE token = ?`, token)
	out, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauth.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: inspect refresh_token: %w", err)
	}
	if out.IsExpired() {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = ?`, token)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM refresh_token_families WHERE token = ?`, token)
		return nil, oauth.ErrRefreshTokenNotFound
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

// DeleteAllForSubject implements [oauth.RefreshTokenSubjectIndex]. Empty
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

// CountForSubject implements [oauth.RefreshTokenSubjectCounter] — counts
// the subject's tokens for clientID (or every client when clientID is
// empty) without deleting them, for erasure dry-run previews.
func (s *RefreshTokenStore) CountForSubject(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	var n int
	var err error
	if clientID == "" {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ?`, userID).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = ? AND client_id = ?`,
			userID, clientID).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("sqlite: count by subject: %w", err)
	}
	return n, nil
}

// DeleteFamily implements [oauth.RefreshTokenFamilyTracker] — kills
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

func scanRefreshToken(s scanner) (*oauth.RefreshToken, error) {
	var (
		out                                        oauth.RefreshToken
		provider, scopesJSON, attrsJSON, resources string
		familyID, authDetails, sid                 string
		issuedAtUnixNs, expiresAtUnixNs            int64
	)
	if err := s.Scan(
		&out.UserID, &out.ClientID, &provider,
		&scopesJSON, &attrsJSON,
		&issuedAtUnixNs, &expiresAtUnixNs,
		&familyID, &resources,
		&authDetails, &sid,
	); err != nil {
		return nil, err
	}
	if authDetails != "" {
		out.AuthorizationDetails = json.RawMessage(authDetails)
	}
	out.Provider = provider
	out.FamilyID = familyID
	out.SID = sid
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
	_ oauth.RefreshTokenStore         = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenInspector     = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenSubjectIndex  = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenFamilyTracker = (*RefreshTokenStore)(nil)
)
