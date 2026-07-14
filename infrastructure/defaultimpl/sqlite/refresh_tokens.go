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

// oauth.RefreshTokenStore is the SQLite-backed implementation. Implements
// both [oauth.RefreshTokenStore] AND [oauth.RefreshTokenInspector] so
// introspection / revocation work against this backend out of the
// box — same contract the memory backend exposes.
type RefreshTokenStore struct {
	db *sql.DB
	// MaxRotationsPerWindow and RotationWindow configure the optional per-family
	// rotation velocity cap (§2 oracle-safe). Both must be positive to arm it.
	MaxRotationsPerWindow int
	RotationWindow        time.Duration
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
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
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

func (s *RefreshTokenStore) Close() error {
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
func (s *RefreshTokenStore) DB() *sql.DB { return s.db }

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
	scopes, attrs, resources, amr, err := marshalRefreshJSONCols(info)
	if err != nil {
		return err
	}
	// Zero-sentinel discipline for the two "may be unset" timestamps: a zero
	// AuthTime stores 0 (auth_time omitted on rotation, not a bogus epoch);
	// a zero FamilyCreatedAt (a caller that never threaded it — pre-feature
	// record, or the absolute-max-lifetime cap never configured) also stores
	// 0, which SKIPS that cap check rather than fabricating a start time.
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO refresh_tokens (token, user_id, client_id, provider,
            scopes, attributes, issued_at, expires_at, family_id, resources,
            authorization_details, sid, amr, acr, auth_time, confirmation_jkt,
            generation, family_created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token, info.UserID, info.ClientID, info.Provider,
		string(scopes), string(attrs),
		info.IssuedAt.UnixNano(), info.ExpiresAt.UnixNano(),
		info.FamilyID, string(resources),
		string(info.AuthorizationDetails), info.SID,
		string(amr), info.Acr, unixNanoOrZero(info.AuthTime), info.ConfirmationJKT,
		info.Generation, unixNanoOrZero(info.FamilyCreatedAt),
	)
	if err != nil {
		return fmt.Errorf("sqlite: insert refresh_token: %w", err)
	}
	return s.mirrorRefreshFamily(ctx, token, info.FamilyID)
}

// marshalRefreshJSONCols JSON-encodes the slice/map columns of a RefreshToken
// for storage. Extracted from Issue for the function-length budget.
func marshalRefreshJSONCols(info *oauth.RefreshToken) (scopes, attrs, resources, amr []byte, err error) {
	if scopes, err = json.Marshal(info.Scopes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sqlite: marshal scopes: %w", err)
	}
	if attrs, err = json.Marshal(info.Attributes); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sqlite: marshal attributes: %w", err)
	}
	if resources, err = json.Marshal(info.Resources); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sqlite: marshal resources: %w", err)
	}
	if amr, err = json.Marshal(info.Amr); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("sqlite: marshal amr: %w", err)
	}
	return scopes, attrs, resources, amr, nil
}

// mirrorRefreshFamily records the (token, family_id) pair in the reuse-detection
// ledger so reuse detection survives the active row's Consume DELETE. Empty
// FamilyID = caller opted out of family tracking; no-op.
func (s *RefreshTokenStore) mirrorRefreshFamily(ctx context.Context, token, familyID string) error {
	if familyID == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT OR REPLACE INTO refresh_token_families (token, family_id) VALUES (?, ?)`,
		token, familyID,
	); err != nil {
		return fmt.Errorf("sqlite: insert refresh_token_families: %w", err)
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
                  authorization_details, sid, amr, acr, auth_time,
                  confirmation_jkt, generation, family_created_at`, token)
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
               authorization_details, sid, amr, acr, auth_time,
               confirmation_jkt, generation, family_created_at
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

// DeleteAllForClient implements [oauth.RefreshTokenClientPurger] — removes
// every refresh token bound to clientID across all subjects, so a tenant
// suspension can purge the refresh tokens of every client in the tenant.
// Returns the count of deleted rows.
//
// Wipes the families ledger for every removed entry so future presentations
// of those tokens look like vanilla invalid_grant rather than stale
// reuse-detection events. Empty clientID is a no-op — a blank client is not
// a wildcard, and wiping the whole table on an empty argument would be a
// footgun (use DeleteAllForSubject with an empty client for per-user wipes).
func (s *RefreshTokenStore) DeleteAllForClient(ctx context.Context, clientID string) (int, error) {
	if clientID == "" {
		return 0, nil
	}
	_, _ = s.db.ExecContext(ctx, `
        DELETE FROM refresh_token_families
        WHERE token IN (SELECT token FROM refresh_tokens WHERE client_id = ?)`,
		clientID)
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_tokens WHERE client_id = ?`, clientID)
	if err != nil {
		return 0, fmt.Errorf("sqlite: delete by client: %w", err)
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
	// Reset the per-family rotation window so a re-issued family starts fresh.
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM refresh_rotation_windows WHERE family_id = ?`, familyID); err != nil {
		return 0, fmt.Errorf("sqlite: delete rotation window: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// ListExpiring implements [oauth.RefreshTokenExpiryLister] — see the
// oauthspi doc for the oracle-safety contract (thumbprint only, never the
// raw token). Filters to ACTIVE rows (expires_at >= now, mirroring
// RefreshToken.IsExpired's "now > ExpiresAt" boundary) whose expiry falls at
// or before `before`, soonest-first via the existing
// idx_refresh_tokens_expires_at index. limit <= 0 returns every matching row.
func (s *RefreshTokenStore) ListExpiring(ctx context.Context, before time.Time, limit int) ([]oauth.RefreshTokenExpiry, error) {
	query := `
        SELECT token, user_id, client_id, expires_at
        FROM refresh_tokens
        WHERE expires_at >= ? AND expires_at <= ?
        ORDER BY expires_at ASC`
	args := []any{time.Now().UnixNano(), before.UnixNano()}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list expiring refresh tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []oauth.RefreshTokenExpiry
	for rows.Next() {
		var token, userID, clientID string
		var expiresAtUnixNs int64
		if err := rows.Scan(&token, &userID, &clientID, &expiresAtUnixNs); err != nil {
			return nil, fmt.Errorf("sqlite: scan expiring refresh token: %w", err)
		}
		out = append(out, oauth.RefreshTokenExpiry{
			Thumbprint: oauth.RefreshTokenThumbprint(token),
			UserID:     userID,
			ClientID:   clientID,
			ExpiresAt:  time.Unix(0, expiresAtUnixNs).UTC(),
		})
	}
	return out, rows.Err()
}

func scanRefreshToken(s scanner) (*oauth.RefreshToken, error) {
	var (
		out                                        oauth.RefreshToken
		provider, scopesJSON, attrsJSON, resources string
		familyID, authDetails, sid                 string
		amrJSON, acr                               string
		issuedAtUnixNs, expiresAtUnixNs            int64
		authTimeUnixNs                             int64
		confirmationJKT                            string
		generation                                 int
		familyCreatedAtUnixNs                      int64
	)
	if err := s.Scan(
		&out.UserID, &out.ClientID, &provider,
		&scopesJSON, &attrsJSON,
		&issuedAtUnixNs, &expiresAtUnixNs,
		&familyID, &resources,
		&authDetails, &sid,
		&amrJSON, &acr, &authTimeUnixNs,
		&confirmationJKT, &generation, &familyCreatedAtUnixNs,
	); err != nil {
		return nil, err
	}
	out.ConfirmationJKT = confirmationJKT
	out.Generation = generation
	if authDetails != "" {
		out.AuthorizationDetails = json.RawMessage(authDetails)
	}
	out.Provider = provider
	out.FamilyID = familyID
	out.SID = sid
	out.Acr = acr
	// 0 sentinel = no auth_time captured; leave the zero time so rotation omits
	// the claim rather than emitting the Unix epoch.
	if authTimeUnixNs != 0 {
		out.AuthTime = time.Unix(0, authTimeUnixNs).UTC()
	}
	// Same 0-sentinel discipline for family_created_at — see the Issue-side
	// comment; a zero value SKIPS the absolute-max-lifetime check.
	if familyCreatedAtUnixNs != 0 {
		out.FamilyCreatedAt = time.Unix(0, familyCreatedAtUnixNs).UTC()
	}
	out.IssuedAt = time.Unix(0, issuedAtUnixNs).UTC()
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	if err := decodeRefreshJSONCols(&out, scopesJSON, attrsJSON, resources, amrJSON); err != nil {
		return nil, err
	}
	return &out, nil
}

// decodeRefreshJSONCols unmarshals the JSON-encoded columns onto out. The
// empty / empty-collection sentinels ("", "[]", "{}") are left as the zero
// value rather than allocating an empty slice/map.
func decodeRefreshJSONCols(out *oauth.RefreshToken, scopesJSON, attrsJSON, resources, amrJSON string) error {
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
	if resources != "" && resources != "[]" {
		if err := json.Unmarshal([]byte(resources), &out.Resources); err != nil {
			return fmt.Errorf("sqlite: unmarshal resources: %w", err)
		}
	}
	if amrJSON != "" && amrJSON != "[]" {
		if err := json.Unmarshal([]byte(amrJSON), &out.Amr); err != nil {
			return fmt.Errorf("sqlite: unmarshal amr: %w", err)
		}
	}
	return nil
}

var (
	_ oauth.RefreshTokenStore           = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenInspector       = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenSubjectIndex    = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenFamilyTracker   = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenClientPurger    = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenRotationLimiter = (*RefreshTokenStore)(nil)
	_ oauth.RefreshTokenExpiryLister    = (*RefreshTokenStore)(nil)
)
