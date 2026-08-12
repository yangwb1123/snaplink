package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memreaper"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
)

// RefreshTokenStore is the Postgres-backed implementation of
// [oauthspi.RefreshTokenStore] plus the full optional extension surface the
// SQLite peer carries, so a postgres deployment never silently loses tenant
// purge / revoke-all / erasure / reuse-detection / rotation-cap features.
type RefreshTokenStore struct {
	db             *sql.DB
	dialect        Dialect
	lookupHMACKeys [][]byte
	reaper         *memreaper.Reaper
	// MaxRotationsPerWindow and RotationWindow configure the optional per-family
	// rotation velocity cap. Both must be positive to arm it.
	MaxRotationsPerWindow int
	RotationWindow        time.Duration
}

// SetLookupHMACKeys enables current-key writes plus previous-key and legacy
// plaintext reads. Keys are copied before retention.
func (s *RefreshTokenStore) SetLookupHMACKeys(keys ...[]byte) {
	s.lookupHMACKeys = cloneLookupKeys(keys...)
}

// NewRefreshTokenStoreWithDB wraps an existing *sql.DB (shared-pool
// deployments) and runs the refresh_tokens namespace migrations. The caller
// owns the pool — Close never releases it.
func NewRefreshTokenStoreWithDB(db *sql.DB, dialect Dialect) (*RefreshTokenStore, error) {
	if db == nil {
		return nil, errors.New("postgres: refresh token store: nil db")
	}
	if err := Run(context.Background(), db, "refresh_tokens", refreshTokenMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate refresh_tokens: %w", err)
	}
	return &RefreshTokenStore{db: db, dialect: dialect}, nil
}

// Close stops the reaper. The shared pool is owned by the caller. Idempotent.
func (s *RefreshTokenStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	_ = s.reaper.Close()
	s.db = nil
	return nil
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
// Nil after Close; callers MUST NOT close it.
func (s *RefreshTokenStore) DB() *sql.DB { return s.db }

// Ping reports connection health for /readyz wiring.
func (s *RefreshTokenStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: refresh token store closed")
	}
	return s.db.PingContext(ctx)
}

// StartReaper sweeps (1) the reuse ledger, (2) expired active tokens, and
// (3) rotation windows whose family has no ledger row left — the SQLite
// peer's three-statement sweep, translated; (3) keeps the table bounded.
func (s *RefreshTokenStore) StartReaper(interval time.Duration) {
	replaceReaper(&s.reaper, memreaper.Start(interval, func(now time.Time) {
		ctx, cancel := context.WithTimeout(context.Background(), postgresExpirySweepTimeout)
		defer cancel()
		nowNs := now.UnixNano()
		_, _ = s.db.ExecContext(ctx, `DELETE FROM refresh_token_families WHERE expires_at < $1`, nowNs)
		_, _ = s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE expires_at < $1`, nowNs)
		// The always-true guard preserves the SQLite shape exactly.
		_, _ = s.db.ExecContext(ctx, `
            DELETE FROM refresh_rotation_windows
             WHERE family_id NOT IN (SELECT family_id FROM refresh_token_families)
               AND $1 > 0`, nowNs)
	}))
}

func (s *RefreshTokenStore) Issue(ctx context.Context, token string, info *oauthspi.RefreshToken) error {
	if token == "" || info == nil {
		return oauthspi.ErrRefreshTokenNotFound
	}
	scopes, attrs, resources, amr, roles, err := marshalRefreshJSONCols(info)
	if err != nil {
		return err
	}
	// Insert + reuse-ledger mirror in ONE transaction (fail closed): an active
	// token without a ledger row would silently disable reuse detection.
	// Default isolation is correct (append-only); runTx retries CRDB 40001.
	lookup := opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "refresh_token", token)
	err = runTx(ctx, s.db, nil, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `
        INSERT INTO refresh_tokens (token, user_id, client_id, provider,
            scopes, attributes, issued_at, expires_at, family_id, jti, resources,
            authorization_details, sid, amr, acr, auth_time, confirmation_jkt,
            generation, family_created_at, roles)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)`,
			lookup, info.UserID, info.ClientID, info.Provider,
			string(scopes), string(attrs),
			info.IssuedAt.UnixNano(), info.ExpiresAt.UnixNano(),
			info.FamilyID, info.JTI, string(resources),
			string(info.AuthorizationDetails), info.SID,
			string(amr), info.Acr, unixNanoOrZero(info.AuthTime), info.ConfirmationJKT,
			info.Generation, unixNanoOrZero(info.FamilyCreatedAt), string(roles),
		); err != nil {
			return fmt.Errorf("postgres: insert refresh_token: %w", err)
		}
		return mirrorRefreshFamilyTx(ctx, tx, lookup, info.FamilyID, info.ExpiresAt)
	})
	if err != nil {
		return err
	}
	return nil
}

// marshalRefreshJSONCols JSON-encodes the slice/map columns of a RefreshToken
// for storage. Extracted from Issue for the function-length budget.
func marshalRefreshJSONCols(info *oauthspi.RefreshToken) (scopes, attrs, resources, amr, roles []byte, err error) {
	if scopes, err = json.Marshal(info.Scopes); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres: marshal scopes: %w", err)
	}
	if attrs, err = json.Marshal(info.Attributes); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres: marshal attributes: %w", err)
	}
	if resources, err = json.Marshal(info.Resources); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres: marshal resources: %w", err)
	}
	if amr, err = json.Marshal(info.Amr); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres: marshal amr: %w", err)
	}
	if roles, err = json.Marshal(info.Roles); err != nil {
		return nil, nil, nil, nil, nil, fmt.Errorf("postgres: marshal roles: %w", err)
	}
	return scopes, attrs, resources, amr, roles, nil
}

// mirrorRefreshFamilyTx mirrors the (token, family_id) reuse-ledger row with
// a validity-window expiry, inside the Issue transaction (fail closed). Empty
// familyID = no family tracking, no ledger row.
func mirrorRefreshFamilyTx(ctx context.Context, tx *sql.Tx, token, familyID string, expiresAt time.Time) error {
	if familyID == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
        INSERT INTO refresh_token_families (token, family_id, expires_at)
        VALUES ($1, $2, $3)
        ON CONFLICT (token) DO UPDATE
            SET family_id = excluded.family_id, expires_at = excluded.expires_at`,
		token, familyID, expiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("postgres: insert refresh_token_families: %w", err)
	}
	return nil
}

// Consume atomically deletes + returns the row (single-use rotation via
// DELETE...RETURNING). On a miss, falls back to the families ledger: a token
// known there but not in refresh_tokens is a reuse-after-rotation — return
// oauthspi.ErrRefreshTokenReused with the family_id stamped on the record so
// the handler can kill the entire family (BCP §4.13).
func (s *RefreshTokenStore) Consume(ctx context.Context, token string) (*oauthspi.RefreshToken, error) {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "refresh_token", token) {
		out, err := s.consume(ctx, candidate)
		if !errors.Is(err, oauthspi.ErrRefreshTokenNotFound) {
			return out, err
		}
	}
	return nil, oauthspi.ErrRefreshTokenNotFound
}

func (s *RefreshTokenStore) consume(ctx context.Context, lookup string) (*oauthspi.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM refresh_tokens WHERE token = $1
        RETURNING user_id, client_id, provider, scopes, attributes,
                  issued_at, expires_at, family_id, jti, resources,
                  authorization_details, sid, amr, acr, auth_time,
                  confirmation_jkt, generation, family_created_at, roles`, lookup)
	out, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		// Reuse-detection path: DELETE-then-SELECT needs no transaction (token
		// values are unique randoms — no interleaving hazard).
		var familyID string
		ferr := s.db.QueryRowContext(ctx,
			`SELECT family_id FROM refresh_token_families WHERE token = $1`, lookup,
		).Scan(&familyID)
		if errors.Is(ferr, sql.ErrNoRows) {
			return nil, oauthspi.ErrRefreshTokenNotFound
		}
		if ferr != nil {
			return nil, fmt.Errorf("postgres: family lookup: %w", ferr)
		}
		return &oauthspi.RefreshToken{FamilyID: familyID}, oauthspi.ErrRefreshTokenReused
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: consume refresh_token: %w", err)
	}
	if out.IsExpired() {
		return nil, oauthspi.ErrRefreshTokenNotFound
	}
	return out, nil
}

// Inspect implements [oauthspi.RefreshTokenInspector] — non-destructive
// SELECT; expired entries are deleted opportunistically (both tables in one
// tx) so the table self-trims as it's read.
func (s *RefreshTokenStore) Inspect(ctx context.Context, token string) (*oauthspi.RefreshToken, error) {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "refresh_token", token) {
		out, err := s.inspect(ctx, candidate)
		if !errors.Is(err, oauthspi.ErrRefreshTokenNotFound) {
			return out, err
		}
	}
	return nil, oauthspi.ErrRefreshTokenNotFound
}

func (s *RefreshTokenStore) inspect(ctx context.Context, lookup string) (*oauthspi.RefreshToken, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT user_id, client_id, provider, scopes, attributes,
               issued_at, expires_at, family_id, jti, resources,
               authorization_details, sid, amr, acr, auth_time,
               confirmation_jkt, generation, family_created_at, roles
        FROM refresh_tokens WHERE token = $1`, lookup)
	out, err := scanRefreshToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauthspi.ErrRefreshTokenNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: inspect refresh_token: %w", err)
	}
	if out.IsExpired() {
		_ = runTx(ctx, s.db, nil, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = $1`, lookup); err != nil {
				return err
			}
			_, err := tx.ExecContext(ctx, `DELETE FROM refresh_token_families WHERE token = $1`, lookup)
			return err
		})
		return nil, oauthspi.ErrRefreshTokenNotFound
	}
	return out, nil
}

// Delete is idempotent per RFC 7009 §2.2 — unknown tokens return nil. Wipes
// the families ledger too so an explicit /token/revoke can't subsequently
// mis-trigger a reuse-detection event on the same token.
func (s *RefreshTokenStore) Delete(ctx context.Context, token string) error {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "refresh_token", token) {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM refresh_tokens WHERE token = $1`, candidate); err != nil {
			return fmt.Errorf("postgres: delete refresh_token: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM refresh_token_families WHERE token = $1`, candidate); err != nil {
			return fmt.Errorf("postgres: delete refresh_token_families: %w", err)
		}
	}
	return nil
}

// deleteTokensAndLedger deletes the active rows matching whereClause (a code
// constant, never user input) AND their ledger rows in one transaction, so a
// revoked subject/client leaves no reuse ghosts (fail-closed on the ledger
// wipe — a deliberate divergence from the SQLite peer's ignored errors).
func (s *RefreshTokenStore) deleteTokensAndLedger(ctx context.Context, whereClause string, args ...any) (int, error) {
	var deleted int64
	err := runTx(ctx, s.db, nil, func(tx *sql.Tx) error {
		ledgerQuery := `DELETE FROM refresh_token_families
             WHERE token IN (SELECT token FROM refresh_tokens WHERE ` + whereClause + `)`
		if _, err := tx.ExecContext(ctx, ledgerQuery, args...); err != nil {
			return fmt.Errorf("postgres: delete ledger: %w", err)
		}
		res, err := tx.ExecContext(ctx,
			`DELETE FROM refresh_tokens WHERE `+whereClause, args...)
		if err != nil {
			return fmt.Errorf("postgres: delete tokens: %w", err)
		}
		deleted, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, err
	}
	return int(deleted), nil
}

// DeleteAllForSubject implements [oauthspi.RefreshTokenSubjectIndex]. Empty
// clientID = revoke across every client the user has tokens for. Returns the
// count of deleted rows.
func (s *RefreshTokenStore) DeleteAllForSubject(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	if clientID == "" {
		return s.deleteTokensAndLedger(ctx, `user_id = $1`, userID)
	}
	return s.deleteTokensAndLedger(ctx, `user_id = $1 AND client_id = $2`, userID, clientID)
}

// DeleteAllForClient implements [oauthspi.RefreshTokenClientPurger] — removes
// every refresh token bound to clientID across all subjects, so a tenant
// suspension can purge the refresh tokens of every client in the tenant.
// Empty clientID is a NO-OP, not a wildcard (oauthspi hard requirement).
func (s *RefreshTokenStore) DeleteAllForClient(ctx context.Context, clientID string) (int, error) {
	if clientID == "" {
		return 0, nil
	}
	return s.deleteTokensAndLedger(ctx, `client_id = $1`, clientID)
}

// CountForSubject implements [oauthspi.RefreshTokenSubjectCounter] — counts
// the subject's tokens without deleting them, for erasure dry-run previews.
func (s *RefreshTokenStore) CountForSubject(ctx context.Context, userID, clientID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	var n int
	var err error
	if clientID == "" {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1`, userID).Scan(&n)
	} else {
		err = s.db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1 AND client_id = $2`,
			userID, clientID).Scan(&n)
	}
	if err != nil {
		return 0, fmt.Errorf("postgres: count by subject: %w", err)
	}
	return n, nil
}

// DeleteFamily implements [oauthspi.RefreshTokenFamilyTracker] — kills every
// active refresh token sharing the FamilyID, wipes the matching reuse-
// detection ledger rows, and resets the rotation window so a re-issued
// family starts fresh. Returns the count of active tokens removed.
func (s *RefreshTokenStore) DeleteFamily(ctx context.Context, familyID string) (int, error) {
	if familyID == "" {
		return 0, nil
	}
	var killed int64
	err := runTx(ctx, s.db, nil, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx,
			`DELETE FROM refresh_tokens WHERE family_id = $1`, familyID)
		if err != nil {
			return fmt.Errorf("postgres: delete family: %w", err)
		}
		killed, _ = res.RowsAffected()
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM refresh_token_families WHERE family_id = $1`, familyID); err != nil {
			return fmt.Errorf("postgres: delete family ledger: %w", err)
		}
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM refresh_rotation_windows WHERE family_id = $1`, familyID); err != nil {
			return fmt.Errorf("postgres: delete rotation window: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return int(killed), nil
}

// ListExpiring implements [oauthspi.RefreshTokenExpiryLister] — see the
// oauthspi doc for the oracle-safety contract (thumbprint only, never the raw
// token). Parity detail: the thumbprint is computed over the STORED lookup
// value (the h1: column), exactly like the SQLite peer — never over the raw
// token, which would require persisting secrets. Active rows only, soonest-
// first; limit <= 0 returns every matching row.
func (s *RefreshTokenStore) ListExpiring(ctx context.Context, before time.Time, limit int) ([]oauthspi.RefreshTokenExpiry, error) {
	query := `
        SELECT token, user_id, client_id, expires_at
        FROM refresh_tokens
        WHERE expires_at >= $1 AND expires_at <= $2
        ORDER BY expires_at ASC`
	args := []any{time.Now().UnixNano(), before.UnixNano()}
	if limit > 0 {
		query += ` LIMIT $3`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("postgres: list expiring refresh tokens: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []oauthspi.RefreshTokenExpiry
	for rows.Next() {
		var token, userID, clientID string
		var expiresAtUnixNs int64
		if err := rows.Scan(&token, &userID, &clientID, &expiresAtUnixNs); err != nil {
			return nil, fmt.Errorf("postgres: scan expiring refresh token: %w", err)
		}
		out = append(out, oauthspi.RefreshTokenExpiry{
			Thumbprint: oauthspi.RefreshTokenThumbprint(token),
			UserID:     userID,
			ClientID:   clientID,
			ExpiresAt:  time.Unix(0, expiresAtUnixNs).UTC(),
		})
	}
	return out, rows.Err()
}

func scanRefreshToken(s scanner) (*oauthspi.RefreshToken, error) {
	var (
		out                                                      oauthspi.RefreshToken
		provider, scopesJSON, attrsJSON, resources               string
		familyID, jti, authDetails, sid, amrJSON, acr, rolesJSON string
		confirmationJKT                                          string
		issuedAtUnixNs, expiresAtUnixNs, authTimeUnixNs          int64
		generation, familyCreatedAtUnixNs                        int64
	)
	if err := s.Scan(
		&out.UserID, &out.ClientID, &provider,
		&scopesJSON, &attrsJSON,
		&issuedAtUnixNs, &expiresAtUnixNs,
		&familyID, &jti, &resources,
		&authDetails, &sid,
		&amrJSON, &acr, &authTimeUnixNs,
		&confirmationJKT, &generation, &familyCreatedAtUnixNs, &rolesJSON,
	); err != nil {
		return nil, err
	}
	out.ConfirmationJKT = confirmationJKT
	out.Generation = int(generation)
	out.JTI = jti
	if authDetails != "" {
		out.AuthorizationDetails = json.RawMessage(authDetails)
	}
	out.Provider = provider
	out.FamilyID = familyID
	out.SID = sid
	out.Acr = acr
	// 0 sentinel = no auth_time captured; leave the zero time so rotation
	// omits the claim rather than emitting the Unix epoch.
	if authTimeUnixNs != 0 {
		out.AuthTime = time.Unix(0, authTimeUnixNs).UTC()
	}
	// Same 0-sentinel discipline for family_created_at — a zero value SKIPS
	// the absolute-max-lifetime check.
	if familyCreatedAtUnixNs != 0 {
		out.FamilyCreatedAt = time.Unix(0, familyCreatedAtUnixNs).UTC()
	}
	out.IssuedAt = time.Unix(0, issuedAtUnixNs).UTC()
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	if err := decodeRefreshJSONCols(&out, scopesJSON, attrsJSON, resources, amrJSON, rolesJSON); err != nil {
		return nil, err
	}
	return &out, nil
}

// decodeRefreshJSONCols unmarshals the JSON-encoded columns onto out. The
// empty / empty-collection sentinels stay the zero value.
func decodeRefreshJSONCols(out *oauthspi.RefreshToken, scopesJSON, attrsJSON, resources, amrJSON, rolesJSON string) error {
	cols := []refreshJSONCol{
		{scopesJSON, "[]", &out.Scopes, "scopes"},
		{attrsJSON, "{}", &out.Attributes, "attributes"},
		{resources, "[]", &out.Resources, "resources"},
		{amrJSON, "[]", &out.Amr, "amr"},
		{rolesJSON, "[]", &out.Roles, "roles"},
	}
	for _, c := range cols {
		if c.raw == "" || c.raw == c.empty {
			continue
		}
		if err := json.Unmarshal([]byte(c.raw), c.dst); err != nil {
			return fmt.Errorf("postgres: unmarshal %s: %w", c.name, err)
		}
	}
	return nil
}

// refreshJSONCol is one JSON-encoded refresh_tokens column: the raw text,
// the empty-collection sentinel that means "no value", the destination, and
// the column name for error messages. Table-driven so decodeRefreshJSONCols
// stays within the complexity budget as columns are added.
type refreshJSONCol struct {
	raw, empty string
	dst        any
	name       string
}

var (
	_ oauthspi.RefreshTokenStore           = (*RefreshTokenStore)(nil)
	_ oauthspi.RefreshTokenInspector       = (*RefreshTokenStore)(nil)
	_ oauthspi.RefreshTokenSubjectIndex    = (*RefreshTokenStore)(nil)
	_ oauthspi.RefreshTokenSubjectCounter  = (*RefreshTokenStore)(nil)
	_ oauthspi.RefreshTokenClientPurger    = (*RefreshTokenStore)(nil)
	_ oauthspi.RefreshTokenFamilyTracker   = (*RefreshTokenStore)(nil)
	_ oauthspi.RefreshTokenRotationLimiter = (*RefreshTokenStore)(nil)
	_ oauthspi.RefreshTokenExpiryLister    = (*RefreshTokenStore)(nil)
)
