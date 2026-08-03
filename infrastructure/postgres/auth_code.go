package postgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memreaper"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
)

const opaqueLookupPrefix = "h1:"

// The opaque-lookup HMAC helpers are shared by every OAuth hot store in this
// package (auth_code, refresh_token, device_code, par) and folded into this
// file exactly like the SQLite peers keep them in auth_codes.go. The stored
// lookup value is domain-separated (kind || 0x00 || raw) so a value minted
// for one artifact class can never be replayed as another.
func opaqueLookupKey(key []byte, kind, raw string) string {
	if len(key) == 0 {
		return raw
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	return opaqueLookupPrefix + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// opaqueLookupCandidates returns the read candidates in order: current key,
// then previous key, then legacy plaintext. A no-logout key rotation works
// because old rows are still readable via the previous key until their TTL
// elapses, and pre-feature rows via the plaintext fallback.
func opaqueLookupCandidates(keys [][]byte, kind, raw string) []string {
	out := make([]string, 0, len(keys)+1)
	for _, key := range keys {
		out = append(out, opaqueLookupKey(key, kind, raw))
	}
	return append(out, raw)
}

func cloneLookupKeys(keys ...[]byte) [][]byte {
	out := make([][]byte, 0, len(keys))
	for _, key := range keys {
		if len(key) > 0 {
			out = append(out, append([]byte(nil), key...))
		}
	}
	return out
}

func firstLookupKey(keys [][]byte) []byte {
	if len(keys) == 0 {
		return nil
	}
	return keys[0]
}

// postgresExpirySweepTimeout bounds each reaper sweep so a wedged pool can
// never pin a background goroutine forever.
const postgresExpirySweepTimeout = 30 * time.Second

// replaceReaper stops the previous sweep loop (if any) before installing the
// next one, so StartReaper is idempotent and Close leaks no goroutines.
func replaceReaper(current **memreaper.Reaper, next *memreaper.Reaper) {
	if *current != nil {
		_ = (*current).Close()
	}
	*current = next
}

// authCodeSchema is the Postgres-dialect baseline for the OAuth 2.0
// authorization_code grant data model — short-lived (10 min default),
// single-use, optionally PKCE-bound. Full column set in one baseline
// migration (the SQLite v2-v4 backfill ladder exists only for legacy
// SQLite databases and is not translated); columns mirror the SQLite
// peer verbatim with BIGINT Unix-nanosecond timestamps.
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
    auth_time             BIGINT  NOT NULL DEFAULT 0,
    amr                   TEXT    NOT NULL DEFAULT '[]',
    acr                   TEXT    NOT NULL DEFAULT '',
    resources             TEXT    NOT NULL DEFAULT '[]',
    authorization_details TEXT    NOT NULL DEFAULT '',
    sid                   TEXT    NOT NULL DEFAULT '',
    requested_claims      TEXT    NOT NULL DEFAULT '',
    expires_at            BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_codes_expires_at
    ON auth_codes(expires_at);
`

var authCodeMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: authCodeSchema},
}

// AuthCodeStore is the Postgres-backed implementation of
// [oauthspi.AuthCodeStore]. Suitable for multi-replica deployments since
// every replica issues + consumes against the same database.
type AuthCodeStore struct {
	db             *sql.DB
	dialect        Dialect
	lookupHMACKeys [][]byte
	reaper         *memreaper.Reaper
}

// SetLookupHMACKeys enables current-key writes plus previous-key and legacy
// plaintext reads for rolling migration. Keys are copied before retention.
func (s *AuthCodeStore) SetLookupHMACKeys(keys ...[]byte) {
	s.lookupHMACKeys = cloneLookupKeys(keys...)
}

// NewAuthCodeStoreWithDB wraps an existing *sql.DB (shared-pool deployments)
// and runs the auth_codes namespace migrations. The caller owns the pool —
// Close never releases it (matches NewSessionManagerWithDB).
func NewAuthCodeStoreWithDB(db *sql.DB, dialect Dialect) (*AuthCodeStore, error) {
	if db == nil {
		return nil, errors.New("postgres: auth code store: nil db")
	}
	if err := Run(context.Background(), db, "auth_codes", authCodeMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate auth_codes: %w", err)
	}
	return &AuthCodeStore{db: db, dialect: dialect}, nil
}

// Close stops the reaper. The shared pool is owned by the caller, so the
// connection is never closed here. Idempotent.
func (s *AuthCodeStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	_ = s.reaper.Close()
	s.db = nil
	return nil
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
// Nil after Close; callers MUST NOT close it.
func (s *AuthCodeStore) DB() *sql.DB { return s.db }

// Ping reports connection health for /readyz wiring.
func (s *AuthCodeStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: auth code store closed")
	}
	return s.db.PingContext(ctx)
}

// StartReaper runs a background sweep of expired codes; interval <= 0
// disables it (lazy consume-time deletion still bounds growth).
func (s *AuthCodeStore) StartReaper(interval time.Duration) {
	replaceReaper(&s.reaper, memreaper.Start(interval, func(now time.Time) {
		ctx, cancel := context.WithTimeout(context.Background(), postgresExpirySweepTimeout)
		defer cancel()
		_, _ = s.db.ExecContext(ctx, `DELETE FROM auth_codes WHERE expires_at < $1`, now.UnixNano())
	}))
}

// Issue persists the auth code. Caller-supplied slices / maps are
// JSON-marshaled at this point so subsequent caller mutations don't leak
// into stored state.
func (s *AuthCodeStore) Issue(ctx context.Context, code string, info *oauthspi.AuthCode) error {
	if code == "" || info == nil {
		return oauthspi.ErrAuthCodeNotFound
	}
	scopes, err := json.Marshal(info.Scopes)
	if err != nil {
		return fmt.Errorf("postgres: marshal scopes: %w", err)
	}
	attrs, err := json.Marshal(info.Attributes)
	if err != nil {
		return fmt.Errorf("postgres: marshal attributes: %w", err)
	}
	resources, err := json.Marshal(info.Resources)
	if err != nil {
		return fmt.Errorf("postgres: marshal resources: %w", err)
	}
	amr, err := json.Marshal(info.AuthMethods)
	if err != nil {
		return fmt.Errorf("postgres: marshal amr: %w", err)
	}
	// Zero-sentinel discipline (matches the SQLite peer): a zero AuthTime
	// stores 0 so the /token exchange falls back to now rather than emitting
	// the Unix epoch.
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO auth_codes (
            code, user_id, client_id, redirect_uri, scopes, nonce,
            provider, attributes, code_challenge, code_challenge_method,
            confirmation_jkt, auth_time, amr, acr, resources,
            authorization_details, sid, requested_claims, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)`,
		opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "auth_code", code),
		info.UserID, info.ClientID, info.RedirectURI,
		string(scopes), info.Nonce, info.Provider, string(attrs),
		info.CodeChallenge, info.CodeChallengeMethod, info.ConfirmationJKT,
		unixNanoOrZero(info.AuthTime), string(amr), info.ACR, string(resources),
		string(info.AuthorizationDetails), info.SID,
		string(info.RequestedClaims), // raw §5.5 claims JSON; '' = none
		info.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("postgres: insert auth_code: %w", err)
	}
	return nil
}

// Consume atomically returns + deletes the row via a single
// DELETE ... RETURNING statement — the atomic claim, so of N concurrent
// Consume calls for one code exactly one wins (same race-safe contract as
// the SQLite peer's RETURNING consume).
func (s *AuthCodeStore) Consume(ctx context.Context, code string) (*oauthspi.AuthCode, error) {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "auth_code", code) {
		out, err := s.consume(ctx, candidate)
		if !errors.Is(err, oauthspi.ErrAuthCodeNotFound) {
			return out, err
		}
	}
	return nil, oauthspi.ErrAuthCodeNotFound
}

func (s *AuthCodeStore) consume(ctx context.Context, lookup string) (*oauthspi.AuthCode, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM auth_codes WHERE code = $1
        RETURNING user_id, client_id, redirect_uri, scopes, nonce,
                  provider, attributes, code_challenge, code_challenge_method,
                  confirmation_jkt, auth_time, amr, acr, resources,
                  authorization_details, sid, requested_claims, expires_at`, lookup)
	out, err := scanAuthCode(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauthspi.ErrAuthCodeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: consume auth_code: %w", err)
	}
	// Expired entries indistinguishable from missing — same oracle-
	// resistance the memory backend enforces. The row is already
	// deleted at this point, so no separate cleanup needed.
	if out.IsExpired() {
		return nil, oauthspi.ErrAuthCodeNotFound
	}
	return out, nil
}

func scanAuthCode(s scanner) (*oauthspi.AuthCode, error) {
	var (
		out                                                                                     oauthspi.AuthCode
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
	// 0 sentinel = no auth_time captured; leave the zero time so the /token
	// exchange falls back to now rather than emitting the Unix epoch.
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
// Extracted from scanAuthCode for the function-length budget. The empty /
// empty-collection sentinels ("", "[]", "{}") are left as the zero value
// rather than allocating an empty slice/map.
func decodeAuthCodeJSONCols(out *oauthspi.AuthCode, scopesJSON, attrsJSON, resourcesJSON, amrJSON string) error {
	if scopesJSON != "" && scopesJSON != "[]" {
		if err := json.Unmarshal([]byte(scopesJSON), &out.Scopes); err != nil {
			return fmt.Errorf("postgres: unmarshal scopes: %w", err)
		}
	}
	if attrsJSON != "" && attrsJSON != "{}" {
		if err := json.Unmarshal([]byte(attrsJSON), &out.Attributes); err != nil {
			return fmt.Errorf("postgres: unmarshal attributes: %w", err)
		}
	}
	if resourcesJSON != "" && resourcesJSON != "[]" {
		if err := json.Unmarshal([]byte(resourcesJSON), &out.Resources); err != nil {
			return fmt.Errorf("postgres: unmarshal resources: %w", err)
		}
	}
	if amrJSON != "" && amrJSON != "[]" {
		if err := json.Unmarshal([]byte(amrJSON), &out.AuthMethods); err != nil {
			return fmt.Errorf("postgres: unmarshal amr: %w", err)
		}
	}
	return nil
}

// AuthCodesMaxVersion returns the highest migration version declared for
// the auth_codes namespace — the boot-gate input for the postgres backend
// branch (parallel to sqlitestores.AuthCodesMaxVersion).
func AuthCodesMaxVersion() int { return migrate.MaxVersion(authCodeMigrations) }

var _ oauthspi.AuthCodeStore = (*AuthCodeStore)(nil)
