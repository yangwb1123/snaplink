package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memreaper"
	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/protocols/oauth/oauthspi"
)

// parSchema covers RFC 9126 Pushed Authorization Requests. The request_uri
// opaque suffix is the PK — Issue inserts, Consume atomically deletes+returns
// via DELETE ... RETURNING (same single-use contract as auth_codes /
// device_codes). Most authorize-request fields are stored verbatim; slices +
// raw JSON (Scope / Resource / AuthorizationDetails / Claims) are
// JSON-encoded since we never query into them — full-row reads only.
const parSchema = `
CREATE TABLE IF NOT EXISTS par_requests (
    request_uri           TEXT    PRIMARY KEY,
    client_id             TEXT    NOT NULL,
    response_type         TEXT    NOT NULL DEFAULT '',
    redirect_uri          TEXT    NOT NULL DEFAULT '',
    scope                 TEXT    NOT NULL DEFAULT '[]',
    state                 TEXT    NOT NULL DEFAULT '',
    nonce                 TEXT    NOT NULL DEFAULT '',
    code_challenge        TEXT    NOT NULL DEFAULT '',
    code_challenge_method TEXT    NOT NULL DEFAULT '',
    resource              TEXT    NOT NULL DEFAULT '[]',
    authorization_details TEXT    NOT NULL DEFAULT '',
    login_hint            TEXT    NOT NULL DEFAULT '',
    response_mode         TEXT    NOT NULL DEFAULT '',
    acr_values            TEXT    NOT NULL DEFAULT '',
    ui_locales            TEXT    NOT NULL DEFAULT '',
    claims                TEXT    NOT NULL DEFAULT '',
    expires_at            BIGINT  NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_par_requests_expires_at
    ON par_requests(expires_at);
`

var parMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: parSchema},
}

// PARStore is the Postgres-backed implementation of [oauthspi.PARStore].
// Suitable for multi-replica deployments: a request_uri minted on one replica
// is consumable on the replica that handles the subsequent /auth/login
// redirect.
type PARStore struct {
	db             *sql.DB
	dialect        Dialect
	lookupHMACKeys [][]byte
	reaper         *memreaper.Reaper
}

// SetLookupHMACKeys enables current-key writes plus previous-key and legacy
// plaintext reads for rolling migration. Keys are copied before retention.
func (s *PARStore) SetLookupHMACKeys(keys ...[]byte) {
	s.lookupHMACKeys = cloneLookupKeys(keys...)
}

// NewPARStoreWithDB wraps an existing *sql.DB (shared-pool deployments) and
// runs the par namespace migrations. The caller owns the pool — Close never
// releases it.
func NewPARStoreWithDB(db *sql.DB, dialect Dialect) (*PARStore, error) {
	if db == nil {
		return nil, errors.New("postgres: par store: nil db")
	}
	if err := Run(context.Background(), db, "par", parMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate par: %w", err)
	}
	return &PARStore{db: db, dialect: dialect}, nil
}

// Close stops the reaper. The shared pool is owned by the caller. Idempotent.
func (s *PARStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	_ = s.reaper.Close()
	s.db = nil
	return nil
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
// Nil after Close; callers MUST NOT close it.
func (s *PARStore) DB() *sql.DB { return s.db }

// Ping reports connection health for /readyz wiring.
func (s *PARStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: par store closed")
	}
	return s.db.PingContext(ctx)
}

// StartReaper runs a background sweep of expired request_uris; interval <= 0
// disables it (lazy consume-time deletion still bounds growth).
func (s *PARStore) StartReaper(interval time.Duration) {
	replaceReaper(&s.reaper, memreaper.Start(interval, func(now time.Time) {
		ctx, cancel := context.WithTimeout(context.Background(), postgresExpirySweepTimeout)
		defer cancel()
		_, _ = s.db.ExecContext(ctx, `DELETE FROM par_requests WHERE expires_at < $1`, now.UnixNano())
	}))
}

// Issue persists the request and returns the opaque request_uri the client
// passes to /auth/login. Caller-supplied slices + raw JSON are marshaled here
// so subsequent caller mutations don't leak into stored state.
func (s *PARStore) Issue(ctx context.Context, req *oauthspi.PARRequest) (string, error) {
	if req == nil {
		return "", oauthspi.ErrPARNotFound
	}
	tok, err := defaultimpl.GeneratePARToken()
	if err != nil {
		return "", err
	}
	uri := oauthspi.PARURIPrefix + tok

	scopeJSON, err := json.Marshal(req.Scope)
	if err != nil {
		return "", fmt.Errorf("postgres: marshal scope: %w", err)
	}
	resourceJSON, err := json.Marshal(req.Resource)
	if err != nil {
		return "", fmt.Errorf("postgres: marshal resource: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
        INSERT INTO par_requests (
            request_uri, client_id, response_type, redirect_uri,
            scope, state, nonce, code_challenge, code_challenge_method,
            resource, authorization_details, login_hint, response_mode,
            acr_values, ui_locales, claims, expires_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		opaqueLookupKey(firstLookupKey(s.lookupHMACKeys), "par", uri),
		req.ClientID, req.ResponseType, req.RedirectURI,
		string(scopeJSON), req.State, req.Nonce,
		req.CodeChallenge, req.CodeChallengeMethod,
		string(resourceJSON), string(req.AuthorizationDetails),
		req.LoginHint, req.ResponseMode, req.ACRValues, req.UILocales,
		string(req.Claims), req.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return "", fmt.Errorf("postgres: insert par_request: %w", err)
	}
	return uri, nil
}

// Consume atomically returns + deletes the row. DELETE ... RETURNING makes
// single-use enforcement race-free — same pattern as the auth-code store.
func (s *PARStore) Consume(ctx context.Context, requestURI string) (*oauthspi.PARRequest, error) {
	for _, candidate := range opaqueLookupCandidates(s.lookupHMACKeys, "par", requestURI) {
		out, err := s.consume(ctx, candidate)
		if !errors.Is(err, oauthspi.ErrPARNotFound) {
			return out, err
		}
	}
	return nil, oauthspi.ErrPARNotFound
}

func (s *PARStore) consume(ctx context.Context, lookup string) (*oauthspi.PARRequest, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM par_requests WHERE request_uri = $1
        RETURNING client_id, response_type, redirect_uri, scope,
                  state, nonce, code_challenge, code_challenge_method,
                  resource, authorization_details, login_hint,
                  response_mode, acr_values, ui_locales, claims,
                  expires_at`, lookup)
	out, err := scanPARRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, oauthspi.ErrPARNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: consume par_request: %w", err)
	}
	// Expired entries indistinguishable from missing (RFC 9126 §2.2
	// oracle-resistance). Row is already deleted; no separate cleanup needed.
	if out.IsExpired() {
		return nil, oauthspi.ErrPARNotFound
	}
	return out, nil
}

func scanPARRequest(s scanner) (*oauthspi.PARRequest, error) {
	var (
		out                                                         oauthspi.PARRequest
		responseType, redirectURI, state, nonce                     string
		codeChallenge, codeChallengeMethod, scopeJSON, resourceJSON string
		loginHint, responseMode, acrValues, uiLocales               string
		authzDetails, claims                                        string
		expiresAtUnixNs                                             int64
	)
	if err := s.Scan(
		&out.ClientID, &responseType, &redirectURI, &scopeJSON,
		&state, &nonce, &codeChallenge, &codeChallengeMethod,
		&resourceJSON, &authzDetails, &loginHint, &responseMode,
		&acrValues, &uiLocales, &claims, &expiresAtUnixNs,
	); err != nil {
		return nil, err
	}
	out.ResponseType = responseType
	out.RedirectURI = redirectURI
	out.State = state
	out.Nonce = nonce
	out.CodeChallenge = codeChallenge
	out.CodeChallengeMethod = codeChallengeMethod
	out.LoginHint = loginHint
	out.ResponseMode = responseMode
	out.ACRValues = acrValues
	out.UILocales = uiLocales
	out.ExpiresAt = time.Unix(0, expiresAtUnixNs).UTC()
	if scopeJSON != "" && scopeJSON != "[]" {
		if err := json.Unmarshal([]byte(scopeJSON), &out.Scope); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal scope: %w", err)
		}
	}
	if resourceJSON != "" && resourceJSON != "[]" {
		if err := json.Unmarshal([]byte(resourceJSON), &out.Resource); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal resource: %w", err)
		}
	}
	if authzDetails != "" {
		out.AuthorizationDetails = json.RawMessage(authzDetails)
	}
	if claims != "" {
		out.Claims = json.RawMessage(claims)
	}
	return &out, nil
}

// PARMaxVersion returns the highest migration version declared for the par
// namespace — the boot-gate input for the postgres branch.
func PARMaxVersion() int { return migrate.MaxVersion(parMigrations) }

var _ oauthspi.PARStore = (*PARStore)(nil)
