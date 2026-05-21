package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// parSchema covers RFC 9126 Pushed Authorization Requests. The
// request_uri opaque suffix is the PK — Issue inserts, Consume
// atomically deletes+returns via DELETE ... RETURNING (same single-
// use contract as auth_codes / device_codes).
//
// Most authorize-request fields are stored verbatim; slices + raw
// JSON (Scope / Resource / AuthorizationDetails / Claims) are
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
    expires_at            INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_par_requests_expires_at
    ON par_requests(expires_at);
`

// PARStore is the SQLite-backed implementation of [sso.PARStore].
// Suitable for multi-replica deployments: a request_uri minted on
// one replica is consumable on the replica that handles the
// subsequent /auth/login redirect.
type PARStore struct {
	db *sql.DB
}

// NewPARStore opens dsn, migrates the schema, and returns the store.
// The provider owns the *sql.DB — Close() releases it. See
// sqlite/users.go for DSN cookbook.
func NewPARStore(dsn string) (*PARStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), parSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate par_requests: %w", err)
	}
	return &PARStore{db: db}, nil
}

// NewPARStoreWithDB wraps an existing *sql.DB. Caller owns the
// connection lifecycle (matches the AuthCodeStore pattern for
// shared-pool deployments).
func NewPARStoreWithDB(db *sql.DB) (*PARStore, error) {
	if _, err := db.ExecContext(context.Background(), parSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate par_requests: %w", err)
	}
	return &PARStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *PARStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Issue persists the request and returns the opaque request_uri the
// client passes to /auth/login. Caller-supplied slices + raw JSON
// are marshaled here so subsequent caller mutations don't leak into
// stored state.
func (s *PARStore) Issue(ctx context.Context, req *sso.PARRequest) (string, error) {
	if req == nil {
		return "", sso.ErrPARNotFound
	}
	tok, err := defaultimpl.GeneratePARToken()
	if err != nil {
		return "", err
	}
	uri := sso.PARURIPrefix + tok

	scopeJSON, err := json.Marshal(req.Scope)
	if err != nil {
		return "", fmt.Errorf("sqlite: marshal scope: %w", err)
	}
	resourceJSON, err := json.Marshal(req.Resource)
	if err != nil {
		return "", fmt.Errorf("sqlite: marshal resource: %w", err)
	}

	_, err = s.db.ExecContext(ctx, `
        INSERT INTO par_requests (
            request_uri, client_id, response_type, redirect_uri,
            scope, state, nonce, code_challenge, code_challenge_method,
            resource, authorization_details, login_hint, response_mode,
            acr_values, ui_locales, claims, expires_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		uri, req.ClientID, req.ResponseType, req.RedirectURI,
		string(scopeJSON), req.State, req.Nonce,
		req.CodeChallenge, req.CodeChallengeMethod,
		string(resourceJSON), string(req.AuthorizationDetails),
		req.LoginHint, req.ResponseMode, req.ACRValues, req.UILocales,
		string(req.Claims), req.ExpiresAt.UnixNano(),
	)
	if err != nil {
		return "", fmt.Errorf("sqlite: insert par_request: %w", err)
	}
	return uri, nil
}

// Consume atomically returns + deletes the row. DELETE ... RETURNING
// makes single-use enforcement race-free — same pattern as
// AuthCodeStore.Consume.
func (s *PARStore) Consume(ctx context.Context, requestURI string) (*sso.PARRequest, error) {
	row := s.db.QueryRowContext(ctx, `
        DELETE FROM par_requests WHERE request_uri = ?
        RETURNING client_id, response_type, redirect_uri, scope,
                  state, nonce, code_challenge, code_challenge_method,
                  resource, authorization_details, login_hint,
                  response_mode, acr_values, ui_locales, claims,
                  expires_at`, requestURI)
	out, err := scanPARRequest(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, sso.ErrPARNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume par_request: %w", err)
	}
	// Expired entries indistinguishable from missing (RFC 9126 §2.2
	// oracle-resistance). Row is already deleted; no separate
	// cleanup needed.
	if out.IsExpired() {
		return nil, sso.ErrPARNotFound
	}
	return out, nil
}

func scanPARRequest(s scanner) (*sso.PARRequest, error) {
	var (
		out                                                         sso.PARRequest
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
			return nil, fmt.Errorf("sqlite: unmarshal scope: %w", err)
		}
	}
	if resourceJSON != "" && resourceJSON != "[]" {
		if err := json.Unmarshal([]byte(resourceJSON), &out.Resource); err != nil {
			return nil, fmt.Errorf("sqlite: unmarshal resource: %w", err)
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

var _ sso.PARStore = (*PARStore)(nil)
