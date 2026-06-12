package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/migrate"
)

// consentSchema is the baseline consent_grants table. A single row per
// (user_id, client_id) pair; RecordConsent is an upsert (INSERT OR REPLACE)
// so the grant is always current. scopes stored as a JSON array;
// granted_at as Unix nanoseconds.
const consentSchema = `
CREATE TABLE IF NOT EXISTS consent_grants (
    user_id    TEXT    NOT NULL,
    client_id  TEXT    NOT NULL,
    scopes     TEXT    NOT NULL DEFAULT '[]',
    granted_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_consent_grants_user_id
    ON consent_grants(user_id);
`

var consentMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: consentSchema},
}

// ConsentStore is the SQLite-backed implementation of [core.ConsentStore].
type ConsentStore struct {
	db *sql.DB
}

// NewConsentStore opens dsn, migrates the schema, and returns the store.
func NewConsentStore(dsn string) (*ConsentStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "consent", consentMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate consent: %w", err)
	}
	return &ConsentStore{db: db}, nil
}

// NewConsentStoreWithDB wraps an existing *sql.DB. Caller owns the
// connection lifecycle (shared-pool deployments).
func NewConsentStoreWithDB(db *sql.DB) (*ConsentStore, error) {
	if err := migrate.Run(context.Background(), db, "consent", consentMigrations); err != nil {
		return nil, fmt.Errorf("sqlite: migrate consent: %w", err)
	}
	return &ConsentStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *ConsentStore) Close() error {
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
func (s *ConsentStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck] wiring.
func (s *ConsentStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: consent store closed")
	}
	return s.db.PingContext(ctx)
}

// RecordConsent upserts a grant for (userID, clientID). An existing grant
// is replaced in full (scopes + granted_at updated atomically).
func (s *ConsentStore) RecordConsent(ctx context.Context, grant core.ConsentGrant) error {
	scopesJSON, err := json.Marshal(grant.Scopes)
	if err != nil {
		return fmt.Errorf("sqlite: marshal scopes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO consent_grants (user_id, client_id, scopes, granted_at)
        VALUES (?, ?, ?, ?)`,
		grant.UserID, grant.ClientID, string(scopesJSON), grant.GrantedAt.UnixNano(),
	)
	if err != nil {
		return fmt.Errorf("sqlite: upsert consent_grant: %w", err)
	}
	return nil
}

// GetConsent returns the grant for (userID, clientID), or ErrNoConsentGrant
// when none exists.
func (s *ConsentStore) GetConsent(ctx context.Context, userID, clientID string) (core.ConsentGrant, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT user_id, client_id, scopes, granted_at
          FROM consent_grants WHERE user_id = ? AND client_id = ?`,
		userID, clientID,
	)
	g, err := scanConsentGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return core.ConsentGrant{}, core.ErrNoConsentGrant
	}
	if err != nil {
		return core.ConsentGrant{}, fmt.Errorf("sqlite: get consent_grant: %w", err)
	}
	return g, nil
}

// RevokeConsent removes the grant for (userID, clientID). Idempotent.
func (s *ConsentStore) RevokeConsent(ctx context.Context, userID, clientID string) error {
	_, err := s.db.ExecContext(ctx, `
        DELETE FROM consent_grants WHERE user_id = ? AND client_id = ?`,
		userID, clientID,
	)
	if err != nil {
		return fmt.Errorf("sqlite: delete consent_grant: %w", err)
	}
	return nil
}

// ListByUser returns all grants for userID in descending granted_at order.
// Returns an empty slice (not an error) when none exist.
func (s *ConsentStore) ListByUser(ctx context.Context, userID string) ([]core.ConsentGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT user_id, client_id, scopes, granted_at
          FROM consent_grants WHERE user_id = ?
          ORDER BY granted_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list consent_grants: %w", err)
	}
	defer rows.Close()
	var out []core.ConsentGrant
	for rows.Next() {
		g, err := scanConsentGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("sqlite: scan consent_grant: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows iter: %w", err)
	}
	if out == nil {
		out = []core.ConsentGrant{}
	}
	return out, nil
}

func scanConsentGrant(s scanner) (core.ConsentGrant, error) {
	var (
		g           core.ConsentGrant
		scopesJSON  string
		grantedAtNs int64
	)
	if err := s.Scan(&g.UserID, &g.ClientID, &scopesJSON, &grantedAtNs); err != nil {
		return core.ConsentGrant{}, err
	}
	g.GrantedAt = time.Unix(0, grantedAtNs).UTC()
	if scopesJSON != "" && scopesJSON != "[]" {
		if err := json.Unmarshal([]byte(scopesJSON), &g.Scopes); err != nil {
			return core.ConsentGrant{}, fmt.Errorf("sqlite: unmarshal scopes: %w", err)
		}
	}
	return g, nil
}

var _ core.ConsentStore = (*ConsentStore)(nil)
