package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

// scanner is the *sql.Row / *sql.Rows subset the scan helpers need, so one
// helper serves both single-row and iterating reads.
type scanner interface {
	Scan(dest ...any) error
}

// consentSchema is the baseline consent_grants table (Postgres dialect). One
// row per (user_id, client_id); RecordConsent upserts via ON CONFLICT so the
// grant is always current. scopes is a JSON array stored as TEXT; granted_at is
// Unix nanoseconds in a BIGINT (NOT timestamptz — preserves exact round-trip +
// oracle-resistant expiry, matching the SQLite peer).
const consentSchema = `
CREATE TABLE IF NOT EXISTS consent_grants (
    user_id    TEXT   NOT NULL,
    client_id  TEXT   NOT NULL,
    scopes     TEXT   NOT NULL DEFAULT '[]',
    granted_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_consent_grants_user_id
    ON consent_grants(user_id);
`

var consentMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: consentSchema},
	{Version: 2, Name: "add_expires_at", SQL: `
ALTER TABLE consent_grants ADD COLUMN expires_at BIGINT NOT NULL DEFAULT 0`},
}

// ConsentStore is the Postgres-backed implementation of [core.ConsentStore].
type ConsentStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewConsentStore opens cfg.DSN, migrates the schema, and returns the store.
func NewConsentStore(cfg Config) (*ConsentStore, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewConsentStoreWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewConsentStoreWithDB wraps an existing shared *sql.DB. The caller owns the
// connection lifecycle (shared-pool deployments).
func NewConsentStoreWithDB(db *sql.DB, dialect Dialect) (*ConsentStore, error) {
	if err := Run(context.Background(), db, "consent", consentMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate consent: %w", err)
	}
	return &ConsentStore{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool store built via
// NewConsentStoreWithDB should be closed by whoever owns the pool, not here —
// but Close is safe either way (database/sql Close is idempotent).
func (s *ConsentStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (s *ConsentStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *ConsentStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: consent store closed")
	}
	return s.db.PingContext(ctx)
}

// RecordConsent upserts a grant for (userID, clientID). An existing grant is
// replaced in full (scopes + granted_at + expires_at), atomically via ON CONFLICT.
func (s *ConsentStore) RecordConsent(ctx context.Context, grant core.ConsentGrant) error {
	scopesJSON, err := json.Marshal(grant.Scopes)
	if err != nil {
		return fmt.Errorf("postgres: marshal scopes: %w", err)
	}
	expiresAtNs := int64(0)
	if !grant.ExpiresAt.IsZero() {
		expiresAtNs = grant.ExpiresAt.UnixNano()
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO consent_grants (user_id, client_id, scopes, granted_at, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (user_id, client_id)
        DO UPDATE SET scopes = EXCLUDED.scopes, granted_at = EXCLUDED.granted_at, expires_at = EXCLUDED.expires_at`,
		grant.UserID, grant.ClientID, string(scopesJSON), grant.GrantedAt.UnixNano(), expiresAtNs,
	)
	if err != nil {
		return fmt.Errorf("postgres: upsert consent_grant: %w", err)
	}
	return nil
}

// GetConsent returns the grant for (userID, clientID), or ErrNoConsentGrant
// when none exists.
func (s *ConsentStore) GetConsent(ctx context.Context, userID, clientID string) (core.ConsentGrant, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT user_id, client_id, scopes, granted_at, expires_at
          FROM consent_grants WHERE user_id = $1 AND client_id = $2`,
		userID, clientID,
	)
	g, err := scanConsentGrant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return core.ConsentGrant{}, core.ErrNoConsentGrant
	}
	if err != nil {
		return core.ConsentGrant{}, fmt.Errorf("postgres: get consent_grant: %w", err)
	}
	// Expired grants are treated as not found.
	if g.IsExpired() {
		return core.ConsentGrant{}, core.ErrNoConsentGrant
	}
	return g, nil
}

// RevokeConsent removes the grant for (userID, clientID). Idempotent.
func (s *ConsentStore) RevokeConsent(ctx context.Context, userID, clientID string) error {
	_, err := s.db.ExecContext(ctx, `
        DELETE FROM consent_grants WHERE user_id = $1 AND client_id = $2`,
		userID, clientID,
	)
	if err != nil {
		return fmt.Errorf("postgres: delete consent_grant: %w", err)
	}
	return nil
}

// ListByUser returns all grants for userID in descending granted_at order.
// Returns an empty slice (not an error) when none exist.
func (s *ConsentStore) ListByUser(ctx context.Context, userID string) ([]core.ConsentGrant, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT user_id, client_id, scopes, granted_at, expires_at
          FROM consent_grants WHERE user_id = $1
          ORDER BY granted_at DESC`,
		userID,
	)
	if err != nil {
		return nil, fmt.Errorf("postgres: list consent_grants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []core.ConsentGrant
	for rows.Next() {
		g, err := scanConsentGrant(rows)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan consent_grant: %w", err)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows iter: %w", err)
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
		expiresAtNs int64
	)
	if err := s.Scan(&g.UserID, &g.ClientID, &scopesJSON, &grantedAtNs, &expiresAtNs); err != nil {
		return core.ConsentGrant{}, err
	}
	g.GrantedAt = time.Unix(0, grantedAtNs).UTC()
	if expiresAtNs != 0 {
		g.ExpiresAt = time.Unix(0, expiresAtNs).UTC()
	}
	if scopesJSON != "" && scopesJSON != "[]" {
		if err := json.Unmarshal([]byte(scopesJSON), &g.Scopes); err != nil {
			return core.ConsentGrant{}, fmt.Errorf("postgres: unmarshal scopes: %w", err)
		}
	}
	return g, nil
}

var _ core.ConsentStore = (*ConsentStore)(nil)
