package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/platform/migrate"
	"github.com/yangwb1123/snaplink/shared/core"
)

// invitationSchema is the org-invitation store (Postgres dialect): a
// server-issued opaque token bound to a tenant + recipient email + the org role
// to grant on accept, short-lived and single-use-on-accept (Consume = DELETE …
// RETURNING). The tenant_id index backs the admin roster view (ListByTenant).
// expires_at is Unix nanoseconds in a BIGINT (NOT timestamptz — preserves exact
// round-trip + oracle-resistant expiry, matching the SQLite peer).
const invitationSchema = `
CREATE TABLE IF NOT EXISTS invitations (
    token      TEXT   PRIMARY KEY,
    tenant_id  TEXT   NOT NULL,
    email      TEXT   NOT NULL,
    role       TEXT   NOT NULL,
    expires_at BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invitations_tenant_id
    ON invitations(tenant_id);
`

var invitationMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: invitationSchema},
}

// InvitationStore is the Postgres-backed implementation of
// [core.InvitationStore] — durable across restarts and safe for multi-replica
// (every replica issues + consumes against the same DB; the single-use
// DELETE…RETURNING is atomic).
type InvitationStore struct {
	db      *sql.DB
	dialect Dialect
}

// NewInvitationStore opens cfg.DSN, migrates the schema, and returns the store.
func NewInvitationStore(cfg Config) (*InvitationStore, error) {
	db, err := Open(cfg)
	if err != nil {
		return nil, err
	}
	s, err := NewInvitationStoreWithDB(db, cfg.Dialect)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// NewInvitationStoreWithDB wraps an existing shared *sql.DB. The caller owns the
// connection lifecycle (shared-pool deployments).
func NewInvitationStoreWithDB(db *sql.DB, dialect Dialect) (*InvitationStore, error) {
	if err := Run(context.Background(), db, "invitations", invitationMigrations, dialect); err != nil {
		return nil, fmt.Errorf("postgres: migrate invitations: %w", err)
	}
	return &InvitationStore{db: db, dialect: dialect.normalized()}, nil
}

// Close releases the connection. Idempotent. A shared-pool store built via
// NewInvitationStoreWithDB should be closed by whoever owns the pool, not here —
// but Close is safe either way (database/sql Close is idempotent).
func (s *InvitationStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for schema reporting (postgres.Status /
// CheckSchema). Nil after Close; callers MUST NOT close it.
func (s *InvitationStore) DB() *sql.DB { return s.db }

// Ping reports connection health for [sso.WithReadyCheck] wiring.
func (s *InvitationStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("postgres: invitation store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue stores an invitation. ON CONFLICT keeps it idempotent by token value
// (replaces the row in full, atomically).
func (s *InvitationStore) Issue(ctx context.Context, inv *core.Invitation) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO invitations (token, tenant_id, email, role, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (token)
        DO UPDATE SET tenant_id = EXCLUDED.tenant_id, email = EXCLUDED.email,
                      role = EXCLUDED.role, expires_at = EXCLUDED.expires_at`,
		inv.Token, inv.TenantID, inv.Email, string(inv.Role), inv.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("postgres: issue invitation: %w", err)
	}
	return nil
}

// Consume atomically deletes and returns the invitation. Missing/expired/
// already-consumed all return core.ErrInvitationNotFound (oracle-safe — the
// row is gone either way).
func (s *InvitationStore) Consume(ctx context.Context, token string) (*core.Invitation, error) {
	var tenantID, email, role string
	var expNanos int64
	err := s.db.QueryRowContext(ctx, `
        DELETE FROM invitations WHERE token = $1
        RETURNING tenant_id, email, role, expires_at`, token).
		Scan(&tenantID, &email, &role, &expNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: consume invitation: %w", err)
	}
	inv := &core.Invitation{
		Token:     token,
		TenantID:  tenantID,
		Email:     email,
		Role:      core.TenantRole(role),
		ExpiresAt: time.Unix(0, expNanos),
	}
	if inv.IsExpired() {
		return nil, core.ErrInvitationNotFound
	}
	return inv, nil
}

// ListByTenant returns all pending invitations for an org (admin roster view).
// Expired rows are returned too; the caller filters/flags them. Token material
// is read back so callers MUST NOT surface it (the json:"-" tag enforces this on
// the wire).
func (s *InvitationStore) ListByTenant(ctx context.Context, tenantID string) ([]*core.Invitation, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT token, email, role, expires_at FROM invitations WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list invitations by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*core.Invitation
	for rows.Next() {
		var token, email, role string
		var expNanos int64
		if err := rows.Scan(&token, &email, &role, &expNanos); err != nil {
			return nil, fmt.Errorf("postgres: scan invitation: %w", err)
		}
		out = append(out, &core.Invitation{
			Token:     token,
			TenantID:  tenantID,
			Email:     email,
			Role:      core.TenantRole(role),
			ExpiresAt: time.Unix(0, expNanos),
		})
	}
	return out, rows.Err()
}

// Revoke deletes every invitation for (tenantID, email). Idempotent — zero
// rows affected is success (no pending-invitation oracle).
func (s *InvitationStore) Revoke(ctx context.Context, tenantID, email string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM invitations WHERE tenant_id = $1 AND email = $2`, tenantID, email)
	if err != nil {
		return fmt.Errorf("postgres: revoke invitation: %w", err)
	}
	return nil
}

var _ core.InvitationStore = (*InvitationStore)(nil)
