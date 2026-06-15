package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
)

// invitationSchema is the org-invitation store: a server-issued opaque token
// bound to a tenant + recipient email + the org role to grant on accept,
// short-lived and single-use-on-accept (Consume = DELETE … RETURNING). The
// tenant_id index backs the admin roster view (ListByTenant).
const invitationSchema = `
CREATE TABLE IF NOT EXISTS invitations (
    token      TEXT    PRIMARY KEY,
    tenant_id  TEXT    NOT NULL,
    email      TEXT    NOT NULL,
    role       TEXT    NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_invitations_tenant_id
    ON invitations(tenant_id);
`

// InvitationStore is the SQLite-backed core.InvitationStore — durable across
// restarts and safe for multi-replica (every replica issues + consumes against
// the same DB; the single-use DELETE…RETURNING is atomic).
type InvitationStore struct {
	db *sql.DB
}

// NewInvitationStore opens dsn, migrates the schema, and returns the store.
func NewInvitationStore(dsn string) (*InvitationStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "invitations", invitationSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate invitations: %w", err)
	}
	return &InvitationStore{db: db}, nil
}

// NewInvitationStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewInvitationStoreWithDB(db *sql.DB) (*InvitationStore, error) {
	if err := ensureSchema(db, "invitations", invitationSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate invitations: %w", err)
	}
	return &InvitationStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *InvitationStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *InvitationStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for /readyz wiring.
func (s *InvitationStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: invitation store closed")
	}
	return s.db.PingContext(ctx)
}

// Issue stores an invitation. INSERT OR REPLACE keeps it idempotent by token value.
func (s *InvitationStore) Issue(ctx context.Context, inv *core.Invitation) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT OR REPLACE INTO invitations (token, tenant_id, email, role, expires_at)
        VALUES (?, ?, ?, ?, ?)`,
		inv.Token, inv.TenantID, inv.Email, string(inv.Role), inv.ExpiresAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: issue invitation: %w", err)
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
        DELETE FROM invitations WHERE token = ?
        RETURNING tenant_id, email, role, expires_at`, token).
		Scan(&tenantID, &email, &role, &expNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrInvitationNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: consume invitation: %w", err)
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
		`SELECT token, email, role, expires_at FROM invitations WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list invitations by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*core.Invitation
	for rows.Next() {
		var token, email, role string
		var expNanos int64
		if err := rows.Scan(&token, &email, &role, &expNanos); err != nil {
			return nil, fmt.Errorf("sqlite: scan invitation: %w", err)
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

var _ core.InvitationStore = (*InvitationStore)(nil)
