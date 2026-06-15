package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/snaplink/sso/core"
)

// tenantMembershipsSchema is the B2B org-membership store: an explicit
// (tenant, user) edge with an org-level role, independent of SCIM groups. The
// composite PRIMARY KEY makes the pair the edge identity so Add can upsert via
// ON CONFLICT; the user_id index serves ListByUser (a user's orgs) without a
// table scan.
const tenantMembershipsSchema = `
CREATE TABLE IF NOT EXISTS tenant_memberships (
    tenant_id  TEXT    NOT NULL,
    user_id    TEXT    NOT NULL,
    role       TEXT    NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_tenant_memberships_user_id
    ON tenant_memberships(user_id);
`

// TenantUserStore is the SQLite-backed core.TenantUserStore — durable across
// restarts and safe for multi-replica (every replica reads/writes the same DB;
// Add is an atomic upsert).
type TenantUserStore struct {
	db *sql.DB
}

// NewTenantUserStore opens dsn, migrates the schema, and returns the store.
func NewTenantUserStore(dsn string) (*TenantUserStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := ensureSchema(db, "tenant_memberships", tenantMembershipsSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate tenant_memberships: %w", err)
	}
	return &TenantUserStore{db: db}, nil
}

// NewTenantUserStoreWithDB wraps an existing *sql.DB (shared-pool deployments).
func NewTenantUserStoreWithDB(db *sql.DB) (*TenantUserStore, error) {
	if err := ensureSchema(db, "tenant_memberships", tenantMembershipsSchema); err != nil {
		return nil, fmt.Errorf("sqlite: migrate tenant_memberships: %w", err)
	}
	return &TenantUserStore{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *TenantUserStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// DB exposes the underlying *sql.DB for the storage-health schema reporter.
func (s *TenantUserStore) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for /readyz wiring.
func (s *TenantUserStore) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("sqlite: tenant user store closed")
	}
	return s.db.PingContext(ctx)
}

// Add upserts the membership on (tenant_id, user_id): a re-add updates the role
// (and refreshes created_at) rather than inserting a duplicate edge.
func (s *TenantUserStore) Add(ctx context.Context, m *core.TenantMembership) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO tenant_memberships (tenant_id, user_id, role, created_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(tenant_id, user_id) DO UPDATE SET
            role = excluded.role,
            created_at = excluded.created_at`,
		m.TenantID, m.UserID, string(m.Role), m.CreatedAt.UnixNano())
	if err != nil {
		return fmt.Errorf("sqlite: add tenant_membership: %w", err)
	}
	return nil
}

// Remove deletes the (tenant, user) membership. Idempotent — a missing edge is
// not an error.
func (s *TenantUserStore) Remove(ctx context.Context, tenantID, userID string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM tenant_memberships WHERE tenant_id = ? AND user_id = ?`,
		tenantID, userID)
	if err != nil {
		return fmt.Errorf("sqlite: remove tenant_membership: %w", err)
	}
	return nil
}

// Get returns the membership for (tenant, user) or core.ErrNoMembership.
func (s *TenantUserStore) Get(ctx context.Context, tenantID, userID string) (*core.TenantMembership, error) {
	var role string
	var createdNanos int64
	err := s.db.QueryRowContext(ctx, `
        SELECT role, created_at FROM tenant_memberships
        WHERE tenant_id = ? AND user_id = ?`, tenantID, userID).
		Scan(&role, &createdNanos)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, core.ErrNoMembership
	}
	if err != nil {
		return nil, fmt.Errorf("sqlite: get tenant_membership: %w", err)
	}
	return &core.TenantMembership{
		TenantID:  tenantID,
		UserID:    userID,
		Role:      core.TenantRole(role),
		CreatedAt: time.Unix(0, createdNanos),
	}, nil
}

// ListByTenant returns the org roster for tenantID.
func (s *TenantUserStore) ListByTenant(ctx context.Context, tenantID string) ([]*core.TenantMembership, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT user_id, role, created_at FROM tenant_memberships
        WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list tenant_memberships by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*core.TenantMembership
	for rows.Next() {
		var userID, role string
		var createdNanos int64
		if err := rows.Scan(&userID, &role, &createdNanos); err != nil {
			return nil, fmt.Errorf("sqlite: scan tenant_membership: %w", err)
		}
		out = append(out, &core.TenantMembership{
			TenantID:  tenantID,
			UserID:    userID,
			Role:      core.TenantRole(role),
			CreatedAt: time.Unix(0, createdNanos),
		})
	}
	return out, rows.Err()
}

// ListByUser returns every org the user belongs to (served by the user_id index).
func (s *TenantUserStore) ListByUser(ctx context.Context, userID string) ([]*core.TenantMembership, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT tenant_id, role, created_at FROM tenant_memberships
        WHERE user_id = ?`, userID)
	if err != nil {
		return nil, fmt.Errorf("sqlite: list tenant_memberships by user: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*core.TenantMembership
	for rows.Next() {
		var tenantID, role string
		var createdNanos int64
		if err := rows.Scan(&tenantID, &role, &createdNanos); err != nil {
			return nil, fmt.Errorf("sqlite: scan tenant_membership: %w", err)
		}
		out = append(out, &core.TenantMembership{
			TenantID:  tenantID,
			UserID:    userID,
			Role:      core.TenantRole(role),
			CreatedAt: time.Unix(0, createdNanos),
		})
	}
	return out, rows.Err()
}

var _ core.TenantUserStore = (*TenantUserStore)(nil)
