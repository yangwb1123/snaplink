// Package sqlite is the SQLite-backed region.PolicyStore — the
// cluster-shared durable peer of region/memory. Residency policies are
// read-mostly (they change only when an operator re-pins a tenant), so a
// single table with tenant-id primary key suffices; every replica resolves
// the same policy against the same database.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/platform/migrate"

	_ "modernc.org/sqlite" // register the "sqlite" driver name (pure-Go, no CGO).
)

const regionPolicySchema = `
CREATE TABLE IF NOT EXISTS region_policies (
    tenant_id       TEXT    PRIMARY KEY,
    home_region     TEXT    NOT NULL DEFAULT '',
    allowed_regions TEXT    NOT NULL DEFAULT '[]',
    enforce_writes  INTEGER NOT NULL DEFAULT 0
);
`

var regionPolicyMigrations = []migrate.Migration{
	{Version: 1, Name: "baseline", SQL: regionPolicySchema},
}

// Store is the SQLite-backed region.PolicyStore. Caller owns Close().
type Store struct {
	db *sql.DB
}

// New opens dsn, migrates the schema, returns the store.
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: ping: %w", err)
	}
	db.SetMaxOpenConns(1) // WAL: one writer at a time prevents lock convoy
	if err := migrate.Run(context.Background(), db, "region_policy", regionPolicyMigrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("sqlite: migrate region_policies: %w", err)
	}
	return &Store{db: db}, nil
}

// Close releases the SQLite connection. Idempotent.
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	return err
}

// Set stores (or replaces) the policy for a tenant. Rejects invalid region
// IDs with region.ErrInvalidRegion, leaving stored state unchanged.
func (s *Store) Set(ctx context.Context, tenantID string, p region.ResidencyPolicy) error {
	if err := region.ValidatePolicy(p); err != nil {
		return err
	}
	allowed, err := json.Marshal(p.AllowedRegions)
	if err != nil {
		return fmt.Errorf("region policy: encode allowed_regions: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO region_policies (tenant_id, home_region, allowed_regions, enforce_writes)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(tenant_id) DO UPDATE SET
            home_region = excluded.home_region,
            allowed_regions = excluded.allowed_regions,
            enforce_writes = excluded.enforce_writes`,
		tenantID, string(p.HomeRegion), string(allowed), boolInt(p.EnforceWrites),
	)
	if err != nil {
		return fmt.Errorf("region policy: upsert: %w", err)
	}
	return nil
}

// Delete removes a tenant's policy; GetPolicy then returns the zero
// (unconstrained) policy. Idempotent.
func (s *Store) Delete(ctx context.Context, tenantID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM region_policies WHERE tenant_id = ?`, tenantID)
	if err != nil {
		return fmt.Errorf("region policy: delete: %w", err)
	}
	return nil
}

// GetPolicy returns the tenant's policy, or the zero (unconstrained) policy
// when absent — never an error.
func (s *Store) GetPolicy(ctx context.Context, tenantID string) (region.ResidencyPolicy, error) {
	var (
		home       string
		allowedRaw string
		enforce    int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT home_region, allowed_regions, enforce_writes FROM region_policies WHERE tenant_id = ?`,
		tenantID).Scan(&home, &allowedRaw, &enforce)
	if errors.Is(err, sql.ErrNoRows) {
		return region.ResidencyPolicy{}, nil
	}
	if err != nil {
		return region.ResidencyPolicy{}, fmt.Errorf("region policy: get: %w", err)
	}
	var allowed []region.ID
	if err := json.Unmarshal([]byte(allowedRaw), &allowed); err != nil {
		return region.ResidencyPolicy{}, fmt.Errorf("region policy: decode allowed_regions: %w", err)
	}
	return region.ResidencyPolicy{
		HomeRegion:     region.ID(home),
		AllowedRegions: allowed,
		EnforceWrites:  enforce != 0,
	}, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Compile-time interface check.
var _ region.PolicyStore = (*Store)(nil)
