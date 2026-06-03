// Package sqlite is a SQLite-backed [tenant.Store] for multi-replica
// deployments. The in-memory peer loses state on restart and forks
// per-replica; this peer shares Tenants + Domains across the cluster
// so admin SetTenantStatus on replica A surfaces on every replica
// (after the tenant-suspension cache TTL elapses + the operator
// triggers invalidation via Server.InvalidateTenantSuspensionCache).
//
// Pure-Go via modernc.org/sqlite — no CGO. Two tables: tenants
// (keyed by id, plus a UNIQUE index on slug) and domains (keyed by
// hostname). Settings + Branding map[string]string columns are
// JSON-encoded; we never query into them, so full-row reads suffice.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/snaplink/sso/migrate"
	"github.com/snaplink/sso/tenant"

	_ "modernc.org/sqlite"
)

// migrations is the ordered schema history. v1 is the baseline (schema
// as shipped before versioned migrations); pre-migration DBs no-op it
// and get stamped v1.
var migrations = []migrate.Migration{
	{Version: 1, Name: "baseline_tenants", SQL: schema},
	// v2 pins data-residency on a tenant. Forward-only ALTER ADD COLUMN
	// with NOT NULL DEFAULT so existing rows backfill to the unconstrained
	// zero value ('' / '[]') — byte-compatible with pre-residency tenants.
	// A v1-populated DB applies this once and stamps v2; a fresh DB gets it
	// in the same run after the baseline.
	{Version: 2, Name: "tenant_residency_regions", SQL: `
ALTER TABLE tenants ADD COLUMN home_region TEXT NOT NULL DEFAULT '';
ALTER TABLE tenants ADD COLUMN allowed_regions_json TEXT NOT NULL DEFAULT '[]';
`},
}

const schema = `
CREATE TABLE IF NOT EXISTS tenants (
    id            TEXT    PRIMARY KEY,
    slug          TEXT    NOT NULL UNIQUE,
    name          TEXT    NOT NULL DEFAULT '',
    status        TEXT    NOT NULL DEFAULT 'active',
    settings_json TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_domains (
    hostname          TEXT    PRIMARY KEY,
    tenant_id         TEXT    NOT NULL,
    default_client_id TEXT    NOT NULL DEFAULT '',
    is_apex           INTEGER NOT NULL DEFAULT 0,
    branding_json     TEXT    NOT NULL DEFAULT '',
    created_at        INTEGER NOT NULL,
    updated_at        INTEGER NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_tenant_domains_tenant_id
    ON tenant_domains(tenant_id);
`

// Store is the SQLite-backed [tenant.Store]. Concurrent readers safe;
// writes serialized via SQLite's single-writer lock.
type Store struct {
	db *sql.DB
}

// New opens dsn, migrates the schema, returns the store. FOREIGN KEYS
// pragma enabled so DeleteTenant cascades to tenant_domains.
func New(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("tenant/sqlite: open: %w", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tenant/sqlite: ping: %w", err)
	}
	if _, err := db.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tenant/sqlite: enable foreign keys: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "tenant", migrations); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("tenant/sqlite: migrate: %w", err)
	}
	return &Store{db: db}, nil
}

// NewWithDB wraps an existing *sql.DB. Caller owns the connection
// lifecycle. Note: PRAGMA foreign_keys is per-connection; callers
// using NewWithDB MUST set it themselves on every connection in
// the pool, OR rely on connection-string pragma settings.
func NewWithDB(db *sql.DB) (*Store, error) {
	if _, err := db.ExecContext(context.Background(), `PRAGMA foreign_keys = ON`); err != nil {
		return nil, fmt.Errorf("tenant/sqlite: enable foreign keys: %w", err)
	}
	if err := migrate.Run(context.Background(), db, "tenant", migrations); err != nil {
		return nil, fmt.Errorf("tenant/sqlite: migrate: %w", err)
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

// DB exposes the underlying *sql.DB for an operator-facing schema
// reporter (sso.WithStorageHealth via migrate.Status). Nil after Close;
// callers MUST NOT close it.
func (s *Store) DB() *sql.DB { return s.db }

// Ping reports SQLite connection health for [sso.WithReadyCheck].
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("tenant/sqlite: closed")
	}
	return s.db.PingContext(ctx)
}

// --- Tenants ---

func (s *Store) GetTenant(ctx context.Context, id string) (*tenant.Tenant, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT slug, name, status, settings_json, home_region, allowed_regions_json, created_at, updated_at
        FROM tenants WHERE id = ?`, id)
	t, err := scanTenant(id, row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrTenantNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("tenant/sqlite: get tenant: %w", err)
	}
	return t, nil
}

func (s *Store) ListTenants(ctx context.Context) ([]*tenant.Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, slug, name, status, settings_json, home_region, allowed_regions_json, created_at, updated_at
        FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("tenant/sqlite: list tenants: %w", err)
	}
	defer rows.Close()
	var out []*tenant.Tenant
	for rows.Next() {
		var id string
		var slug, name, status, settingsJSON, homeRegion, allowedRegionsJSON string
		var createdNs, updatedNs int64
		if err := rows.Scan(&id, &slug, &name, &status, &settingsJSON, &homeRegion, &allowedRegionsJSON, &createdNs, &updatedNs); err != nil {
			return nil, fmt.Errorf("tenant/sqlite: scan tenant: %w", err)
		}
		t := &tenant.Tenant{
			ID:         id,
			Slug:       slug,
			Name:       name,
			Status:     tenant.Status(status),
			HomeRegion: homeRegion,
			CreatedAt:  time.Unix(0, createdNs).UTC(),
			UpdatedAt:  time.Unix(0, updatedNs).UTC(),
		}
		if settingsJSON != "" {
			if err := json.Unmarshal([]byte(settingsJSON), &t.Settings); err != nil {
				return nil, fmt.Errorf("tenant/sqlite: unmarshal settings: %w", err)
			}
		}
		if err := unmarshalRegions(allowedRegionsJSON, &t.AllowedRegions); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenant/sqlite: rows: %w", err)
	}
	if out == nil {
		out = []*tenant.Tenant{}
	}
	return out, nil
}

func (s *Store) PutTenant(ctx context.Context, t *tenant.Tenant) error {
	if err := t.Validate(); err != nil {
		return err
	}
	now := time.Now().UTC().UnixNano()

	settingsJSON := ""
	if len(t.Settings) > 0 {
		raw, err := json.Marshal(t.Settings)
		if err != nil {
			return fmt.Errorf("tenant/sqlite: marshal settings: %w", err)
		}
		settingsJSON = string(raw)
	}

	allowedRegionsJSON, err := marshalRegions(t.AllowedRegions)
	if err != nil {
		return err
	}

	createdAt := now
	if !t.CreatedAt.IsZero() {
		createdAt = t.CreatedAt.UnixNano()
	}
	// UPSERT: on conflict by id, preserve CREATED_AT (matches the
	// memory peer's behavior — operator updates don't reset the
	// creation timestamp).
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO tenants (id, slug, name, status, settings_json, home_region, allowed_regions_json, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            slug = excluded.slug,
            name = excluded.name,
            status = excluded.status,
            settings_json = excluded.settings_json,
            home_region = excluded.home_region,
            allowed_regions_json = excluded.allowed_regions_json,
            updated_at = excluded.updated_at`,
		t.ID, t.Slug, t.Name, string(t.Status), settingsJSON, t.HomeRegion, allowedRegionsJSON, createdAt, now,
	)
	if err != nil {
		// Slug collisions surface as UNIQUE constraint violations;
		// admin RPCs map them to ErrTenantExists (matches the memory
		// peer's contract — different tenants can't share a slug).
		if strings.Contains(err.Error(), "UNIQUE") && strings.Contains(err.Error(), "slug") {
			return tenant.ErrTenantExists
		}
		return fmt.Errorf("tenant/sqlite: put tenant: %w", err)
	}
	return nil
}

func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	// FOREIGN KEY ON DELETE CASCADE handles the tenant_domains side
	// — same orphan-prevention the memory peer enforces inline.
	_, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("tenant/sqlite: delete tenant: %w", err)
	}
	return nil
}

// --- Domains ---

func (s *Store) GetDomain(ctx context.Context, hostname string) (*tenant.Domain, error) {
	host := normalizeHost(hostname)
	row := s.db.QueryRowContext(ctx, `
        SELECT tenant_id, default_client_id, is_apex, branding_json,
               created_at, updated_at
        FROM tenant_domains WHERE hostname = ?`, host)
	d, err := scanDomain(host, row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrDomainNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("tenant/sqlite: get domain: %w", err)
	}
	return d, nil
}

func (s *Store) ListDomains(ctx context.Context) ([]*tenant.Domain, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT hostname, tenant_id, default_client_id, is_apex, branding_json,
               created_at, updated_at
        FROM tenant_domains ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("tenant/sqlite: list domains: %w", err)
	}
	defer rows.Close()
	return scanDomainRows(rows)
}

func (s *Store) ListDomainsByTenant(ctx context.Context, tenantID string) ([]*tenant.Domain, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT hostname, tenant_id, default_client_id, is_apex, branding_json,
               created_at, updated_at
        FROM tenant_domains WHERE tenant_id = ? ORDER BY hostname`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant/sqlite: list domains by tenant: %w", err)
	}
	defer rows.Close()
	return scanDomainRows(rows)
}

func (s *Store) PutDomain(ctx context.Context, d *tenant.Domain) error {
	if err := d.Validate(); err != nil {
		return err
	}
	// Verify the referenced tenant exists. Same semantics as the
	// memory peer + matches what admin RPCs expect (ErrTenantNotFound,
	// not a generic FK violation).
	var exists int
	if err := s.db.QueryRowContext(ctx, `SELECT 1 FROM tenants WHERE id = ?`, d.TenantID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tenant.ErrTenantNotFound
		}
		return fmt.Errorf("tenant/sqlite: verify tenant: %w", err)
	}

	host := normalizeHost(d.Hostname)
	now := time.Now().UTC().UnixNano()
	createdAt := now
	if !d.CreatedAt.IsZero() {
		createdAt = d.CreatedAt.UnixNano()
	}

	// Hostname collisions across tenants → ErrDomainExists. Same
	// tenant updating its own hostname → upsert.
	row := s.db.QueryRowContext(ctx, `SELECT tenant_id FROM tenant_domains WHERE hostname = ?`, host)
	var existingTenantID string
	switch err := row.Scan(&existingTenantID); {
	case errors.Is(err, sql.ErrNoRows):
		// Fresh insert path.
	case err != nil:
		return fmt.Errorf("tenant/sqlite: check domain conflict: %w", err)
	default:
		if existingTenantID != d.TenantID {
			return tenant.ErrDomainExists
		}
	}

	brandingJSON := ""
	if len(d.Branding) > 0 {
		raw, err := json.Marshal(d.Branding)
		if err != nil {
			return fmt.Errorf("tenant/sqlite: marshal branding: %w", err)
		}
		brandingJSON = string(raw)
	}

	isApex := 0
	if d.IsApex {
		isApex = 1
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO tenant_domains (
            hostname, tenant_id, default_client_id, is_apex,
            branding_json, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            tenant_id = excluded.tenant_id,
            default_client_id = excluded.default_client_id,
            is_apex = excluded.is_apex,
            branding_json = excluded.branding_json,
            updated_at = excluded.updated_at`,
		host, d.TenantID, d.DefaultClientID, isApex,
		brandingJSON, createdAt, now,
	)
	if err != nil {
		return fmt.Errorf("tenant/sqlite: put domain: %w", err)
	}
	return nil
}

func (s *Store) DeleteDomain(ctx context.Context, hostname string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM tenant_domains WHERE hostname = ?`, normalizeHost(hostname))
	if err != nil {
		return fmt.Errorf("tenant/sqlite: delete domain: %w", err)
	}
	return nil
}

// --- helpers ---

func scanTenant(id string, row interface{ Scan(...any) error }) (*tenant.Tenant, error) {
	var slug, name, status, settingsJSON, homeRegion, allowedRegionsJSON string
	var createdNs, updatedNs int64
	if err := row.Scan(&slug, &name, &status, &settingsJSON, &homeRegion, &allowedRegionsJSON, &createdNs, &updatedNs); err != nil {
		return nil, err
	}
	t := &tenant.Tenant{
		ID:         id,
		Slug:       slug,
		Name:       name,
		Status:     tenant.Status(status),
		HomeRegion: homeRegion,
		CreatedAt:  time.Unix(0, createdNs).UTC(),
		UpdatedAt:  time.Unix(0, updatedNs).UTC(),
	}
	if settingsJSON != "" {
		if err := json.Unmarshal([]byte(settingsJSON), &t.Settings); err != nil {
			return nil, fmt.Errorf("tenant/sqlite: unmarshal settings: %w", err)
		}
	}
	if err := unmarshalRegions(allowedRegionsJSON, &t.AllowedRegions); err != nil {
		return nil, err
	}
	return t, nil
}

// unmarshalRegions decodes the allowed_regions_json TEXT column into a
// []string. The column's NOT NULL DEFAULT '[]' means a backfilled v1 row
// decodes to an empty non-nil slice; we normalize that back to nil so a
// round-trip of an unconstrained tenant stays the zero value (matches the
// settings_json "" -> nil map handling).
func unmarshalRegions(raw string, dst *[]string) error {
	if raw == "" || raw == "[]" {
		*dst = nil
		return nil
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return fmt.Errorf("tenant/sqlite: unmarshal allowed_regions: %w", err)
	}
	if len(*dst) == 0 {
		*dst = nil
	}
	return nil
}

// marshalRegions encodes AllowedRegions for the allowed_regions_json
// column. Nil/empty marshals to '[]' so the column's NOT NULL invariant
// holds (mirrors the column DEFAULT).
func marshalRegions(regions []string) (string, error) {
	if len(regions) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(regions)
	if err != nil {
		return "", fmt.Errorf("tenant/sqlite: marshal allowed_regions: %w", err)
	}
	return string(raw), nil
}

func scanDomain(host string, row interface{ Scan(...any) error }) (*tenant.Domain, error) {
	var tenantID, defaultClientID, brandingJSON string
	var isApexInt int
	var createdNs, updatedNs int64
	if err := row.Scan(&tenantID, &defaultClientID, &isApexInt, &brandingJSON, &createdNs, &updatedNs); err != nil {
		return nil, err
	}
	d := &tenant.Domain{
		Hostname:        host,
		TenantID:        tenantID,
		DefaultClientID: defaultClientID,
		IsApex:          isApexInt == 1,
		CreatedAt:       time.Unix(0, createdNs).UTC(),
		UpdatedAt:       time.Unix(0, updatedNs).UTC(),
	}
	if brandingJSON != "" {
		if err := json.Unmarshal([]byte(brandingJSON), &d.Branding); err != nil {
			return nil, fmt.Errorf("tenant/sqlite: unmarshal branding: %w", err)
		}
	}
	return d, nil
}

func scanDomainRows(rows *sql.Rows) ([]*tenant.Domain, error) {
	var out []*tenant.Domain
	for rows.Next() {
		var host, tenantID, defaultClientID, brandingJSON string
		var isApexInt int
		var createdNs, updatedNs int64
		if err := rows.Scan(&host, &tenantID, &defaultClientID, &isApexInt, &brandingJSON, &createdNs, &updatedNs); err != nil {
			return nil, fmt.Errorf("tenant/sqlite: scan domain: %w", err)
		}
		d := &tenant.Domain{
			Hostname:        host,
			TenantID:        tenantID,
			DefaultClientID: defaultClientID,
			IsApex:          isApexInt == 1,
			CreatedAt:       time.Unix(0, createdNs).UTC(),
			UpdatedAt:       time.Unix(0, updatedNs).UTC(),
		}
		if brandingJSON != "" {
			if err := json.Unmarshal([]byte(brandingJSON), &d.Branding); err != nil {
				return nil, fmt.Errorf("tenant/sqlite: unmarshal branding: %w", err)
			}
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("tenant/sqlite: rows: %w", err)
	}
	if out == nil {
		out = []*tenant.Domain{}
	}
	// Sort for deterministic order (LIST callers + tests rely on it).
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

// normalizeHost mirrors the memory peer's RFC-1035 hostname
// normalization (case-insensitive + strip trailing dot) so the
// two backends agree on equivalence classes.
func normalizeHost(h string) string {
	if len(h) > 0 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
	}
	return strings.ToLower(h)
}

// Compile-time interface assertion.
var _ tenant.Store = (*Store)(nil)
