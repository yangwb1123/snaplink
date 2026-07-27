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
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/migrate"

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
	// v3 adds the EnforceWrites residency toggle. INTEGER 0/1 (SQLite has no
	// native bool) with NOT NULL DEFAULT 0 so existing rows backfill to the
	// fail-open zero value (false) — byte-compatible with v2 tenants. A
	// v2-populated DB applies this once and stamps v3; a fresh DB gets it in
	// the same run after the baseline + v2.
	{Version: 3, Name: "tenant_residency_enforce_writes", SQL: `
ALTER TABLE tenants ADD COLUMN enforce_writes INTEGER NOT NULL DEFAULT 0;
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
        SELECT slug, name, status, settings_json, home_region, allowed_regions_json, enforce_writes, created_at, updated_at
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
        SELECT id, slug, name, status, settings_json, home_region, allowed_regions_json, enforce_writes, created_at, updated_at
        FROM tenants ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("tenant/sqlite: list tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*tenant.Tenant
	for rows.Next() {
		var id string
		var slug, name, status, settingsJSON, homeRegion, allowedRegionsJSON string
		var enforceWrites int
		var createdNs, updatedNs int64
		if err := rows.Scan(&id, &slug, &name, &status, &settingsJSON, &homeRegion, &allowedRegionsJSON, &enforceWrites, &createdNs, &updatedNs); err != nil {
			return nil, fmt.Errorf("tenant/sqlite: scan tenant: %w", err)
		}
		t := &tenant.Tenant{
			ID:            id,
			Slug:          slug,
			Name:          name,
			Status:        tenant.Status(status),
			HomeRegion:    homeRegion,
			EnforceWrites: enforceWrites == 1,
			CreatedAt:     time.Unix(0, createdNs).UTC(),
			UpdatedAt:     time.Unix(0, updatedNs).UTC(),
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
	cols, err := encodeTenantColumns(t, now)
	if err != nil {
		return err
	}
	// UPSERT: on conflict by id, preserve CREATED_AT (matches the
	// memory peer's behavior — operator updates don't reset the
	// creation timestamp).
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO tenants (id, slug, name, status, settings_json, home_region, allowed_regions_json, enforce_writes, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            slug = excluded.slug,
            name = excluded.name,
            status = excluded.status,
            settings_json = excluded.settings_json,
            home_region = excluded.home_region,
            allowed_regions_json = excluded.allowed_regions_json,
            enforce_writes = excluded.enforce_writes,
            updated_at = excluded.updated_at`,
		t.ID, t.Slug, t.Name, string(t.Status), cols.settingsJSON, t.HomeRegion, cols.allowedRegionsJSON, cols.enforceWrites, cols.createdAt, now,
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
	defer func() { _ = rows.Close() }()
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
	defer func() { _ = rows.Close() }()
	return scanDomainRows(rows)
}

// domainClaimBusyTimeoutMS bounds how long PutDomain's pinned connection
// waits for the write lock when a concurrent PutDomain already holds it,
// rather than failing SQLITE_BUSY immediately — modernc.org/sqlite's
// per-connection busy_timeout default is 0 (see
// infrastructure/defaultimpl/sqlite/busy_timeout.go for the identical
// rationale). Long enough to ride out a brief concurrent hostname-claim
// convoy, short enough that a genuinely stuck lock still errors instead of
// hanging the admin request.
const domainClaimBusyTimeoutMS = 5000

// rowQuerier is the *sql.DB / *sql.Conn subset verifyTenantExists +
// checkDomainConflict need, so both can run over PutDomain's pinned,
// BEGIN IMMEDIATE-protected connection.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// PutDomain validates the referenced tenant + hostname-ownership invariant
// and then upserts the domain row. The verify-then-check-then-write sequence
// is a classic read-modify-write: run as three independent auto-commit
// statements (the pre-fix shape), two concurrent PutDomain calls claiming the
// SAME fresh hostname for DIFFERENT tenants could both read "unclaimed" from
// checkDomainConflict before either's INSERT ... ON CONFLICT DO UPDATE
// landed — the second silently overwrote the first tenant's tenant_id with
// NO error to either caller, defeating the exact hostname-ownership check
// this function exists to enforce (a cross-tenant domain hijack; mirrors the
// fix required in the Postgres peer's PutDomain). A REAL BEGIN IMMEDIATE on a
// pinned connection acquires the write lock BEFORE either SELECT runs, so a
// second concurrent claim blocks (up to domainClaimBusyTimeoutMS) until the
// first commits, then re-reads the now-committed row and correctly loses via
// ErrDomainExists instead of silently clobbering it. Plain db.BeginTx does
// NOT achieve this under modernc.org/sqlite — the driver has no SQL
// isolation-level concept and silently starts a plain DEFERRED transaction
// regardless of the requested level, leaving the same lost-update race
// window open (see infrastructure/defaultimpl/sqlite/busy_timeout.go).
func (s *Store) PutDomain(ctx context.Context, d *tenant.Domain) error {
	if err := d.Validate(); err != nil {
		return err
	}
	host := normalizeHost(d.Hostname)
	now := time.Now().UTC().UnixNano()
	cols, err := encodeDomainColumns(d, now)
	if err != nil {
		return err
	}

	conn, err := beginImmediateConn(ctx, s.db)
	if err != nil {
		return fmt.Errorf("tenant/sqlite: put domain: %w", err)
	}
	defer func() { _ = conn.Close() }()
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
	}()

	if err := putDomainTx(ctx, conn, d, host, cols, now); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return fmt.Errorf("tenant/sqlite: put domain: commit: %w", err)
	}
	committed = true
	return nil
}

// beginImmediateConn pins a connection from db's pool, bounds its busy wait
// with domainClaimBusyTimeoutMS, and issues a REAL BEGIN IMMEDIATE — the
// write lock is acquired up front, not lazily on the first write statement.
// The caller owns the returned *sql.Conn (MUST Close it) and the open
// transaction (MUST COMMIT or ROLLBACK before Close).
func beginImmediateConn(ctx context.Context, db *sql.DB) (*sql.Conn, error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire conn: %w", err)
	}
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout=%d", domainClaimBusyTimeoutMS)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("busy_timeout: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("begin: %w", err)
	}
	return conn, nil
}

// putDomainTx runs the verify-tenant + conflict-check + upsert sequence over
// conn — already inside the caller's BEGIN IMMEDIATE transaction, so the
// whole read-modify-write is atomic against a concurrent PutDomain racing
// the same hostname.
func putDomainTx(ctx context.Context, conn *sql.Conn, d *tenant.Domain, host string, cols domainColumns, now int64) error {
	if err := verifyTenantExists(ctx, conn, d.TenantID); err != nil {
		return err
	}
	if err := checkDomainConflict(ctx, conn, host, d.TenantID); err != nil {
		return err
	}
	_, err := conn.ExecContext(ctx, `
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
		host, d.TenantID, d.DefaultClientID, cols.isApex,
		cols.brandingJSON, cols.createdAt, now,
	)
	if err != nil {
		return fmt.Errorf("tenant/sqlite: put domain: %w", err)
	}
	return nil
}

// verifyTenantExists confirms the referenced tenant row is present. Same
// semantics as the memory peer + matches what admin RPCs expect
// (ErrTenantNotFound, not a generic FK violation). Takes an explicit querier
// so PutDomain can run it over its pinned BEGIN IMMEDIATE connection.
func verifyTenantExists(ctx context.Context, q rowQuerier, tenantID string) error {
	var exists int
	if err := q.QueryRowContext(ctx, `SELECT 1 FROM tenants WHERE id = ?`, tenantID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tenant.ErrTenantNotFound
		}
		return fmt.Errorf("tenant/sqlite: verify tenant: %w", err)
	}
	return nil
}

// checkDomainConflict rejects a hostname already owned by a different tenant
// with ErrDomainExists. A hostname owned by the same tenant (or unclaimed)
// falls through to the upsert path. Takes an explicit querier so PutDomain
// can run it over its pinned BEGIN IMMEDIATE connection.
func checkDomainConflict(ctx context.Context, q rowQuerier, host, tenantID string) error {
	row := q.QueryRowContext(ctx, `SELECT tenant_id FROM tenant_domains WHERE hostname = ?`, host)
	var existingTenantID string
	switch err := row.Scan(&existingTenantID); {
	case errors.Is(err, sql.ErrNoRows):
		// Fresh insert path.
	case err != nil:
		return fmt.Errorf("tenant/sqlite: check domain conflict: %w", err)
	default:
		if existingTenantID != tenantID {
			return tenant.ErrDomainExists
		}
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

// Compile-time interface assertion.
var _ tenant.Store = (*Store)(nil)
