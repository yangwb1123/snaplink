package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// --- Domains ---

func (s *TenantStore) GetDomain(ctx context.Context, hostname string) (*tenant.Domain, error) {
	host := normalizeHost(hostname)
	row := s.db.QueryRowContext(ctx, `
        SELECT tenant_id, default_client_id, is_apex, branding_json,
               created_at, updated_at
        FROM tenant_domains WHERE hostname = $1`, host)
	d, err := scanDomain(host, row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, tenant.ErrDomainNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("postgres: get domain: %w", err)
	}
	return d, nil
}

func (s *TenantStore) ListDomains(ctx context.Context) ([]*tenant.Domain, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT hostname, tenant_id, default_client_id, is_apex, branding_json,
               created_at, updated_at
        FROM tenant_domains ORDER BY hostname`)
	if err != nil {
		return nil, fmt.Errorf("postgres: list domains: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanDomainRows(rows)
}

func (s *TenantStore) ListDomainsByTenant(ctx context.Context, tenantID string) ([]*tenant.Domain, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT hostname, tenant_id, default_client_id, is_apex, branding_json,
               created_at, updated_at
        FROM tenant_domains WHERE tenant_id = $1 ORDER BY hostname`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list domains by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	return scanDomainRows(rows)
}

// PutDomain validates the referenced tenant + hostname-ownership invariant and
// then upserts the domain row. The verify-then-check-then-write sequence is a
// classic read-modify-write: run at plain READ COMMITTED (the default), two
// concurrent PutDomain calls claiming the SAME fresh hostname for DIFFERENT
// tenants would both read "unclaimed" from checkDomainConflict, then both
// commit their own single-statement INSERT ... ON CONFLICT DO UPDATE — the
// second silently overwrites the first's tenant_id with no error to either
// caller, breaking the exact hostname-ownership check this function exists to
// enforce (a cross-tenant domain hijack). Running the whole sequence inside one
// SERIALIZABLE transaction (runTx) closes the race: Postgres's SSI detects the
// read/write dependency between the two transactions' overlapping
// checkDomainConflict-read + insert-write and aborts one with 40001, which
// runTx retries — the retry re-runs checkDomainConflict against the winner's
// now-committed row and correctly returns ErrDomainExists instead of silently
// losing the update. See permissions_assignments.go for the identical pattern
// already applied to the RBAC read-modify-writes.
func (s *TenantStore) PutDomain(ctx context.Context, d *tenant.Domain) error {
	if err := d.Validate(); err != nil {
		return err
	}
	host := normalizeHost(d.Hostname)
	return runTx(ctx, s.db, serializable, func(tx *sql.Tx) error {
		if err := verifyTenantExists(ctx, tx, d.TenantID); err != nil {
			return err
		}
		if err := checkDomainConflict(ctx, tx, host, d.TenantID); err != nil {
			return err
		}
		now := time.Now().UTC().UnixNano()
		cols, err := encodeDomainColumns(d, now)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
        INSERT INTO tenant_domains (
            hostname, tenant_id, default_client_id, is_apex,
            branding_json, created_at, updated_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7)
        ON CONFLICT (hostname) DO UPDATE SET
            tenant_id = EXCLUDED.tenant_id,
            default_client_id = EXCLUDED.default_client_id,
            is_apex = EXCLUDED.is_apex,
            branding_json = EXCLUDED.branding_json,
            updated_at = EXCLUDED.updated_at`,
			host, d.TenantID, d.DefaultClientID, cols.isApex,
			cols.brandingJSON, cols.createdAt, now,
		)
		if err != nil {
			return fmt.Errorf("postgres: put domain: %w", err)
		}
		return nil
	})
}

// rowQuerier is the *sql.DB / *sql.Tx subset verifyTenantExists +
// checkDomainConflict need, so both can run inside PutDomain's transaction.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// verifyTenantExists confirms the referenced tenant row is present. Same
// semantics as the memory peer + matches what admin RPCs expect
// (ErrTenantNotFound, not a generic FK violation).
func verifyTenantExists(ctx context.Context, q rowQuerier, tenantID string) error {
	var exists int
	if err := q.QueryRowContext(ctx, `SELECT 1 FROM tenants WHERE id = $1`, tenantID).Scan(&exists); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return tenant.ErrTenantNotFound
		}
		return fmt.Errorf("postgres: verify tenant: %w", err)
	}
	return nil
}

// checkDomainConflict rejects a hostname already owned by a different tenant
// with ErrDomainExists. A hostname owned by the same tenant (or unclaimed)
// falls through to the upsert path.
func checkDomainConflict(ctx context.Context, q rowQuerier, host, tenantID string) error {
	row := q.QueryRowContext(ctx, `SELECT tenant_id FROM tenant_domains WHERE hostname = $1`, host)
	var existingTenantID string
	switch err := row.Scan(&existingTenantID); {
	case errors.Is(err, sql.ErrNoRows):
		// Fresh insert path.
	case err != nil:
		return fmt.Errorf("postgres: check domain conflict: %w", err)
	default:
		if existingTenantID != tenantID {
			return tenant.ErrDomainExists
		}
	}
	return nil
}

func (s *TenantStore) DeleteDomain(ctx context.Context, hostname string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM tenant_domains WHERE hostname = $1`, normalizeHost(hostname)); err != nil {
		return fmt.Errorf("postgres: delete domain: %w", err)
	}
	return nil
}
