package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// GetBranding reads the dedicated, independently versioned branding resource.
func (s *Store) GetBranding(ctx context.Context, tenantID string) (tenant.Branding, error) {
	var raw string
	var version uint64
	err := s.db.QueryRowContext(ctx, `
SELECT branding_json, version FROM tenant_branding WHERE tenant_id = ?`, tenantID).
		Scan(&raw, &version)
	if errors.Is(err, sql.ErrNoRows) {
		if err := verifyTenantExists(ctx, s.db, tenantID); err != nil {
			return tenant.Branding{}, err
		}
		return tenant.Branding{Values: map[string]string{}, Version: "0"}, nil
	}
	if err != nil {
		return tenant.Branding{}, fmt.Errorf("tenant/sqlite: get branding: %w", err)
	}
	values := map[string]string{}
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		return tenant.Branding{}, fmt.Errorf("tenant/sqlite: decode branding: %w", err)
	}
	return tenant.Branding{Values: values, Version: strconv.FormatUint(version, 10)}, nil
}

// PutBranding atomically compares and advances the branding version.
func (s *Store) PutBranding(
	ctx context.Context, tenantID string, values map[string]string, expectedVersion string,
) (tenant.Branding, error) {
	expected, err := strconv.ParseUint(expectedVersion, 10, 64)
	if err != nil {
		return tenant.Branding{}, tenant.ErrBrandingPrecondition
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return tenant.Branding{}, fmt.Errorf("tenant/sqlite: encode branding: %w", err)
	}
	if err := verifyTenantExists(ctx, s.db, tenantID); err != nil {
		return tenant.Branding{}, err
	}
	result, err := s.writeBranding(ctx, tenantID, raw, expected)
	if err != nil {
		return tenant.Branding{}, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return tenant.Branding{}, fmt.Errorf("tenant/sqlite: branding rows affected: %w", err)
	}
	if affected != 1 {
		return tenant.Branding{}, tenant.ErrBrandingPrecondition
	}
	return s.GetBranding(ctx, tenantID)
}

func (s *Store) writeBranding(
	ctx context.Context, tenantID string, raw []byte, expected uint64,
) (sql.Result, error) {
	now := time.Now().UTC().UnixNano()
	if expected == 0 {
		return s.db.ExecContext(ctx, `
INSERT INTO tenant_branding (tenant_id, branding_json, version, updated_at)
VALUES (?, ?, 1, ?) ON CONFLICT(tenant_id) DO NOTHING`, tenantID, string(raw), now)
	}
	return s.db.ExecContext(ctx, `
UPDATE tenant_branding
SET branding_json = ?, version = version + 1, updated_at = ?
WHERE tenant_id = ? AND version = ?`, string(raw), now, tenantID, expected)
}
