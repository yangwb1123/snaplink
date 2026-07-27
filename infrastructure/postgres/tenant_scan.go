package postgres

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// scanTenant decodes a single tenant row (GetTenant projection: id supplied
// by the caller, the remaining columns scanned). Booleans arrive as INTEGER
// (int64) and timestamps as BIGINT nanoseconds.
func scanTenant(id string, row scanner) (*tenant.Tenant, error) {
	var slug, name, status, settingsJSON, homeRegion, allowedRegionsJSON string
	var enforceWrites int64
	var createdNs, updatedNs int64
	if err := row.Scan(&slug, &name, &status, &settingsJSON, &homeRegion, &allowedRegionsJSON, &enforceWrites, &createdNs, &updatedNs); err != nil {
		return nil, err
	}
	t := &tenant.Tenant{
		ID:            id,
		Slug:          slug,
		Name:          name,
		Status:        tenant.Status(status),
		HomeRegion:    homeRegion,
		EnforceWrites: enforceWrites != 0,
		CreatedAt:     time.Unix(0, createdNs).UTC(),
		UpdatedAt:     time.Unix(0, updatedNs).UTC(),
	}
	if settingsJSON != "" {
		if err := json.Unmarshal([]byte(settingsJSON), &t.Settings); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal settings: %w", err)
		}
	}
	if err := unmarshalRegions(allowedRegionsJSON, &t.AllowedRegions); err != nil {
		return nil, err
	}
	return t, nil
}

// scanTenantRows decodes the ListTenants projection (id is the first column).
// Shared by ListTenants; ordering is delegated to the SQL ORDER BY id.
func scanTenantRows(rows *sql.Rows) ([]*tenant.Tenant, error) {
	var out []*tenant.Tenant
	for rows.Next() {
		var id, slug, name, status, settingsJSON, homeRegion, allowedRegionsJSON string
		var enforceWrites int64
		var createdNs, updatedNs int64
		if err := rows.Scan(&id, &slug, &name, &status, &settingsJSON, &homeRegion, &allowedRegionsJSON, &enforceWrites, &createdNs, &updatedNs); err != nil {
			return nil, fmt.Errorf("postgres: scan tenant: %w", err)
		}
		t := &tenant.Tenant{
			ID:            id,
			Slug:          slug,
			Name:          name,
			Status:        tenant.Status(status),
			HomeRegion:    homeRegion,
			EnforceWrites: enforceWrites != 0,
			CreatedAt:     time.Unix(0, createdNs).UTC(),
			UpdatedAt:     time.Unix(0, updatedNs).UTC(),
		}
		if settingsJSON != "" {
			if err := json.Unmarshal([]byte(settingsJSON), &t.Settings); err != nil {
				return nil, fmt.Errorf("postgres: unmarshal settings: %w", err)
			}
		}
		if err := unmarshalRegions(allowedRegionsJSON, &t.AllowedRegions); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows: %w", err)
	}
	if out == nil {
		out = []*tenant.Tenant{}
	}
	return out, nil
}

// unmarshalRegions decodes the allowed_regions_json TEXT column into a
// []string. The column's NOT NULL DEFAULT '[]' means a row persisted without
// region fields decodes to an empty non-nil slice; we normalize that back to
// nil so a round-trip of an unconstrained tenant stays the zero value (matches
// the settings_json "" -> nil map handling).
func unmarshalRegions(raw string, dst *[]string) error {
	if raw == "" || raw == "[]" {
		*dst = nil
		return nil
	}
	if err := json.Unmarshal([]byte(raw), dst); err != nil {
		return fmt.Errorf("postgres: unmarshal allowed_regions: %w", err)
	}
	if len(*dst) == 0 {
		*dst = nil
	}
	return nil
}

// marshalRegions encodes AllowedRegions for the allowed_regions_json column.
// Nil/empty marshals to '[]' so the column's NOT NULL invariant holds (mirrors
// the column DEFAULT).
func marshalRegions(regions []string) (string, error) {
	if len(regions) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(regions)
	if err != nil {
		return "", fmt.Errorf("postgres: marshal allowed_regions: %w", err)
	}
	return string(raw), nil
}

// scanDomain decodes a single domain row (GetDomain projection: hostname
// supplied by the caller). is_apex arrives as INTEGER (int64).
func scanDomain(host string, row scanner) (*tenant.Domain, error) {
	var tenantID, defaultClientID, brandingJSON string
	var isApexInt int64
	var createdNs, updatedNs int64
	if err := row.Scan(&tenantID, &defaultClientID, &isApexInt, &brandingJSON, &createdNs, &updatedNs); err != nil {
		return nil, err
	}
	d := &tenant.Domain{
		Hostname:        host,
		TenantID:        tenantID,
		DefaultClientID: defaultClientID,
		IsApex:          isApexInt != 0,
		CreatedAt:       time.Unix(0, createdNs).UTC(),
		UpdatedAt:       time.Unix(0, updatedNs).UTC(),
	}
	if brandingJSON != "" {
		if err := json.Unmarshal([]byte(brandingJSON), &d.Branding); err != nil {
			return nil, fmt.Errorf("postgres: unmarshal branding: %w", err)
		}
	}
	return d, nil
}

func scanDomainRows(rows *sql.Rows) ([]*tenant.Domain, error) {
	var out []*tenant.Domain
	for rows.Next() {
		var host, tenantID, defaultClientID, brandingJSON string
		var isApexInt int64
		var createdNs, updatedNs int64
		if err := rows.Scan(&host, &tenantID, &defaultClientID, &isApexInt, &brandingJSON, &createdNs, &updatedNs); err != nil {
			return nil, fmt.Errorf("postgres: scan domain: %w", err)
		}
		d := &tenant.Domain{
			Hostname:        host,
			TenantID:        tenantID,
			DefaultClientID: defaultClientID,
			IsApex:          isApexInt != 0,
			CreatedAt:       time.Unix(0, createdNs).UTC(),
			UpdatedAt:       time.Unix(0, updatedNs).UTC(),
		}
		if brandingJSON != "" {
			if err := json.Unmarshal([]byte(brandingJSON), &d.Branding); err != nil {
				return nil, fmt.Errorf("postgres: unmarshal branding: %w", err)
			}
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: rows: %w", err)
	}
	if out == nil {
		out = []*tenant.Domain{}
	}
	// Sort for deterministic order (LIST callers + tests rely on it). The SQL
	// ORDER BY hostname already sorts, but this keeps parity with the sqlite
	// peer's belt-and-suspenders ordering.
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

// normalizeHost mirrors the memory peer's RFC-1035 hostname normalization
// (case-insensitive + strip trailing dot) so the backends agree on equivalence
// classes.
func normalizeHost(h string) string {
	if len(h) > 0 && h[len(h)-1] == '.' {
		h = h[:len(h)-1]
	}
	return strings.ToLower(h)
}
