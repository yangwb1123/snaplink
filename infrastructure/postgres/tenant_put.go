package postgres

import (
	"encoding/json"
	"fmt"

	"github.com/snaplink/sso/domains/tenant"
)

// tenantColumns holds the Postgres-encoded scalar values for a tenant UPSERT,
// derived once so PutTenant stays a thin SQL wrapper. Booleans are encoded as
// 0/1 INTEGERs (boolToInt) and timestamps as int64 nanoseconds (BIGINT).
type tenantColumns struct {
	settingsJSON       string
	allowedRegionsJSON string
	enforceWrites      int
	createdAt          int64
}

// encodeTenantColumns marshals the JSON columns and normalizes the bool/time
// columns to the on-disk storage form. createdAt preserves a caller-supplied
// timestamp (operator updates don't reset creation), else defaults to now.
func encodeTenantColumns(t *tenant.Tenant, now int64) (tenantColumns, error) {
	settingsJSON := ""
	if len(t.Settings) > 0 {
		raw, err := json.Marshal(t.Settings)
		if err != nil {
			return tenantColumns{}, fmt.Errorf("postgres: marshal settings: %w", err)
		}
		settingsJSON = string(raw)
	}

	allowedRegionsJSON, err := marshalRegions(t.AllowedRegions)
	if err != nil {
		return tenantColumns{}, err
	}

	createdAt := now
	if !t.CreatedAt.IsZero() {
		createdAt = t.CreatedAt.UnixNano()
	}
	return tenantColumns{
		settingsJSON:       settingsJSON,
		allowedRegionsJSON: allowedRegionsJSON,
		enforceWrites:      boolToInt(t.EnforceWrites),
		createdAt:          createdAt,
	}, nil
}

// domainColumns holds the Postgres-encoded scalar values for a domain UPSERT.
type domainColumns struct {
	brandingJSON string
	isApex       int
	createdAt    int64
}

// encodeDomainColumns marshals the branding JSON and normalizes the bool/time
// columns to the on-disk storage form. createdAt preserves a caller-supplied
// timestamp, else defaults to now.
func encodeDomainColumns(d *tenant.Domain, now int64) (domainColumns, error) {
	brandingJSON := ""
	if len(d.Branding) > 0 {
		raw, err := json.Marshal(d.Branding)
		if err != nil {
			return domainColumns{}, fmt.Errorf("postgres: marshal branding: %w", err)
		}
		brandingJSON = string(raw)
	}

	createdAt := now
	if !d.CreatedAt.IsZero() {
		createdAt = d.CreatedAt.UnixNano()
	}
	return domainColumns{
		brandingJSON: brandingJSON,
		isApex:       boolToInt(d.IsApex),
		createdAt:    createdAt,
	}, nil
}
