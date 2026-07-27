package sqlite

import (
	"encoding/json"
	"fmt"

	"github.com/yangwb1123/snaplink/domains/tenant"
)

// tenantColumns holds the SQLite-encoded scalar values for a tenant UPSERT,
// derived once so PutTenant stays a thin SQL wrapper.
type tenantColumns struct {
	settingsJSON       string
	allowedRegionsJSON string
	enforceWrites      int
	createdAt          int64
}

// encodeTenantColumns marshals the JSON columns and normalizes the bool/time
// columns to SQLite's storage form. createdAt preserves a caller-supplied
// timestamp (operator updates don't reset creation), else defaults to now.
func encodeTenantColumns(t *tenant.Tenant, now int64) (tenantColumns, error) {
	settingsJSON := ""
	if len(t.Settings) > 0 {
		raw, err := json.Marshal(t.Settings)
		if err != nil {
			return tenantColumns{}, fmt.Errorf("tenant/sqlite: marshal settings: %w", err)
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
	enforceWrites := 0
	if t.EnforceWrites {
		enforceWrites = 1
	}
	return tenantColumns{
		settingsJSON:       settingsJSON,
		allowedRegionsJSON: allowedRegionsJSON,
		enforceWrites:      enforceWrites,
		createdAt:          createdAt,
	}, nil
}

// domainColumns holds the SQLite-encoded scalar values for a domain UPSERT.
type domainColumns struct {
	brandingJSON string
	isApex       int
	createdAt    int64
}

// encodeDomainColumns marshals the branding JSON and normalizes the bool/time
// columns to SQLite's storage form. createdAt preserves a caller-supplied
// timestamp, else defaults to now.
func encodeDomainColumns(d *tenant.Domain, now int64) (domainColumns, error) {
	brandingJSON := ""
	if len(d.Branding) > 0 {
		raw, err := json.Marshal(d.Branding)
		if err != nil {
			return domainColumns{}, fmt.Errorf("tenant/sqlite: marshal branding: %w", err)
		}
		brandingJSON = string(raw)
	}

	createdAt := now
	if !d.CreatedAt.IsZero() {
		createdAt = d.CreatedAt.UnixNano()
	}
	isApex := 0
	if d.IsApex {
		isApex = 1
	}
	return domainColumns{
		brandingJSON: brandingJSON,
		isApex:       isApex,
		createdAt:    createdAt,
	}, nil
}
