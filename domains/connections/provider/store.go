package provider

import (
	"context"
	"errors"
)

// ErrNoSuchProvider is returned when a provider is not found.
var ErrNoSuchProvider = errors.New("provider: no such provider")

// Store persists third-party login providers. Implementations MUST be safe
// for concurrent use.
type Store interface {
	// Create inserts a new provider. Returns ErrProviderExists if the ID
	// is taken within the same tenant.
	Create(ctx context.Context, p *Provider) error

	// Get returns a provider by ID, or ErrNoSuchProvider.
	Get(ctx context.Context, id string) (*Provider, error)

	// Update replaces an existing provider. Returns ErrNoSuchProvider when
	// the provider does not exist.
	Update(ctx context.Context, p *Provider) error

	// Delete removes a provider by ID. Idempotent — missing IDs return nil.
	Delete(ctx context.Context, id string) error

	// ListByTenant returns every provider owned by tenantID (including
	// global providers). Returns empty slice when none exist.
	ListByTenant(ctx context.Context, tenantID string) ([]*Provider, error)

	// ListGlobal returns every global provider (TenantID == "").
	ListGlobal(ctx context.Context) ([]*Provider, error)

	// ListByIDs returns the providers matching the given ID set. Unknown
	// IDs are silently skipped — the caller compares length to detect
	// missing entries.
	ListByIDs(ctx context.Context, ids []string) ([]*Provider, error)
}

// ErrProviderExists is returned when Create finds a duplicate (id, tenant_id).
var ErrProviderExists = errors.New("provider: already exists")
