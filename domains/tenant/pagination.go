package tenant

import (
	"context"
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// PaginatedTenantStore is an OPTIONAL extension a tenant.Store MAY implement
// to push ListTenants' filter/sort/pagination down into the backend instead
// of the grpcadmin fallback's full ListTenants() -> filter -> sort -> offset
// slice. Same optional-extension pattern as core.PaginatedClientStore:
// callers type-assert, absence degrades to ListTenants(). The core.PageQuery
// contract (raw filter mini-grammar, canonical order field, store-opaque
// cursor bytes, exact-or--1 totalHint) applies unchanged.
type PaginatedTenantStore interface {
	ListPage(ctx context.Context, q core.PageQuery) ([]*Tenant, []byte, int, error)
}

// PaginatedDomainStore is the domain counterpart of PaginatedTenantStore.
// tenantID "" = every domain (the ListDomains fallback); non-empty = that
// tenant's domains (the ListDomainsByTenant fallback). Named
// ListDomainsPage (not ListPage) because Go types cannot overload two
// ListPage methods on the same Store receiver.
type PaginatedDomainStore interface {
	ListDomainsPage(ctx context.Context, tenantID string, q core.PageQuery) ([]*Domain, []byte, int, error)
}

// --- Tenant filter/sort semantics (fallback + memory-store reference) ---
//
// Extracted from grpcadmin's per-RPC matchers so the fallback path and the
// memory-store ListPage share one semantics and one error text
// ("unsupported filter field %q"). grpcadmin wraps the plain errors into
// InvalidArgument status errors with byte-identical messages.

// ValidateTenantFilter checks one filter field/value pair. Field set:
// id/slug/status (exact) + name (substring) — the fields a Tenant carries
// that make sense as filter keys.
func ValidateTenantFilter(field, value string) error {
	switch strings.ToLower(field) {
	case "id", "slug", "name", "status":
		return nil
	default:
		return fmt.Errorf("unsupported filter field %q", field)
	}
}

// TenantMatches evaluates one filter field against a tenant.
func TenantMatches(t *Tenant, field, value string) (bool, error) {
	switch strings.ToLower(field) {
	case "id":
		return t.ID == value, nil
	case "slug":
		return t.Slug == value, nil
	case "name":
		return strings.Contains(strings.ToLower(t.Name), strings.ToLower(value)), nil
	case "status":
		return string(t.Status) == value, nil
	default:
		return false, fmt.Errorf("unsupported filter field %q", field)
	}
}

// ValidateTenantOrderBy checks one order_by field without touching any row.
// The supported set is id/slug/name ONLY — deliberately not status, which
// the fallback path never accepted (changing that would alter the fallback's
// InvalidArgument behavior for order_by=status).
func ValidateTenantOrderBy(field string) error {
	switch strings.ToLower(field) {
	case "", "id", "slug", "name":
		return nil
	default:
		return fmt.Errorf("unsupported order_by field %q", field)
	}
}

// TenantSortKey returns the canonical string form of a tenant's sort key for
// the given canonical order field ("" = id). Memory stores use it so their
// sort, their keyset search, and their cursor bytes share one encoding.
func TenantSortKey(t *Tenant, field string) string {
	switch strings.ToLower(field) {
	case "slug":
		return t.Slug
	case "name":
		return t.Name
	case "", "id":
		return t.ID
	}
	return t.ID
}

// CompareTenants orders two tenants by the canonical sort field, breaking
// ties by ID — the strict total order keyset paging relies on.
func CompareTenants(a, b *Tenant, field string) int {
	switch strings.ToLower(field) {
	case "slug":
		if c := strings.Compare(a.Slug, b.Slug); c != 0 {
			return c
		}
	case "name":
		if c := strings.Compare(a.Name, b.Name); c != 0 {
			return c
		}
	case "", "id":
	}
	return strings.Compare(a.ID, b.ID)
}

// CompareDomains orders two domains by hostname (their unique key, so no
// tiebreaker is needed).
func CompareDomains(a, b *Domain) int {
	return strings.Compare(a.Hostname, b.Hostname)
}
