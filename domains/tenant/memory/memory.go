// Package memory is the in-process tenant.Store. State is lost on
// restart — fine for tests + small embedded deployments where the
// tenant set is loaded from YAML at boot. Production multi-tenant
// SaaS should swap this for a SQL-backed Store.
package memory

import (
	"context"
	"maps"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Store holds Tenants + Domains in process-local maps. Safe for
// concurrent use.
type Store struct {
	mu       sync.RWMutex
	tenants  map[string]*tenant.Tenant
	domains  map[string]*tenant.Domain // keyed by hostname (lowercased)
	branding map[string]tenant.Branding
	now      func() time.Time
}

// New constructs an empty Store.
func New() *Store {
	return &Store{
		tenants:  make(map[string]*tenant.Tenant),
		domains:  make(map[string]*tenant.Domain),
		branding: make(map[string]tenant.Branding),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

// --- Tenants ---

func (s *Store) GetTenant(_ context.Context, id string) (*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	if !ok {
		return nil, tenant.ErrTenantNotFound
	}
	return cloneTenant(t), nil
}

func (s *Store) ListTenants(_ context.Context) ([]*tenant.Tenant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*tenant.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, cloneTenant(t))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *Store) PutTenant(_ context.Context, t *tenant.Tenant) error {
	if err := t.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	cp := cloneTenant(t)
	if existing, ok := s.tenants[t.ID]; ok {
		cp.CreatedAt = existing.CreatedAt
	} else if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	}
	cp.UpdatedAt = now
	s.tenants[t.ID] = cp
	return nil
}

func (s *Store) DeleteTenant(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tenants, id)
	delete(s.branding, id)
	// Cascade: drop any domains pointing at this tenant. The store
	// is the source of truth — leaving orphan Domain rows would
	// route to a 404 tenant on next request.
	for h, d := range s.domains {
		if d.TenantID == id {
			delete(s.domains, h)
		}
	}
	return nil
}

// GetBranding returns the dedicated branding resource without exposing or
// copying Tenant.Settings.
func (s *Store) GetBranding(_ context.Context, tenantID string) (tenant.Branding, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return tenant.Branding{}, tenant.ErrTenantNotFound
	}
	value, ok := s.branding[tenantID]
	if !ok {
		return tenant.Branding{Values: map[string]string{}, Version: "0"}, nil
	}
	value.Values = maps.Clone(value.Values)
	return value, nil
}

// PutBranding atomically compares and advances the resource version.
func (s *Store) PutBranding(
	_ context.Context, tenantID string, values map[string]string, expectedVersion string,
) (tenant.Branding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[tenantID]; !ok {
		return tenant.Branding{}, tenant.ErrTenantNotFound
	}
	current, ok := s.branding[tenantID]
	if !ok {
		current = tenant.Branding{Version: "0"}
	}
	if current.Version != expectedVersion {
		return tenant.Branding{}, tenant.ErrBrandingPrecondition
	}
	next := tenant.Branding{
		Values: maps.Clone(values), Version: nextBrandingVersion(current.Version),
	}
	s.branding[tenantID] = next
	next.Values = maps.Clone(next.Values)
	return next, nil
}

func nextBrandingVersion(current string) string {
	version, _ := strconv.ParseUint(current, 10, 64)
	return strconv.FormatUint(version+1, 10)
}

// --- Domains ---

func (s *Store) GetDomain(_ context.Context, hostname string) (*tenant.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.domains[normalizeHost(hostname)]
	if !ok {
		return nil, tenant.ErrDomainNotFound
	}
	return cloneDomain(d), nil
}

func (s *Store) ListDomains(_ context.Context) ([]*tenant.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*tenant.Domain, 0, len(s.domains))
	for _, d := range s.domains {
		out = append(out, cloneDomain(d))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

func (s *Store) ListDomainsByTenant(_ context.Context, tenantID string) ([]*tenant.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*tenant.Domain
	for _, d := range s.domains {
		if d.TenantID == tenantID {
			out = append(out, cloneDomain(d))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Hostname < out[j].Hostname })
	return out, nil
}

func (s *Store) PutDomain(_ context.Context, d *tenant.Domain) error {
	if err := d.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[d.TenantID]; !ok {
		return tenant.ErrTenantNotFound
	}
	host := normalizeHost(d.Hostname)
	now := s.now()
	cp := cloneDomain(d)
	cp.Hostname = host
	if existing, ok := s.domains[host]; ok {
		// Same hostname for a different tenant is a real conflict.
		if existing.TenantID != d.TenantID {
			return tenant.ErrDomainExists
		}
		cp.CreatedAt = existing.CreatedAt
	} else if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	}
	cp.UpdatedAt = now
	s.domains[host] = cp
	return nil
}

func (s *Store) DeleteDomain(_ context.Context, hostname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.domains, normalizeHost(hostname))
	return nil
}

func (s *Store) Close() error { return nil }

// ListPage implements tenant.PaginatedTenantStore: filter (shared tenant
// matchers) -> sort (shared comparators over a snapshot, so random map
// iteration cannot leak into page order) -> keyset slice. totalHint is the
// exact filtered count.
func (s *Store) ListPage(_ context.Context, q core.PageQuery) ([]*tenant.Tenant, []byte, int, error) {
	s.mu.RLock()
	all := make([]*tenant.Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		all = append(all, cloneTenant(t))
	}
	s.mu.RUnlock()
	field, value, ok := core.ParseFilterExpr(q.Filter)
	if ok {
		if err := tenant.ValidateTenantFilter(field, value); err != nil {
			return nil, nil, 0, err
		}
		filtered := all[:0]
		for _, t := range all {
			match, err := tenant.TenantMatches(t, field, value)
			if err != nil {
				return nil, nil, 0, err
			}
			if match {
				filtered = append(filtered, t)
			}
		}
		all = filtered
	}
	keyID := func(t *tenant.Tenant) (string, string) { return tenant.TenantSortKey(t, q.OrderBy), t.ID }
	core.SortKeyset(all, q.Desc, keyID)
	return core.KeysetSlice(all, q, keyID)
}

// ListDomainsPage implements tenant.PaginatedDomainStore: keyset
// pagination over a snapshot sorted by hostname. tenantID "" = every domain
// (the ListDomains fallback); non-empty = that tenant's domains (the
// ListDomainsByTenant fallback). totalHint is the exact row count.
func (s *Store) ListDomainsPage(_ context.Context, tenantID string, q core.PageQuery) ([]*tenant.Domain, []byte, int, error) {
	s.mu.RLock()
	all := make([]*tenant.Domain, 0, len(s.domains))
	for _, d := range s.domains {
		if tenantID == "" || d.TenantID == tenantID {
			all = append(all, cloneDomain(d))
		}
	}
	s.mu.RUnlock()
	keyID := func(d *tenant.Domain) (string, string) { return d.Hostname, d.Hostname }
	core.SortKeyset(all, q.Desc, keyID)
	return core.KeysetSlice(all, q, keyID)
}

// Compile-time interface checks.
// normalizeHost lowercases + strips a trailing dot so
// "Acme.com" / "acme.com." / "acme.com" all resolve to the same
// row. RFC 1035 says hostnames are case-insensitive.
func normalizeHost(h string) string {
	h = stripTrailingDot(h)
	return toLower(h)
}

func stripTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func toLower(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}

func cloneTenant(t *tenant.Tenant) *tenant.Tenant {
	if t == nil {
		return nil
	}
	cp := *t
	if t.Settings != nil {
		cp.Settings = make(map[string]string, len(t.Settings))
		maps.Copy(cp.Settings, t.Settings)
	}
	if t.AllowedRegions != nil {
		// Deep-copy the residency slice for the same reason Settings is
		// copied: a stored Tenant must not alias the caller's slice.
		cp.AllowedRegions = make([]string, len(t.AllowedRegions))
		copy(cp.AllowedRegions, t.AllowedRegions)
	}
	return &cp
}

func cloneDomain(d *tenant.Domain) *tenant.Domain {
	if d == nil {
		return nil
	}
	cp := *d
	if d.Branding != nil {
		cp.Branding = make(map[string]string, len(d.Branding))
		maps.Copy(cp.Branding, d.Branding)
	}
	return &cp
}

// Compile-time interface checks.
var (
	_ tenant.Store                = (*Store)(nil)
	_ tenant.PaginatedTenantStore = (*Store)(nil)
	_ tenant.PaginatedDomainStore = (*Store)(nil)
)
