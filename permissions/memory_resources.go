package permissions

import (
	"context"
	"maps"
	"strings"
	"time"
)

// resourceTupleKey is the composite uniqueness key for the
// (TenantID, ClientID, Type, Name) tuple. Pipe-separator is fine
// because none of those fields can legitimately contain "|".
func resourceTupleKey(r *Resource) string {
	return r.TenantID + "|" + r.ClientID + "|" + string(r.Type) + "|" + r.Name
}

// RegisterResource inserts or updates a Resource. Conflict on the
// (TenantID, ClientID, Type, Name) tuple with a different ID is
// ErrResourceExists; same ID overwrites in place (idempotent
// re-register). Stamps CreatedAt on first write, UpdatedAt on
// every write.
func (m *MemoryProvider) RegisterResource(_ context.Context, r *Resource) error {
	if err := r.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	tuple := resourceTupleKey(r)
	if existingID, ok := m.resourceIndex[tuple]; ok && existingID != r.ID {
		return ErrResourceExists
	}
	now := time.Now().UTC()
	cp := cloneResource(r)
	if existing, ok := m.resources[r.ID]; ok {
		cp.CreatedAt = existing.CreatedAt
		// If the (tenant,client,type,name) tuple changed, drop
		// the stale index entry so future lookups aren't
		// shadowed by a ghost row.
		oldTuple := resourceTupleKey(existing)
		if oldTuple != tuple {
			delete(m.resourceIndex, oldTuple)
		}
	} else if cp.CreatedAt.IsZero() {
		cp.CreatedAt = now
	}
	cp.UpdatedAt = now
	m.resources[r.ID] = cp
	m.resourceIndex[tuple] = r.ID
	return nil
}

// GetResource returns the Resource by ID.
func (m *MemoryProvider) GetResource(_ context.Context, id string) (*Resource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.resources[id]
	if !ok {
		return nil, ErrResourceNotFound
	}
	return cloneResource(r), nil
}

// ListResources filters by (TenantID, ClientID). Pass empty
// strings to enumerate the no-tenant / no-client buckets
// respectively (NOT "any" — admin tooling that wants "every
// resource in the catalog" should iterate per-bucket).
func (m *MemoryProvider) ListResources(_ context.Context, tenantID, clientID string) ([]*Resource, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Resource
	for _, r := range m.resources {
		if r.TenantID == tenantID && r.ClientID == clientID {
			out = append(out, cloneResource(r))
		}
	}
	return out, nil
}

// DeleteResource removes a Resource by ID. Idempotent.
func (m *MemoryProvider) DeleteResource(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.resources[id]
	if !ok {
		return nil
	}
	delete(m.resourceIndex, resourceTupleKey(r))
	delete(m.resources, id)
	return nil
}

// ResolveResource walks the catalog for a Resource matching the
// lookup. Linear scan is fine for the in-memory backend (the
// catalog is rarely larger than a few hundred entries per
// client); SQL backends should prefer a dispatch table per Type
// keyed by the canonical match attribute.
//
// Returns Decision{Found:false} when no Resource matches — NOT
// an error. Handlers decide the missing-entry default.
func (m *MemoryProvider) ResolveResource(_ context.Context, lookup ResourceLookup) (*ResourceDecision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, r := range m.resources {
		if r.TenantID != lookup.TenantID || r.ClientID != lookup.ClientID {
			continue
		}
		if r.Type != lookup.Type {
			continue
		}
		if !matchAttributes(r.Type, r.Attributes, lookup.Match) {
			continue
		}
		return &ResourceDecision{
			Found:               true,
			ResourceID:          r.ID,
			RequiresAuth:        r.RequiresAuth,
			RequiredPermissions: append([]string(nil), r.RequiredPermissions...),
			RequireMode:         r.EffectiveRequireMode(),
		}, nil
	}
	return &ResourceDecision{Found: false}, nil
}

// matchAttributes runs the per-Type match between a registered
// Resource's attributes and a runtime lookup's Match keys. HTTP
// supports :param path placeholders; everything else is exact
// match on the documented keys.
func matchAttributes(t ResourceType, want, have map[string]string) bool {
	switch t {
	case ResourceTypeHTTPAPI:
		if !equalFold(want["method"], have["method"]) {
			return false
		}
		return matchPath(want["path"], have["path"])
	case ResourceTypeGRPCAPI:
		return want["service"] == have["service"] && want["method"] == have["method"]
	case ResourceTypeGraphQLAPI:
		return want["op"] == have["op"] && want["field"] == have["field"]
	case ResourceTypePage:
		return want["route"] == have["route"]
	case ResourceTypeJSFn:
		return want["route"] == have["route"] && want["symbol"] == have["symbol"]
	case ResourceTypeUIElement:
		// UI elements are typically resolved by selector lookup
		// per page; runtime path is rare. Match by selector
		// (and page_id when both sides set it).
		if want["selector"] != have["selector"] {
			return false
		}
		if wp, hp := want["page_id"], have["page_id"]; wp != "" && hp != "" && wp != hp {
			return false
		}
		return true
	default:
		// Custom types: best-effort exact match across every key
		// in the registered Attributes.
		for k, v := range want {
			if have[k] != v {
				return false
			}
		}
		return true
	}
}

// matchPath returns true when actual matches the pattern, where
// pattern segments starting with ":" are wildcards. Same shape
// as router.go's matchPath; reproduced here so the permissions
// package doesn't import the sso runtime.
func matchPath(pattern, actual string) bool {
	pParts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	aParts := strings.Split(strings.TrimPrefix(actual, "/"), "/")
	if len(pParts) != len(aParts) {
		return false
	}
	for i, p := range pParts {
		if strings.HasPrefix(p, ":") {
			continue
		}
		if p != aParts[i] {
			return false
		}
	}
	return true
}

func equalFold(a, b string) bool {
	return strings.EqualFold(a, b)
}

func cloneResource(r *Resource) *Resource {
	if r == nil {
		return nil
	}
	cp := *r
	if r.Attributes != nil {
		cp.Attributes = make(map[string]string, len(r.Attributes))
		maps.Copy(cp.Attributes, r.Attributes)
	}
	if r.RequiredPermissions != nil {
		cp.RequiredPermissions = append([]string(nil), r.RequiredPermissions...)
	}
	return &cp
}

// Compile-time check that MemoryProvider satisfies ResourceProvider.
var _ ResourceProvider = (*MemoryProvider)(nil)
