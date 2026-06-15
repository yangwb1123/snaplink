package defaultimpl

import (
	"context"
	"sync"

	"github.com/snaplink/sso/core"
)

// MemoryTenantUserStore is an in-memory core.TenantUserStore for B2B org
// membership. Single-process only; multi-replica needs the sqlite peer. The map
// is keyed by tenantID+"\x00"+userID so the (tenant, user) pair is the edge
// identity and Add naturally upserts (NUL separator can't appear in either id).
type MemoryTenantUserStore struct {
	mu      sync.Mutex
	members map[string]*core.TenantMembership
}

// NewMemoryTenantUserStore returns an empty store.
func NewMemoryTenantUserStore() *MemoryTenantUserStore {
	return &MemoryTenantUserStore{members: make(map[string]*core.TenantMembership)}
}

func tenantUserKey(tenantID, userID string) string {
	return tenantID + "\x00" + userID
}

// Add upserts the membership keyed by (tenant, user): re-adding updates the role
// rather than creating a duplicate edge.
func (m *MemoryTenantUserStore) Add(_ context.Context, mem *core.TenantMembership) error {
	cp := *mem
	m.mu.Lock()
	m.members[tenantUserKey(mem.TenantID, mem.UserID)] = &cp
	m.mu.Unlock()
	return nil
}

// Remove deletes the (tenant, user) membership. Idempotent — a missing edge is
// not an error.
func (m *MemoryTenantUserStore) Remove(_ context.Context, tenantID, userID string) error {
	m.mu.Lock()
	delete(m.members, tenantUserKey(tenantID, userID))
	m.mu.Unlock()
	return nil
}

// Get returns the membership for (tenant, user) or core.ErrNoMembership.
func (m *MemoryTenantUserStore) Get(_ context.Context, tenantID, userID string) (*core.TenantMembership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	mem, ok := m.members[tenantUserKey(tenantID, userID)]
	if !ok {
		return nil, core.ErrNoMembership
	}
	cp := *mem
	return &cp, nil
}

// ListByTenant returns the org roster for tenantID.
func (m *MemoryTenantUserStore) ListByTenant(_ context.Context, tenantID string) ([]*core.TenantMembership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*core.TenantMembership
	for _, mem := range m.members {
		if mem.TenantID == tenantID {
			cp := *mem
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ListByUser returns every org the user belongs to.
func (m *MemoryTenantUserStore) ListByUser(_ context.Context, userID string) ([]*core.TenantMembership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*core.TenantMembership
	for _, mem := range m.members {
		if mem.UserID == userID {
			cp := *mem
			out = append(out, &cp)
		}
	}
	return out, nil
}

var _ core.TenantUserStore = (*MemoryTenantUserStore)(nil)
