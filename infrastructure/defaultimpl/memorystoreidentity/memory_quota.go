package memorystoreidentity

import (
	"context"
	"sync"

	"github.com/snaplink/sso/shared/core"
)

// MemoryTenantQuotaStore is an in-memory implementation of core.TenantQuotaStore.
// Suitable for tests and single-process deployments; not durable across restarts.
// Thread-safe.
type MemoryTenantQuotaStore struct {
	mu     sync.RWMutex
	quotas map[string]*core.TenantQuota
	usage  map[string]*core.TenantUsage
}

// NewMemoryTenantQuotaStore returns an empty MemoryTenantQuotaStore.
func NewMemoryTenantQuotaStore() *MemoryTenantQuotaStore {
	return &MemoryTenantQuotaStore{
		quotas: make(map[string]*core.TenantQuota),
		usage:  make(map[string]*core.TenantUsage),
	}
}

// GetQuota implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) GetQuota(_ context.Context, tenantID string) (*core.TenantQuota, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	q, ok := s.quotas[tenantID]
	if !ok {
		return &core.TenantQuota{}, nil // unlimited default
	}
	return q, nil
}

// GetUsage implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) GetUsage(_ context.Context, tenantID string) (*core.TenantUsage, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.usage[tenantID]
	if !ok {
		return &core.TenantUsage{}, nil
	}
	return u, nil
}

// IncrementUsage implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) IncrementUsage(_ context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	q, hasQuota := s.quotas[tenantID]
	u, _ := s.usage[tenantID]
	if u == nil {
		u = &core.TenantUsage{}
		s.usage[tenantID] = u
	}

	switch resource {
	case core.ResourceClients:
		u.Clients += int(delta)
		if hasQuota && q.MaxClients > 0 && u.Clients > q.MaxClients {
			u.Clients -= int(delta)
			return core.ErrQuotaExceeded
		}
	case core.ResourceUsers:
		u.Users += int(delta)
		if hasQuota && q.MaxUsers > 0 && u.Users > q.MaxUsers {
			u.Users -= int(delta)
			return core.ErrQuotaExceeded
		}
	case core.ResourceSessions:
		u.Sessions += int(delta)
		if hasQuota && q.MaxSessions > 0 && u.Sessions > q.MaxSessions {
			u.Sessions -= int(delta)
			return core.ErrQuotaExceeded
		}
	}
	return nil
}

// DecrementUsage implements core.TenantQuotaStore. Floors at 0 — a caller
// compensating an IncrementUsage it never actually charged (e.g. a double
// rollback) must not push the counter negative.
func (s *MemoryTenantQuotaStore) DecrementUsage(_ context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	u, ok := s.usage[tenantID]
	if !ok {
		return nil
	}
	switch resource {
	case core.ResourceClients:
		u.Clients = max(0, u.Clients-int(delta))
	case core.ResourceUsers:
		u.Users = max(0, u.Users-int(delta))
	case core.ResourceSessions:
		u.Sessions = max(0, u.Sessions-int(delta))
	}
	return nil
}

// SetQuota implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) SetQuota(_ context.Context, tenantID string, quota *core.TenantQuota) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.quotas[tenantID] = quota
	return nil
}

// ResetUsage implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) ResetUsage(_ context.Context, tenantID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.usage, tenantID)
	return nil
}

// compile-time guard
var _ core.TenantQuotaStore = (*MemoryTenantQuotaStore)(nil)
