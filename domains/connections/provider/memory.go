package provider

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-process Store backed by a map. Suitable for dev,
// single-node deployments, and tests.
type MemoryStore struct {
	mu  sync.RWMutex
	byID map[string]*Provider
}

// NewMemoryStore returns an empty in-memory provider store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID: make(map[string]*Provider),
	}
}

func (m *MemoryStore) Create(_ context.Context, p *Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.byID[p.ID]; exists {
		return ErrProviderExists
	}
	now := time.Now()
	cp := p.Clone()
	cp.CreatedAt = now
	cp.UpdatedAt = now
	m.byID[cp.ID] = cp
	return nil
}

func (m *MemoryStore) Get(_ context.Context, id string) (*Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, ok := m.byID[id]
	if !ok {
		return nil, ErrNoSuchProvider
	}
	return p.Clone(), nil
}

func (m *MemoryStore) Update(_ context.Context, p *Provider) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.byID[p.ID]; !exists {
		return ErrNoSuchProvider
	}
	cp := p.Clone()
	cp.UpdatedAt = time.Now()
	m.byID[cp.ID] = cp
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.byID, id)
	return nil
}

func (m *MemoryStore) ListByTenant(_ context.Context, tenantID string) ([]*Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*Provider
	for _, p := range m.byID {
		if p.TenantID == tenantID || p.TenantID == "" {
			out = append(out, p.Clone())
		}
	}
	if out == nil {
		out = []*Provider{}
	}
	return out, nil
}

func (m *MemoryStore) ListGlobal(_ context.Context) ([]*Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var out []*Provider
	for _, p := range m.byID {
		if p.TenantID == "" {
			out = append(out, p.Clone())
		}
	}
	if out == nil {
		out = []*Provider{}
	}
	return out, nil
}

func (m *MemoryStore) ListByIDs(_ context.Context, ids []string) ([]*Provider, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]*Provider, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		if p, ok := m.byID[id]; ok {
			out = append(out, p.Clone())
		}
	}
	return out, nil
}

// Compile-time interface check.
var _ Store = (*MemoryStore)(nil)
