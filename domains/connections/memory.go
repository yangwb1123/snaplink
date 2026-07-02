package connections

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// MemoryStore is the in-process connections.Store. It maintains a
// lowercase-domain -> connection-ID index so home-realm discovery (ByDomain)
// is O(1). domainIndex holds ONLY the current verified routing owner per
// domain; per-connection ownership claims (pending + verified) live in claims.
type MemoryStore struct {
	mu          sync.RWMutex
	cfg         StoreConfig
	byID        map[string]*Connection
	domainIndex map[string]string                         // lowercase domain -> verified routing owner
	claims      map[string]map[string]*DomainVerification // connID -> lowercase domain -> claim
	health      map[string]*ConnectionHealth              // connID -> last recorded probe outcome
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty in-process connection store. Options are
// variadic so the historical zero-arg call sites keep compiling unchanged; with
// no options the store behaves byte-identically to the pre-verification build.
func NewMemoryStore(opts ...StoreOption) *MemoryStore {
	return &MemoryStore{
		cfg:         ApplyStoreOptions(opts...),
		byID:        make(map[string]*Connection),
		domainIndex: make(map[string]string),
		claims:      make(map[string]map[string]*DomainVerification),
		health:      make(map[string]*ConnectionHealth),
	}
}

func (m *MemoryStore) Get(_ context.Context, id string) (*Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.byID[id]
	if !ok {
		return nil, ErrNoConnection
	}
	return cloneConnection(c), nil
}

func (m *MemoryStore) ByTenant(_ context.Context, tenantID string) ([]*Connection, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Connection
	for _, c := range m.byID {
		if c.TenantID == tenantID {
			out = append(out, cloneConnection(c))
		}
	}
	return out, nil
}

func (m *MemoryStore) ByDomain(_ context.Context, emailDomain string) (*Connection, error) {
	d := strings.ToLower(strings.TrimSpace(emailDomain))
	if d == "" {
		return nil, ErrNoConnection
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	id, ok := m.domainIndex[d]
	if !ok {
		return nil, ErrNoConnection
	}
	c, ok := m.byID[id]
	if !ok || !c.Enabled {
		// Disabled connections do not serve home-realm discovery (the org's
		// federation is paused) — fall back to the normal login path.
		return nil, ErrNoConnection
	}
	return cloneConnection(c), nil
}

func (m *MemoryStore) Upsert(_ context.Context, c *Connection) error {
	if c == nil || c.ID == "" {
		return errors.New("connections: id required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := cloneConnection(c)
	m.byID[c.ID] = stored
	return m.reconcileClaimsLocked(stored)
}

func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
	delete(m.claims, id)
	delete(m.health, id)
	for d, cid := range m.domainIndex {
		if cid == id {
			delete(m.domainIndex, d)
		}
	}
	return nil
}

// cloneConnection deep-copies so stored state can't be mutated through a
// returned pointer (matching the other Memory* stores' by-value contract).
func cloneConnection(c *Connection) *Connection {
	cp := *c
	cp.Domains = append([]string(nil), c.Domains...)
	if c.Config != nil {
		cp.Config = make(map[string]string, len(c.Config))
		for k, v := range c.Config {
			cp.Config[k] = v
		}
	}
	return &cp
}
