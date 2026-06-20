package connections

import (
	"context"
	"errors"
	"strings"
	"sync"
)

// MemoryStore is the in-process connections.Store. It maintains a
// lowercase-domain -> connection-ID index so home-realm discovery (ByDomain)
// is O(1).
type MemoryStore struct {
	mu          sync.RWMutex
	byID        map[string]*Connection
	domainIndex map[string]string // lowercase domain -> connection ID
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty in-process connection store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		byID:        make(map[string]*Connection),
		domainIndex: make(map[string]string),
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
	// Drop this connection's stale domain-index entries first so a removed
	// domain stops routing.
	for d, id := range m.domainIndex {
		if id == c.ID {
			delete(m.domainIndex, d)
		}
	}
	stored := cloneConnection(c)
	m.byID[c.ID] = stored
	// Last-write-wins per domain: a domain routes to exactly one connection (an
	// org owns its domain). Re-claiming a domain reassigns it.
	for _, d := range stored.Domains {
		nd := strings.ToLower(strings.TrimSpace(d))
		if nd != "" {
			m.domainIndex[nd] = c.ID
		}
	}
	return nil
}

func (m *MemoryStore) Delete(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, id)
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
