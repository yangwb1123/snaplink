package conditionalaccess

import (
	"context"
	"sync"
)

// MemoryStore is the in-process conditional-access Store. Policies are
// read-mostly (they change only when an operator edits them or loads a YAML
// bundle), so a plain RWMutex-guarded map suffices. State is lost on restart —
// fine for tests and for deployments that reload policies from config at boot.
type MemoryStore struct {
	mu       sync.RWMutex
	policies map[string]Policy
}

var _ Store = (*MemoryStore)(nil)

// NewMemoryStore returns an empty in-process policy store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{policies: make(map[string]Policy)}
}

// List returns every stored policy (cloned; order unspecified).
func (m *MemoryStore) List(_ context.Context) ([]Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Policy, 0, len(m.policies))
	for _, p := range m.policies {
		out = append(out, clonePolicy(p))
	}
	return out, nil
}

// Get returns the policy by name; ok is false when absent (never an error).
func (m *MemoryStore) Get(_ context.Context, name string) (Policy, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.policies[name]
	if !ok {
		return Policy{}, false, nil
	}
	return clonePolicy(p), true, nil
}

// Put validates then inserts or replaces the policy keyed by Name.
func (m *MemoryStore) Put(_ context.Context, p Policy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[p.Name] = clonePolicy(p)
	return nil
}

// Delete removes the policy by name. Idempotent.
func (m *MemoryStore) Delete(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.policies, name)
	return nil
}

// clonePolicy deep-copies the slice- and pointer-valued fields so stored state
// is isolated from caller-side mutation in both directions.
func clonePolicy(p Policy) Policy {
	p.Conditions.UserMemberOf = cloneStrings(p.Conditions.UserMemberOf)
	p.Conditions.GeoIn = cloneStrings(p.Conditions.GeoIn)
	p.Conditions.GeoNotIn = cloneStrings(p.Conditions.GeoNotIn)
	if p.Conditions.DeviceManaged != nil {
		v := *p.Conditions.DeviceManaged
		p.Conditions.DeviceManaged = &v
	}
	p.Actions.RestrictScopes = cloneStrings(p.Actions.RestrictScopes)
	return p
}
