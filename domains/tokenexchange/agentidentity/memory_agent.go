package agentidentity

import (
	"context"
	"slices"
	"sync"
	"time"
)

// MemoryAgentProvider is the in-process reference AgentProvider — a
// mutex-protected map keyed by Agent.ID. Suitable for tests and
// single-replica deployments; a durable backend (sqlite/etcd) implements
// the same interface.
type MemoryAgentProvider struct {
	mu     sync.RWMutex
	agents map[string]*Agent
}

// NewMemoryAgentProvider returns an empty MemoryAgentProvider.
func NewMemoryAgentProvider() *MemoryAgentProvider {
	return &MemoryAgentProvider{agents: make(map[string]*Agent)}
}

// Register implements [AgentProvider].
func (m *MemoryAgentProvider) Register(_ context.Context, agent *Agent) error {
	if agent == nil {
		return ErrInvalidAgent
	}
	if err := agent.Validate(); err != nil {
		return err
	}
	cp := *agent
	cp.AllowedScopes = slices.Clone(agent.AllowedScopes)
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.agents[cp.ID] = &cp
	return nil
}

// Get implements [AgentProvider].
func (m *MemoryAgentProvider) Get(_ context.Context, agentID string) (*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	a, ok := m.agents[agentID]
	if !ok {
		return nil, ErrNoSuchAgent
	}
	cp := *a
	cp.AllowedScopes = slices.Clone(a.AllowedScopes)
	return &cp, nil
}

// List implements [AgentProvider].
func (m *MemoryAgentProvider) List(_ context.Context) ([]*Agent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Agent, 0, len(m.agents))
	for _, a := range m.agents {
		cp := *a
		cp.AllowedScopes = slices.Clone(a.AllowedScopes)
		out = append(out, &cp)
	}
	return out, nil
}

// var _ AgentProvider = (*MemoryAgentProvider)(nil) proves the reference
// implementation satisfies the SPI it backs. Interface guards live beside
// the implementation, never the interface (AGENTS.md §4 — avoids a cycle).
var _ AgentProvider = (*MemoryAgentProvider)(nil)
