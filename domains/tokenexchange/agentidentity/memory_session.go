package agentidentity

import (
	"context"
	"slices"
	"sync"
	"time"
)

// MemoryAgentSessionStore is the in-process reference AgentSessionStore — a
// mutex-protected map keyed by AgentSession.ID. Suitable for tests and
// single-replica deployments; a durable backend (sqlite/etcd) implements
// the same interface (e.g. to survive a restart, or share state across
// replicas the way a cluster-aware refresh-token store does).
type MemoryAgentSessionStore struct {
	mu       sync.RWMutex
	sessions map[string]*AgentSession
}

// NewMemoryAgentSessionStore returns an empty MemoryAgentSessionStore.
func NewMemoryAgentSessionStore() *MemoryAgentSessionStore {
	return &MemoryAgentSessionStore{sessions: make(map[string]*AgentSession)}
}

// Create implements [AgentSessionStore].
func (m *MemoryAgentSessionStore) Create(_ context.Context, sess *AgentSession) error {
	if sess == nil {
		return ErrInvalidSession
	}
	if err := sess.Validate(); err != nil {
		return err
	}
	cp := *sess
	cp.GrantedScopes = slices.Clone(sess.GrantedScopes)
	if cp.CreatedAt.IsZero() {
		cp.CreatedAt = time.Now()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[cp.ID] = &cp
	return nil
}

// Get implements [AgentSessionStore].
func (m *MemoryAgentSessionStore) Get(_ context.Context, id string) (*AgentSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	if !ok {
		return nil, ErrNoSuchSession
	}
	cp := *s
	cp.GrantedScopes = slices.Clone(s.GrantedScopes)
	return &cp, nil
}

// Revoke implements [AgentSessionStore].
func (m *MemoryAgentSessionStore) Revoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok || s.Revoked {
		return nil // idempotent — no oracle on prior existence/state
	}
	s.Revoked = true
	s.RevokedAt = time.Now()
	return nil
}

// RevokeAllForHuman implements [AgentSessionStore].
func (m *MemoryAgentSessionStore) RevokeAllForHuman(_ context.Context, humanSubject string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var n int
	for _, s := range m.sessions {
		if s.HumanSubject != humanSubject || s.Revoked {
			continue
		}
		s.Revoked = true
		s.RevokedAt = now
		n++
	}
	return n, nil
}

// var _ AgentSessionStore = (*MemoryAgentSessionStore)(nil) proves the
// reference implementation satisfies the SPI it backs.
var _ AgentSessionStore = (*MemoryAgentSessionStore)(nil)
