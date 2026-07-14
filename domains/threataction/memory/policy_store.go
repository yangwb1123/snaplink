// Package memory implements an in-memory ThreatPolicyStore suitable
// for development, testing, and single-replica deployments with no
// cross-restart policy persistence.
package memory

import (
	"context"
	"sort"
	"sync"

	"github.com/snaplink/sso/domains/threataction"
)

// ThreatPolicyStore is an in-memory, concurrency-safe ThreatPolicyStore.
// Policies are sorted by name for deterministic first-match ordering.
type ThreatPolicyStore struct {
	mu       sync.RWMutex
	policies map[string]threataction.ThreatPolicy
}

// NewThreatPolicyStore builds an empty memory-backed policy store.
func NewThreatPolicyStore() *ThreatPolicyStore {
	return &ThreatPolicyStore{
		policies: make(map[string]threataction.ThreatPolicy),
	}
}

// List returns every policy, sorted by name (deterministic ordering for
// first-match-wins evaluation).
func (s *ThreatPolicyStore) List(_ context.Context) ([]threataction.ThreatPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]threataction.ThreatPolicy, 0, len(s.policies))
	for _, p := range s.policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// Get returns a single policy by name. Returns threataction.ErrPolicyNotFound
// when the policy doesn't exist.
func (s *ThreatPolicyStore) Get(_ context.Context, name string) (*threataction.ThreatPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[name]
	if !ok {
		return nil, threataction.ErrPolicyNotFound
	}
	return &p, nil
}

// Put upserts a policy by name. If a policy with the same name already
// exists, it is replaced.
func (s *ThreatPolicyStore) Put(_ context.Context, policy threataction.ThreatPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policy.Name] = policy
	return nil
}

// Delete removes a policy by name. Returns threataction.ErrPolicyNotFound
// when the policy doesn't exist.
func (s *ThreatPolicyStore) Delete(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.policies[name]; !ok {
		return threataction.ErrPolicyNotFound
	}
	delete(s.policies, name)
	return nil
}
