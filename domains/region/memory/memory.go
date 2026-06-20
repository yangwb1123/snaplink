// Package memory is the in-process region.PolicyStore. State is lost on
// restart — fine for tests + small embedded deployments where residency
// policies are loaded from config at boot. The residency policy is
// read-mostly (it changes only when an operator re-pins a tenant), so a
// plain RWMutex-guarded map suffices.
package memory

import (
	"context"
	"sync"

	"github.com/snaplink/sso/domains/region"
)

// Store holds per-tenant ResidencyPolicy in a process-local map. Safe for
// concurrent use.
type Store struct {
	mu       sync.RWMutex
	policies map[string]region.ResidencyPolicy
}

// New constructs an empty Store.
func New() *Store {
	return &Store{policies: make(map[string]region.ResidencyPolicy)}
}

// Set stores (or replaces) the policy for a tenant. AllowedRegions is
// copied so a later mutation of the caller's slice can't reach into the
// stored policy.
func (s *Store) Set(tenantID string, p region.ResidencyPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[tenantID] = clonePolicy(p)
}

// Delete removes a tenant's policy. After Delete, GetPolicy returns the
// zero (unconstrained) ResidencyPolicy for that tenant. Idempotent.
func (s *Store) Delete(tenantID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, tenantID)
}

// GetPolicy returns the tenant's ResidencyPolicy, or the zero
// (unconstrained) policy when absent — never an error. Callers treat "no
// policy" and "unconstrained policy" identically.
func (s *Store) GetPolicy(_ context.Context, tenantID string) (region.ResidencyPolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.policies[tenantID]
	if !ok {
		return region.ResidencyPolicy{}, nil
	}
	return clonePolicy(p), nil
}

// clonePolicy deep-copies the AllowedRegions slice so the stored policy is
// isolated from caller-side mutation in both directions.
func clonePolicy(p region.ResidencyPolicy) region.ResidencyPolicy {
	if p.AllowedRegions != nil {
		cp := make([]region.ID, len(p.AllowedRegions))
		copy(cp, p.AllowedRegions)
		p.AllowedRegions = cp
	}
	return p
}

// Compile-time interface check.
var _ region.PolicyStore = (*Store)(nil)
