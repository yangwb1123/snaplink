// Package memory is the in-memory [tokenpolicy.Store]: a copy-on-write
// snapshot of the active policy set, seeded from YAML/config at startup and
// atomically replaceable for dynamic updates. Policy sets are small (a
// governance rule list, not per-token state) so the whole set lives in
// memory; there is no eviction — unlike the token-USAGE store this is a
// configuration surface, not a rolling telemetry window.
package memory

import (
	"context"
	"sync"

	"github.com/yangwb1123/snaplink/domains/tokenpolicy"
)

// Store is the in-memory implementation of [tokenpolicy.Store]. Safe for
// concurrent use: Policies is read on the token-issuance hot path while
// Replace swaps the set. The store owns its policy graph: ingress and egress
// both use deep copies so callers cannot mutate an active snapshot.
type Store struct {
	mu       sync.RWMutex
	policies []tokenpolicy.Policy
}

// New returns a Store seeded with the given policies (the variadic form
// suits inline test/config seeding). Pass none for an empty store.
func New(policies ...tokenpolicy.Policy) *Store {
	return &Store{policies: clonePolicies(policies)}
}

// NewFromSlice returns a Store seeded from an existing slice — the natural
// constructor for the output of [tokenpolicy.ParseYAML].
func NewFromSlice(policies []tokenpolicy.Policy) *Store {
	return &Store{policies: clonePolicies(policies)}
}

// Policies returns the active set. The result is READ-ONLY per the
// [tokenpolicy.Store] contract; Replace never mutates a returned slice.
func (s *Store) Policies(_ context.Context) ([]tokenpolicy.Policy, error) {
	s.mu.RLock()
	p := clonePolicies(s.policies)
	s.mu.RUnlock()
	return p, nil
}

// Replace atomically swaps the active policy set — the dynamic-update path
// (e.g. a config reload). The store clones policies before publishing them.
func (s *Store) Replace(policies []tokenpolicy.Policy) {
	cloned := clonePolicies(policies)
	s.mu.Lock()
	s.policies = cloned
	s.mu.Unlock()
}

func clonePolicies(policies []tokenpolicy.Policy) []tokenpolicy.Policy {
	if policies == nil {
		return nil
	}
	cloned := make([]tokenpolicy.Policy, len(policies))
	for i := range policies {
		cloned[i] = clonePolicy(policies[i])
	}
	return cloned
}

func clonePolicy(policy tokenpolicy.Policy) tokenpolicy.Policy {
	policy.SubjectRoles = cloneStrings(policy.SubjectRoles)
	policy.Scopes = cloneStrings(policy.Scopes)
	policy.BlockScopeCombos = cloneStringGroups(policy.BlockScopeCombos)
	return policy
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func cloneStringGroups(groups [][]string) [][]string {
	if groups == nil {
		return nil
	}
	cloned := make([][]string, len(groups))
	for i := range groups {
		cloned[i] = cloneStrings(groups[i])
	}
	return cloned
}

var _ tokenpolicy.Store = (*Store)(nil)
