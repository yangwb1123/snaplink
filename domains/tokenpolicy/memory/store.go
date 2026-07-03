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

	"github.com/snaplink/sso/domains/tokenpolicy"
)

// Store is the in-memory implementation of [tokenpolicy.Store]. Safe for
// concurrent use: Policies is read on the token-issuance hot path while
// Replace swaps the set. Replace assigns a NEW slice rather than mutating in
// place, so a reader holding a previously returned slice is never disturbed
// (copy-on-write) — which is why Policies can return the backing slice
// without copying.
type Store struct {
	mu       sync.RWMutex
	policies []tokenpolicy.Policy
}

// New returns a Store seeded with the given policies (the variadic form
// suits inline test/config seeding). Pass none for an empty store.
func New(policies ...tokenpolicy.Policy) *Store {
	return &Store{policies: policies}
}

// NewFromSlice returns a Store seeded from an existing slice — the natural
// constructor for the output of [tokenpolicy.ParseYAML].
func NewFromSlice(policies []tokenpolicy.Policy) *Store {
	return &Store{policies: policies}
}

// Policies returns the active set. The result is READ-ONLY per the
// [tokenpolicy.Store] contract; Replace never mutates a returned slice.
func (s *Store) Policies(_ context.Context) ([]tokenpolicy.Policy, error) {
	s.mu.RLock()
	p := s.policies
	s.mu.RUnlock()
	return p, nil
}

// Replace atomically swaps the active policy set — the dynamic-update path
// (e.g. a config reload). The caller MUST NOT mutate policies afterward.
func (s *Store) Replace(policies []tokenpolicy.Policy) {
	s.mu.Lock()
	s.policies = policies
	s.mu.Unlock()
}

var _ tokenpolicy.Store = (*Store)(nil)
