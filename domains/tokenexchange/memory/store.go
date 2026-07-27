// Package memory is the in-memory reference [tokenexchange.Policy]: an
// ordered, atomically-replaceable rule list evaluated via
// [tokenexchange.Evaluate]. Mirrors domains/tokenpolicy/memory's
// copy-on-write discipline — small, admin-sized rule sets, no eviction.
package memory

import (
	"context"
	"sync"

	"github.com/yangwb1123/snaplink/domains/tokenexchange"
)

// Store is the in-memory implementation of [tokenexchange.Policy]. Safe for
// concurrent use: Allow is read on the token-exchange hot path (opt-in)
// while Replace swaps the rule set. Replace assigns a NEW slice rather than
// mutating in place (copy-on-write), so a concurrent Allow call is never
// disturbed mid-evaluation.
type Store struct {
	mu           sync.RWMutex
	rules        []tokenexchange.Rule
	defaultAllow bool
}

// New returns a Store seeded with the given defaultAllow fallback and rules
// (the variadic form suits inline test/config seeding). defaultAllow governs
// hops that match no rule — true keeps exchange behavior unchanged (every
// hop allowed) except for explicit Deny rules; false is a default-deny
// allowlist model where only explicit Allow rules pass.
func New(defaultAllow bool, rules ...tokenexchange.Rule) *Store {
	return &Store{defaultAllow: defaultAllow, rules: rules}
}

// Allow implements [tokenexchange.Policy]. Never returns an error — the
// in-memory matcher is pure and can't fail; Allow is still typed to return
// one so callers wired against the interface behave identically against a
// future I/O-backed Policy.
func (s *Store) Allow(_ context.Context, hop tokenexchange.Hop) (bool, error) {
	s.mu.RLock()
	rules, defaultAllow := s.rules, s.defaultAllow
	s.mu.RUnlock()
	return tokenexchange.Evaluate(hop, rules, defaultAllow), nil
}

// Replace atomically swaps the active rule set — the dynamic-update path
// (e.g. an admin API or config reload). The caller MUST NOT mutate rules
// afterward.
func (s *Store) Replace(rules []tokenexchange.Rule) {
	s.mu.Lock()
	s.rules = rules
	s.mu.Unlock()
}

// Rules returns a snapshot of the active rule set (read-only for the
// caller).
func (s *Store) Rules() []tokenexchange.Rule {
	s.mu.RLock()
	r := s.rules
	s.mu.RUnlock()
	return r
}

var _ tokenexchange.Policy = (*Store)(nil)
