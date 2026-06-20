package memorystoreidentity

import (
	"context"
	"sync"

	"github.com/snaplink/sso/shared/security"
)

// MemorySubjectClientIndex is the in-process default for
// [security.SubjectClientIndex]. map-of-maps — outer key is subject id,
// inner is the set of client ids that subject has active tokens for.
// No TTL: operators that need bounded lifetime should periodically
// call Forget for stale entries OR swap for a TTL-aware store.
//
// Mutex serializes every operation; for a typical SSO deployment
// (login latency dominates the path), contention is not a concern.
type MemorySubjectClientIndex struct {
	mu      sync.Mutex
	entries map[string]map[string]struct{}
}

func NewMemorySubjectClientIndex() *MemorySubjectClientIndex {
	return &MemorySubjectClientIndex{entries: make(map[string]map[string]struct{})}
}

func (m *MemorySubjectClientIndex) RecordAccess(_ context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.entries[subject]
	if !ok {
		set = make(map[string]struct{})
		m.entries[subject] = set
	}
	set[clientID] = struct{}{}
	return nil
}

func (m *MemorySubjectClientIndex) ListClients(_ context.Context, subject string) ([]string, error) {
	if subject == "" {
		return nil, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.entries[subject]
	if !ok || len(set) == 0 {
		return nil, nil
	}
	out := make([]string, 0, len(set))
	for cid := range set {
		out = append(out, cid)
	}
	return out, nil
}

func (m *MemorySubjectClientIndex) Forget(_ context.Context, subject, clientID string) error {
	if subject == "" || clientID == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	set, ok := m.entries[subject]
	if !ok {
		return nil
	}
	delete(set, clientID)
	if len(set) == 0 {
		delete(m.entries, subject)
	}
	return nil
}

var _ security.SubjectClientIndex = (*MemorySubjectClientIndex)(nil)
