package memorystorecredential

import (
	"context"
	"sort"
	"sync"

	"github.com/snaplink/sso/shared/core/corecredential"
)

// MemoryCredentialStatusStore is an in-process
// [corecredential.CredentialStatusStore]. Governance metadata only — never
// holds secret material — so a plain map+mutex is the right shape; a
// multi-replica deployment wanting one shared rotation-inventory view across
// replicas needs the sqlite peer instead.
type MemoryCredentialStatusStore struct {
	mu sync.Mutex
	// versions is keyed by (type, id) so ListByType can select+sort just the
	// one credential class without scanning every tracked version.
	versions map[corecredential.CredentialType]map[string]corecredential.CredentialMeta
}

// NewMemoryCredentialStatusStore returns an empty store.
func NewMemoryCredentialStatusStore() *MemoryCredentialStatusStore {
	return &MemoryCredentialStatusStore{
		versions: make(map[corecredential.CredentialType]map[string]corecredential.CredentialMeta),
	}
}

// Upsert inserts or replaces the record for (meta.Type, meta.ID).
func (m *MemoryCredentialStatusStore) Upsert(_ context.Context, meta corecredential.CredentialMeta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket, ok := m.versions[meta.Type]
	if !ok {
		bucket = make(map[string]corecredential.CredentialMeta)
		m.versions[meta.Type] = bucket
	}
	bucket[meta.ID] = meta
	return nil
}

// Get returns one version's record. ErrCredentialNotFound when the (type, id)
// pair is unknown — the oracle-safe shape every CredentialStatusStore backend
// must share since the caller may be an admin surface probing an id.
func (m *MemoryCredentialStatusStore) Get(_ context.Context, credType corecredential.CredentialType, id string) (corecredential.CredentialMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	meta, ok := m.versions[credType][id]
	if !ok {
		return corecredential.CredentialMeta{}, corecredential.ErrCredentialNotFound
	}
	return meta, nil
}

// ListByType returns every tracked version of one credential class, ordered
// by ascending Version so "current" is last.
func (m *MemoryCredentialStatusStore) ListByType(_ context.Context, credType corecredential.CredentialType) ([]corecredential.CredentialMeta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket := m.versions[credType]
	out := make([]corecredential.CredentialMeta, 0, len(bucket))
	for _, meta := range bucket {
		out = append(out, meta)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, nil
}

// UpdateStatus transitions one version's lifecycle status. ErrCredentialNotFound
// when the (type, id) pair is unknown.
func (m *MemoryCredentialStatusStore) UpdateStatus(_ context.Context, credType corecredential.CredentialType, id string, status corecredential.CredentialStatus) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	bucket, ok := m.versions[credType]
	if !ok {
		return corecredential.ErrCredentialNotFound
	}
	meta, ok := bucket[id]
	if !ok {
		return corecredential.ErrCredentialNotFound
	}
	meta.Status = status
	bucket[id] = meta
	return nil
}

var _ corecredential.CredentialStatusStore = (*MemoryCredentialStatusStore)(nil)
