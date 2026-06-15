package defaultimpl

import (
	"context"
	"sync"

	"github.com/snaplink/sso/core"
)

// MemoryInvitationStore is an in-memory core.InvitationStore for org
// invitations. Single-process only; multi-replica needs the sqlite peer.
// Consume is destructive (single-use).
type MemoryInvitationStore struct {
	mu    sync.Mutex
	invts map[string]*core.Invitation
}

// NewMemoryInvitationStore returns an empty store.
func NewMemoryInvitationStore() *MemoryInvitationStore {
	return &MemoryInvitationStore{invts: make(map[string]*core.Invitation)}
}

// Issue stores a copy of the invitation keyed by its token value.
func (m *MemoryInvitationStore) Issue(_ context.Context, inv *core.Invitation) error {
	cp := *inv
	m.mu.Lock()
	m.invts[inv.Token] = &cp
	m.mu.Unlock()
	return nil
}

// Consume atomically deletes and returns the invitation. Missing or expired
// entries return core.ErrInvitationNotFound (expired rows are deleted).
func (m *MemoryInvitationStore) Consume(_ context.Context, token string) (*core.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inv, ok := m.invts[token]
	if !ok {
		return nil, core.ErrInvitationNotFound
	}
	delete(m.invts, token)
	if inv.IsExpired() {
		return nil, core.ErrInvitationNotFound
	}
	return inv, nil
}

// ListByTenant returns copies of the non-expired pending invitations for an org
// (admin roster view; the caller projects safe metadata only).
func (m *MemoryInvitationStore) ListByTenant(_ context.Context, tenantID string) ([]*core.Invitation, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*core.Invitation
	for _, inv := range m.invts {
		if inv.TenantID == tenantID && !inv.IsExpired() {
			cp := *inv
			out = append(out, &cp)
		}
	}
	return out, nil
}

var _ core.InvitationStore = (*MemoryInvitationStore)(nil)
