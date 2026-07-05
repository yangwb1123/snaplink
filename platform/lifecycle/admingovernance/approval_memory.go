package admingovernance

import (
	"context"
	"sort"
	"sync"
	"time"
)

// MemoryApprovalStore is an in-process, non-persistent ApprovalStore.
// Suitable for single-replica deployments, dev, and tests — the same
// tier every other opt-in admin governance store in this SDK ships at
// (mirrors memorystoreidentity.MemoryBreakGlassStore).
type MemoryApprovalStore struct {
	mu      sync.RWMutex
	changes map[string]ChangeRequest
}

var _ ApprovalStore = (*MemoryApprovalStore)(nil)

// NewMemoryApprovalStore returns an empty MemoryApprovalStore.
func NewMemoryApprovalStore() *MemoryApprovalStore {
	return &MemoryApprovalStore{changes: make(map[string]ChangeRequest)}
}

func (m *MemoryApprovalStore) Propose(_ context.Context, c ChangeRequest) (ChangeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now()
	}
	c.Status = ChangeStatusPending
	m.changes[c.ID] = c
	return c, nil
}

func (m *MemoryApprovalStore) Get(_ context.Context, id string) (ChangeRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.changes[id]
	if !ok {
		return ChangeRequest{}, ErrChangeNotFound
	}
	return c, nil
}

func (m *MemoryApprovalStore) List(_ context.Context) ([]ChangeRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ChangeRequest, 0, len(m.changes))
	for _, c := range m.changes {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (m *MemoryApprovalStore) Approve(_ context.Context, id, approverID string) (ChangeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.changes[id]
	if !ok {
		return ChangeRequest{}, ErrChangeNotFound
	}
	if c.Status != ChangeStatusPending {
		return ChangeRequest{}, ErrChangeNotPending
	}
	// The self-approval rejection lives here (not only in the handler) so
	// the two-person rule holds for every caller of the SPI, mirroring
	// MemoryBreakGlassStore.Approve.
	if approverID == "" || approverID == c.ProposedBy {
		return ChangeRequest{}, ErrChangeSelfApproval
	}
	c.Status = ChangeStatusApproved
	c.ApprovedBy = approverID
	c.DecidedAt = time.Now()
	m.changes[id] = c
	return c, nil
}

func (m *MemoryApprovalStore) Reject(_ context.Context, id, approverID string) (ChangeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.changes[id]
	if !ok {
		return ChangeRequest{}, ErrChangeNotFound
	}
	if c.Status != ChangeStatusPending {
		return ChangeRequest{}, ErrChangeNotPending
	}
	c.Status = ChangeStatusRejected
	c.ApprovedBy = approverID
	c.DecidedAt = time.Now()
	m.changes[id] = c
	return c, nil
}

func (m *MemoryApprovalStore) MarkApplied(_ context.Context, id string) (ChangeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.changes[id]
	if !ok || c.Status != ChangeStatusApproved {
		return c, nil
	}
	c.Status = ChangeStatusApplied
	m.changes[id] = c
	return c, nil
}

func (m *MemoryApprovalStore) MarkFailed(_ context.Context, id, note string) (ChangeRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.changes[id]
	if !ok || c.Status != ChangeStatusApproved {
		return c, nil
	}
	c.Status = ChangeStatusFailed
	c.FailureNote = note
	m.changes[id] = c
	return c, nil
}
