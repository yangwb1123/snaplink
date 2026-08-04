package usageledger

import (
	"context"
	"sort"
)

// NewMemorySourceBindingStore returns the same in-memory aggregate used for
// usage writes. Sharing one mutex makes evidence revalidation atomic with the
// mutation rather than leaving a resolve-to-write disable race.
func NewMemorySourceBindingStore() *MemoryStore {
	return NewMemoryStore()
}

func (s *MemoryStore) SaveSourceBinding(
	ctx context.Context, binding *SourceBinding, expectedRevision uint64,
) (*SourceBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.bindings[binding.ID]
	if !validBindingRevision(current, exists, binding, expectedRevision) {
		return nil, ErrSourceBindingConflict
	}
	if exists && !sameBindingIdentity(current, binding) {
		return nil, ErrSourceBindingConflict
	}
	if binding.Enabled && s.hasOtherEnabledClientLocked(binding.ClientID, binding.ID) {
		return nil, ErrSourceBindingConflict
	}
	s.bindings[binding.ID] = cloneSourceBinding(binding)
	return cloneSourceBinding(binding), nil
}

func validBindingRevision(
	current *SourceBinding, exists bool, proposed *SourceBinding, expected uint64,
) bool {
	if !exists {
		return expected == 0 && proposed.Revision == 1
	}
	return current.Revision == expected && proposed.Revision == expected+1 &&
		proposed.CreatedAt.Equal(current.CreatedAt)
}

func sameBindingIdentity(left, right *SourceBinding) bool {
	return left.ClientID == right.ClientID && left.TenantID == right.TenantID &&
		left.SourceSystem == right.SourceSystem
}

func (s *MemoryStore) hasOtherEnabledClientLocked(clientID, exceptID string) bool {
	for id, binding := range s.bindings {
		if id != exceptID && binding.Enabled && binding.ClientID == clientID {
			return true
		}
	}
	return false
}

func (s *MemoryStore) ListSourceBindingsByClient(
	ctx context.Context, clientID string,
) ([]*SourceBinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*SourceBinding, 0)
	for _, binding := range s.bindings {
		if binding.ClientID == clientID {
			result = append(result, cloneSourceBinding(binding))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ID < result[right].ID })
	return result, nil
}

func (s *MemoryStore) validateEvidenceLocked(
	evidence *SourceBindingEvidence, tenantID, sourceSystem string, dimension Dimension,
) error {
	if evidence == nil {
		return nil
	}
	if evidence.Validate() != nil {
		return ErrSourceBindingUnauthorized
	}
	binding := s.bindings[evidence.BindingID]
	if evidence.TenantID != tenantID || evidence.SourceSystem != sourceSystem ||
		binding == nil || !binding.Enabled || binding.ClientID != evidence.ClientID ||
		binding.TenantID != evidence.TenantID || binding.SourceSystem != evidence.SourceSystem ||
		binding.Revision != evidence.Revision || !binding.Allows(dimension) {
		return ErrSourceBindingUnauthorized
	}
	return nil
}

var _ SourceBindingStore = (*MemoryStore)(nil)
