package memorystoreidentity

import (
	"context"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ResourceLeaseActive reports whether an exact resource identity is currently
// represented in the gauge.
func (s *MemoryTenantQuotaStore) ResourceLeaseActive(
	ctx context.Context,
	tenantID string,
	resource core.ResourceType,
	resourceID string,
) (bool, error) {
	if err := validateResourceLease(ctx, tenantID, resource, resourceID); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryQuotaResource{tenantID: tenantID, resource: resource}
	return s.resourceLeases[key][resourceID], nil
}

// ReconcileResourceSet atomically replaces the gauge and active identities
// under one generation CAS. Removed identities remain false tombstones so a
// late duplicate release cannot decrement the rebuilt counter.
func (s *MemoryTenantQuotaStore) ReconcileResourceSet(
	ctx context.Context,
	tenantID string,
	resource core.ResourceType,
	resourceIDs []string,
	expectedGeneration uint64,
) (uint64, error) {
	ids, err := validateMemoryResourceSet(ctx, tenantID, resource, resourceIDs, expectedGeneration)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryQuotaResource{tenantID: tenantID, resource: resource}
	current := s.generations[key]
	if current != expectedGeneration {
		return current, core.ErrQuotaRevisionConflict
	}
	if err := s.requireGenerationRoomLocked(key); err != nil {
		return current, err
	}
	leases := s.resourceLeases[key]
	if leases == nil {
		leases = make(map[string]bool, len(ids))
		s.resourceLeases[key] = leases
	}
	for id := range leases {
		leases[id] = false
	}
	for id := range ids {
		leases[id] = true
	}
	usage := s.usage[tenantID]
	value, _ := gaugePointers(&usage, &core.TenantQuota{}, resource)
	*value = len(ids)
	s.usage[tenantID] = usage
	s.generations[key]++
	return s.generations[key], nil
}

func validateMemoryResourceSet(
	ctx context.Context,
	tenantID string,
	resource core.ResourceType,
	resourceIDs []string,
	expectedGeneration uint64,
) (map[string]struct{}, error) {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil || expectedGeneration > core.TenantQuotaMaxRevision {
		if err != nil {
			return nil, err
		}
		return nil, core.ErrInvalidQuotaOperation
	}
	ids := make(map[string]struct{}, len(resourceIDs))
	for _, id := range resourceIDs {
		if err := core.ValidateQuotaResourceID(id); err != nil {
			return nil, err
		}
		if _, duplicate := ids[id]; duplicate {
			return nil, core.ErrInvalidQuotaOperation
		}
		ids[id] = struct{}{}
	}
	return ids, nil
}

var _ core.TenantQuotaResourceSetStore = (*MemoryTenantQuotaStore)(nil)
