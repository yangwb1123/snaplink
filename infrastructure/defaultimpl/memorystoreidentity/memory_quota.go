package memorystoreidentity

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// MemoryTenantQuotaStore is an in-memory implementation of core.TenantQuotaStore.
// Suitable for tests and single-process deployments; not durable across restarts.
// Thread-safe.
type MemoryTenantQuotaStore struct {
	mu             sync.Mutex
	quotas         map[string]core.TenantQuota
	quotaRevisions map[string]uint64
	usage          map[string]core.TenantUsage
	resourceLeases map[memoryQuotaResource]map[string]bool
	generations    map[memoryQuotaResource]uint64
	tokenRates     map[string]*memoryTokenRate
	now            func() time.Time
}

type memoryQuotaResource struct {
	tenantID string
	resource core.ResourceType
}

type memoryTokenRate struct {
	clockSecond int64
	windows     map[int64]int64
}

// NewMemoryTenantQuotaStore returns an empty MemoryTenantQuotaStore.
func NewMemoryTenantQuotaStore() *MemoryTenantQuotaStore {
	return newMemoryTenantQuotaStore(time.Now)
}

func newMemoryTenantQuotaStore(now func() time.Time) *MemoryTenantQuotaStore {
	return &MemoryTenantQuotaStore{
		quotas:         make(map[string]core.TenantQuota),
		quotaRevisions: make(map[string]uint64),
		usage:          make(map[string]core.TenantUsage),
		resourceLeases: make(map[memoryQuotaResource]map[string]bool),
		generations:    make(map[memoryQuotaResource]uint64),
		tokenRates:     make(map[string]*memoryTokenRate),
		now:            now,
	}
}

// GetQuota implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) GetQuota(ctx context.Context, tenantID string) (*core.TenantQuota, error) {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	quota := s.quotas[tenantID]
	return &quota, nil
}

// GetUsage implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) GetUsage(ctx context.Context, tenantID string) (*core.TenantUsage, error) {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	usage := s.usage[tenantID]
	usage.TokenRate = s.tokenRateLocked(tenantID)
	return &usage, nil
}

// IncrementUsage implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) IncrementUsage(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	if err := validateQuotaMutation(ctx, tenantID, resource, delta); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if resource == core.ResourceTokenRate {
		return s.incrementTokenRateLocked(tenantID, delta)
	}
	usage := s.usage[tenantID]
	quota := s.quotas[tenantID]
	value, limit := gaugePointers(&usage, &quota, resource)
	key := memoryQuotaResource{tenantID: tenantID, resource: resource}
	if err := s.requireGenerationRoomLocked(key); err != nil {
		return err
	}
	_, limited, _ := quota.ResourceLimit(resource)
	if err := incrementGauge(value, limit, limited, delta); err != nil {
		return err
	}
	s.usage[tenantID] = usage
	s.generations[key]++
	return nil
}

// DecrementUsage implements core.TenantQuotaStore. Floors at 0 — a caller
// compensating an IncrementUsage it never actually charged (e.g. a double
// rollback) must not push the counter negative.
func (s *MemoryTenantQuotaStore) DecrementUsage(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	if err := validateQuotaMutation(ctx, tenantID, resource, delta); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if resource == core.ResourceTokenRate {
		s.decrementTokenRateLocked(tenantID, delta)
		return nil
	}
	usage := s.usage[tenantID]
	value, _ := gaugePointers(&usage, &core.TenantQuota{}, resource)
	key := memoryQuotaResource{tenantID: tenantID, resource: resource}
	if err := s.requireGenerationRoomLocked(key); err != nil {
		return err
	}
	*value = max(0, *value-int(delta))
	s.usage[tenantID] = usage
	s.generations[key]++
	return nil
}

// SetQuota implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) SetQuota(ctx context.Context, tenantID string, quota *core.TenantQuota) error {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return err
	}
	if err := core.ValidateTenantQuota(quota); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quotaRevisions[tenantID] > 0 {
		return core.ErrQuotaRevisionConflict
	}
	s.quotas[tenantID] = *quota
	return nil
}

// ResetUsage implements core.TenantQuotaStore.
func (s *MemoryTenantQuotaStore) ResetUsage(ctx context.Context, tenantID string) error {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, resource := range memoryGaugeResources() {
		key := memoryQuotaResource{tenantID: tenantID, resource: resource}
		if err := s.requireGenerationRoomLocked(key); err != nil {
			return err
		}
	}
	delete(s.usage, tenantID)
	delete(s.tokenRates, tenantID)
	for _, resource := range memoryGaugeResources() {
		key := memoryQuotaResource{tenantID: tenantID, resource: resource}
		delete(s.resourceLeases, key)
		s.generations[key]++
	}
	return nil
}

// ReserveResource implements core.TenantQuotaResourceStore.
func (s *MemoryTenantQuotaStore) ReserveResource(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) (bool, error) {
	if err := validateResourceLease(ctx, tenantID, resource, resourceID); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryQuotaResource{tenantID: tenantID, resource: resource}
	leases := s.resourceLeases[key]
	if leases != nil && leases[resourceID] {
		return false, nil
	}
	if err := s.requireGenerationRoomLocked(key); err != nil {
		return false, err
	}
	usage, quota := s.usage[tenantID], s.quotas[tenantID]
	value, limit := gaugePointers(&usage, &quota, resource)
	_, limited, _ := quota.ResourceLimit(resource)
	if err := incrementGauge(value, limit, limited, 1); err != nil {
		return false, err
	}
	if leases == nil {
		leases = make(map[string]bool)
		s.resourceLeases[key] = leases
	}
	leases[resourceID] = true
	s.usage[tenantID] = usage
	s.generations[key]++
	return true, nil
}

// ReleaseResource implements core.TenantQuotaResourceStore. A first release
// without a prior lease consumes one reconciled/legacy baseline unit and
// leaves a tombstone, making retries harmless.
func (s *MemoryTenantQuotaStore) ReleaseResource(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) (bool, error) {
	if err := validateResourceLease(ctx, tenantID, resource, resourceID); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := memoryQuotaResource{tenantID: tenantID, resource: resource}
	leases := s.resourceLeases[key]
	if active, exists := leases[resourceID]; exists && !active {
		return false, nil
	}
	if err := s.requireGenerationRoomLocked(key); err != nil {
		return false, err
	}
	if leases == nil {
		leases = make(map[string]bool)
		s.resourceLeases[key] = leases
	}
	leases[resourceID] = false
	usage := s.usage[tenantID]
	value, _ := gaugePointers(&usage, &core.TenantQuota{}, resource)
	*value = max(0, *value-1)
	s.usage[tenantID] = usage
	s.generations[key]++
	return true, nil
}

// GetResourceUsage implements core.TenantQuotaResourceStore.
func (s *MemoryTenantQuotaStore) GetResourceUsage(ctx context.Context, tenantID string, resource core.ResourceType) (*core.TenantResourceUsage, error) {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	usage := s.usage[tenantID]
	value, _ := gaugePointers(&usage, &core.TenantQuota{}, resource)
	key := memoryQuotaResource{tenantID: tenantID, resource: resource}
	return &core.TenantResourceUsage{Value: *value, Generation: s.generations[key]}, nil
}

// ReconcileUsage implements core.TenantQuotaResourceStore.
func (s *MemoryTenantQuotaStore) ReconcileUsage(ctx context.Context, tenantID string, resource core.ResourceType, absolute int, expectedGeneration uint64) (uint64, error) {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil || absolute < 0 || expectedGeneration > core.TenantQuotaMaxRevision {
		if err != nil {
			return 0, err
		}
		return 0, core.ErrInvalidQuotaOperation
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
	usage := s.usage[tenantID]
	value, _ := gaugePointers(&usage, &core.TenantQuota{}, resource)
	*value = absolute
	s.usage[tenantID] = usage
	s.generations[key]++
	return s.generations[key], nil
}

// GetQuotaProjection implements core.TenantQuotaProjectionStore.
func (s *MemoryTenantQuotaStore) GetQuotaProjection(ctx context.Context, tenantID string) (*core.TenantQuotaProjection, error) {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return &core.TenantQuotaProjection{Revision: s.quotaRevisions[tenantID], Quota: s.quotas[tenantID]}, nil
}

// ApplyQuotaProjection implements core.TenantQuotaProjectionStore.
func (s *MemoryTenantQuotaStore) ApplyQuotaProjection(ctx context.Context, tenantID string, projection *core.TenantQuotaProjection) (bool, error) {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return false, err
	}
	if err := core.ValidateTenantQuotaProjection(projection); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current := s.quotaRevisions[tenantID]
	if projection.Revision < current {
		return false, nil
	}
	if projection.Revision == current {
		if projection.Quota != s.quotas[tenantID] {
			return false, core.ErrQuotaRevisionConflict
		}
		return false, nil
	}
	s.quotas[tenantID] = projection.Quota
	s.quotaRevisions[tenantID] = projection.Revision
	return true, nil
}

// CleanupTokenRateWindows implements core.TenantQuotaWindowCleaner.
func (s *MemoryTenantQuotaStore) CleanupTokenRateWindows(ctx context.Context, now time.Time) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var removed int64
	for _, state := range s.tokenRates {
		second := max(now.UTC().Unix(), state.clockSecond)
		state.clockSecond = second
		removed += cleanupMemoryWindows(state, second)
	}
	return removed, nil
}

func validateQuotaCall(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return core.ValidateQuotaTenantID(tenantID)
}

func validateQuotaMutation(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return err
	}
	if err := core.ValidateQuotaResource(resource); err != nil {
		return err
	}
	return core.ValidateQuotaDelta(delta)
}

func validateGaugeCall(ctx context.Context, tenantID string, resource core.ResourceType) error {
	if err := validateQuotaCall(ctx, tenantID); err != nil {
		return err
	}
	return core.ValidateQuotaGaugeResource(resource)
}

func validateResourceLease(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) error {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil {
		return err
	}
	return core.ValidateQuotaResourceID(resourceID)
}

func gaugePointers(usage *core.TenantUsage, quota *core.TenantQuota, resource core.ResourceType) (*int, int) {
	switch resource {
	case core.ResourceClients:
		return &usage.Clients, quota.MaxClients
	case core.ResourceUsers:
		return &usage.Users, quota.MaxUsers
	default:
		return &usage.Sessions, quota.MaxSessions
	}
}

func incrementGauge(value *int, limit int, limited bool, delta int64) error {
	if int64(*value) > int64(math.MaxInt)-delta {
		return core.ErrInvalidQuotaOperation
	}
	next := *value + int(delta)
	if limited && next > limit {
		return core.ErrQuotaExceeded
	}
	*value = next
	return nil
}

func memoryGaugeResources() []core.ResourceType {
	return []core.ResourceType{core.ResourceClients, core.ResourceUsers, core.ResourceSessions}
}

func (s *MemoryTenantQuotaStore) requireGenerationRoomLocked(key memoryQuotaResource) error {
	if s.generations[key] == core.TenantQuotaMaxRevision {
		return core.ErrInvalidQuotaOperation
	}
	return nil
}

func (s *MemoryTenantQuotaStore) tokenStateLocked(tenantID string) (*memoryTokenRate, int64) {
	state := s.tokenRates[tenantID]
	if state == nil {
		state = &memoryTokenRate{windows: make(map[int64]int64)}
		s.tokenRates[tenantID] = state
	}
	second := max(s.now().UTC().Unix(), state.clockSecond)
	state.clockSecond = second
	cleanupMemoryWindows(state, second)
	return state, second
}

func cleanupMemoryWindows(state *memoryTokenRate, second int64) int64 {
	var removed int64
	cutoff := second - core.TenantQuotaTokenWindowSeconds + 1
	for window := range state.windows {
		if window < cutoff {
			delete(state.windows, window)
			removed++
		}
	}
	return removed
}

func (s *MemoryTenantQuotaStore) tokenRateLocked(tenantID string) float64 {
	state, _ := s.tokenStateLocked(tenantID)
	return float64(sumMemoryWindows(state)) / float64(core.TenantQuotaTokenWindowSeconds)
}

func sumMemoryWindows(state *memoryTokenRate) int64 {
	var total int64
	for _, quantity := range state.windows {
		total += quantity
	}
	return total
}

func (s *MemoryTenantQuotaStore) incrementTokenRateLocked(tenantID string, delta int64) error {
	state, second := s.tokenStateLocked(tenantID)
	total := sumMemoryWindows(state)
	if total > math.MaxInt64-delta {
		return core.ErrInvalidQuotaOperation
	}
	limit := s.quotas[tenantID].MaxTokenRate
	_, limited, _ := s.quotas[tenantID].ResourceLimit(core.ResourceTokenRate)
	if limited && total+delta > int64(limit)*core.TenantQuotaTokenWindowSeconds {
		return core.ErrQuotaExceeded
	}
	state.windows[second] += delta
	return nil
}

func (s *MemoryTenantQuotaStore) decrementTokenRateLocked(tenantID string, delta int64) {
	state, second := s.tokenStateLocked(tenantID)
	for offset := int64(0); offset < core.TenantQuotaTokenWindowSeconds && delta > 0; offset++ {
		window := second - offset
		quantity := state.windows[window]
		take := min(quantity, delta)
		state.windows[window] -= take
		delta -= take
		if state.windows[window] == 0 {
			delete(state.windows, window)
		}
	}
}

// compile-time guard
var _ core.TenantQuotaStore = (*MemoryTenantQuotaStore)(nil)
var _ core.TenantQuotaResourceStore = (*MemoryTenantQuotaStore)(nil)
var _ core.TenantQuotaProjectionStore = (*MemoryTenantQuotaStore)(nil)
var _ core.TenantQuotaWindowCleaner = (*MemoryTenantQuotaStore)(nil)
