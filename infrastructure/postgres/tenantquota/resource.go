package tenantquota

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ReserveResource implements core.TenantQuotaResourceStore.
func (s *Store) ReserveResource(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) (bool, error) {
	if err := validateResourceCall(ctx, tenantID, resource, resourceID); err != nil {
		return false, err
	}
	var reserved bool
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		active, exists, err := readLease(ctx, tx, tenantID, resource, resourceID)
		if err != nil || exists && active {
			return err
		}
		if err := reserveResourceLocked(ctx, tx, tenantID, resource, resourceID, state); err != nil {
			return err
		}
		reserved = true
		return nil
	})
	return reserved, err
}

func reserveResourceLocked(ctx context.Context, tx *sql.Tx, tenantID string, resource core.ResourceType, resourceID string, state stateRow) error {
	column, generationColumn, current, limit, limited, generation := gaugeState(state, resource)
	if generation == math.MaxInt64 || current == math.MaxInt64 {
		return core.ErrInvalidQuotaOperation
	}
	if limited && current+1 > limit {
		return core.ErrQuotaExceeded
	}
	if err := writeLease(ctx, tx, tenantID, resource, resourceID, true); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE tenant_quota_state SET `+column+` = $2, `+
		generationColumn+` = $3 WHERE tenant_id = $1`, tenantID, current+1, generation+1)
	return err
}

// ReleaseResource implements core.TenantQuotaResourceStore.
func (s *Store) ReleaseResource(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) (bool, error) {
	if err := validateResourceCall(ctx, tenantID, resource, resourceID); err != nil {
		return false, err
	}
	var released bool
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		active, exists, err := readLease(ctx, tx, tenantID, resource, resourceID)
		if err != nil || exists && !active {
			return err
		}
		if err := releaseResourceLocked(ctx, tx, tenantID, resource, resourceID, state); err != nil {
			return err
		}
		released = true
		return nil
	})
	return released, err
}

func releaseResourceLocked(ctx context.Context, tx *sql.Tx, tenantID string, resource core.ResourceType, resourceID string, state stateRow) error {
	column, generationColumn, current, _, _, generation := gaugeState(state, resource)
	if generation == math.MaxInt64 {
		return core.ErrInvalidQuotaOperation
	}
	if err := writeLease(ctx, tx, tenantID, resource, resourceID, false); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE tenant_quota_state SET `+column+` = $2, `+
		generationColumn+` = $3 WHERE tenant_id = $1`, tenantID, max(int64(0), current-1), generation+1)
	return err
}

func readLease(ctx context.Context, tx *sql.Tx, tenantID string, resource core.ResourceType, resourceID string) (bool, bool, error) {
	var active bool
	err := tx.QueryRowContext(ctx, `SELECT active FROM tenant_quota_resource_leases
WHERE tenant_id = $1 AND resource = $2 AND resource_id = $3`, tenantID, resource, resourceID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, false, nil
	}
	return active, err == nil, err
}

func writeLease(ctx context.Context, tx *sql.Tx, tenantID string, resource core.ResourceType, resourceID string, active bool) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_quota_resource_leases
(tenant_id, resource, resource_id, active) VALUES ($1, $2, $3, $4)
ON CONFLICT (tenant_id, resource, resource_id) DO UPDATE SET active = EXCLUDED.active`,
		tenantID, resource, resourceID, active)
	return err
}

// GetResourceUsage implements core.TenantQuotaResourceStore.
func (s *Store) GetResourceUsage(ctx context.Context, tenantID string, resource core.ResourceType) (*core.TenantResourceUsage, error) {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil {
		return nil, err
	}
	state, err := stateOrZero(readState(ctx, s.db, tenantID))
	if err != nil {
		return nil, err
	}
	_, _, current, _, _, generation := gaugeState(state, resource)
	return &core.TenantResourceUsage{Value: int(current), Generation: uint64(generation)}, nil
}

// ReconcileUsage implements core.TenantQuotaResourceStore.
func (s *Store) ReconcileUsage(ctx context.Context, tenantID string, resource core.ResourceType, absolute int, expectedGeneration uint64) (uint64, error) {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil || absolute < 0 || expectedGeneration > math.MaxInt64 {
		if err != nil {
			return 0, err
		}
		return 0, core.ErrInvalidQuotaOperation
	}
	var next uint64
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		column, generationColumn, _, _, _, generation := gaugeState(state, resource)
		if uint64(generation) != expectedGeneration {
			next = uint64(generation)
			return core.ErrQuotaRevisionConflict
		}
		if generation == math.MaxInt64 {
			return core.ErrInvalidQuotaOperation
		}
		next = uint64(generation + 1)
		_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state SET `+column+` = $2, `+
			generationColumn+` = $3 WHERE tenant_id = $1`, tenantID, absolute, next)
		return err
	})
	return next, err
}

// ResourceLeaseActive reports whether resourceID currently contributes to the
// durable gauge.
func (s *Store) ResourceLeaseActive(
	ctx context.Context,
	tenantID string,
	resource core.ResourceType,
	resourceID string,
) (bool, error) {
	if err := validateResourceCall(ctx, tenantID, resource, resourceID); err != nil {
		return false, err
	}
	var active bool
	err := s.db.QueryRowContext(ctx, `SELECT active FROM tenant_quota_resource_leases
WHERE tenant_id = $1 AND resource = $2 AND resource_id = $3`, tenantID, resource, resourceID).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return active, err
}

// ReconcileResourceSet replaces both the exact active identities and counter
// under the resource generation CAS.
func (s *Store) ReconcileResourceSet(
	ctx context.Context,
	tenantID string,
	resource core.ResourceType,
	resourceIDs []string,
	expectedGeneration uint64,
) (uint64, error) {
	ids, err := validateResourceSet(ctx, tenantID, resource, resourceIDs, expectedGeneration)
	if err != nil {
		return 0, err
	}
	var next uint64
	err = runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		column, generationColumn, _, _, _, generation := gaugeState(state, resource)
		if uint64(generation) != expectedGeneration {
			next = uint64(generation)
			return core.ErrQuotaRevisionConflict
		}
		if generation == math.MaxInt64 {
			return core.ErrInvalidQuotaOperation
		}
		if err := replaceResourceLeasesLocked(ctx, tx, tenantID, resource, ids); err != nil {
			return err
		}
		next = uint64(generation + 1)
		_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state SET `+column+` = $2, `+
			generationColumn+` = $3 WHERE tenant_id = $1`, tenantID, len(ids), next)
		return err
	})
	return next, err
}

func replaceResourceLeasesLocked(
	ctx context.Context,
	tx *sql.Tx,
	tenantID string,
	resource core.ResourceType,
	ids map[string]struct{},
) error {
	if _, err := tx.ExecContext(ctx, `UPDATE tenant_quota_resource_leases SET active = FALSE
WHERE tenant_id = $1 AND resource = $2 AND active = TRUE`, tenantID, resource); err != nil {
		return err
	}
	for id := range ids {
		if err := writeLease(ctx, tx, tenantID, resource, id, true); err != nil {
			return err
		}
	}
	return nil
}

func validateResourceSet(
	ctx context.Context,
	tenantID string,
	resource core.ResourceType,
	resourceIDs []string,
	expectedGeneration uint64,
) (map[string]struct{}, error) {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil || expectedGeneration > math.MaxInt64 {
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

func validateGaugeCall(ctx context.Context, tenantID string, resource core.ResourceType) error {
	if err := validateCall(ctx, tenantID); err != nil {
		return err
	}
	return core.ValidateQuotaGaugeResource(resource)
}

func validateResourceCall(ctx context.Context, tenantID string, resource core.ResourceType, resourceID string) error {
	if err := validateGaugeCall(ctx, tenantID, resource); err != nil {
		return err
	}
	return core.ValidateQuotaResourceID(resourceID)
}

var _ core.TenantQuotaResourceSetStore = (*Store)(nil)
