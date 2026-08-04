package tenantquota

import (
	"context"
	"database/sql"
	"math"

	"github.com/yangwb1123/snaplink/shared/core"
)

// GetQuotaProjection implements core.TenantQuotaProjectionStore.
func (s *Store) GetQuotaProjection(ctx context.Context, tenantID string) (*core.TenantQuotaProjection, error) {
	if err := validateCall(ctx, tenantID); err != nil {
		return nil, err
	}
	state, err := stateOrZero(readState(ctx, s.db, tenantID))
	if err != nil {
		return nil, err
	}
	quota, err := quotaFromState(state)
	if err != nil {
		return nil, err
	}
	return &core.TenantQuotaProjection{Revision: uint64(state.quotaRevision), Quota: *quota}, nil
}

// ApplyQuotaProjection implements core.TenantQuotaProjectionStore.
func (s *Store) ApplyQuotaProjection(ctx context.Context, tenantID string, projection *core.TenantQuotaProjection) (bool, error) {
	if err := validateCall(ctx, tenantID); err != nil {
		return false, err
	}
	if err := core.ValidateTenantQuotaProjection(projection); err != nil || projection.Revision > math.MaxInt64 {
		if err != nil {
			return false, err
		}
		return false, core.ErrInvalidQuotaOperation
	}
	var applied bool
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		applied, err = applyProjectionLocked(ctx, tx, tenantID, state, projection)
		return err
	})
	return applied, err
}

func applyProjectionLocked(ctx context.Context, tx *sql.Tx, tenantID string, state stateRow, projection *core.TenantQuotaProjection) (bool, error) {
	revision := uint64(state.quotaRevision)
	if projection.Revision < revision {
		return false, nil
	}
	current, err := quotaFromState(state)
	if err != nil {
		return false, err
	}
	if projection.Revision == revision {
		if projection.Quota != *current {
			return false, core.ErrQuotaRevisionConflict
		}
		return false, nil
	}
	quota := projection.Quota
	_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state SET
max_clients = $2, max_users = $3, max_sessions = $4, max_token_rate = $5,
clients_limited = $6, users_limited = $7, sessions_limited = $8,
token_rate_limited = $9, quota_revision = $10 WHERE tenant_id = $1`,
		tenantID, quota.MaxClients, quota.MaxUsers, quota.MaxSessions, quota.MaxTokenRate,
		quota.ClientsLimited, quota.UsersLimited, quota.SessionsLimited,
		quota.TokenRateLimited, projection.Revision)
	return err == nil, err
}
