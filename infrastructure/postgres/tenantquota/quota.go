package tenantquota

import (
	"context"
	"database/sql"

	"github.com/yangwb1123/snaplink/shared/core"
)

// GetQuota implements core.TenantQuotaStore.
func (s *Store) GetQuota(ctx context.Context, tenantID string) (*core.TenantQuota, error) {
	if err := validateCall(ctx, tenantID); err != nil {
		return nil, err
	}
	state, err := stateOrZero(readState(ctx, s.db, tenantID))
	if err != nil {
		return nil, err
	}
	return quotaFromState(state)
}

// SetQuota implements core.TenantQuotaStore.
func (s *Store) SetQuota(ctx context.Context, tenantID string, quota *core.TenantQuota) error {
	if err := validateCall(ctx, tenantID); err != nil {
		return err
	}
	if err := core.ValidateTenantQuota(quota); err != nil {
		return err
	}
	return runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if state.quotaRevision > 0 {
			return core.ErrQuotaRevisionConflict
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state SET
max_clients = $2, max_users = $3, max_sessions = $4, max_token_rate = $5,
clients_limited = $6, users_limited = $7, sessions_limited = $8, token_rate_limited = $9
WHERE tenant_id = $1`, tenantID, quota.MaxClients, quota.MaxUsers, quota.MaxSessions,
			quota.MaxTokenRate, quota.ClientsLimited, quota.UsersLimited,
			quota.SessionsLimited, quota.TokenRateLimited)
		return err
	})
}
