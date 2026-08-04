package tenantquota

import (
	"context"
	"database/sql"
	"errors"
	"math"

	"github.com/yangwb1123/snaplink/shared/core"
)

// GetUsage implements core.TenantQuotaStore.
func (s *Store) GetUsage(ctx context.Context, tenantID string) (*core.TenantUsage, error) {
	if err := validateCall(ctx, tenantID); err != nil {
		return nil, err
	}
	state, tokenCount, err := s.readUsage(ctx, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return &core.TenantUsage{}, nil
	}
	if err != nil {
		return nil, err
	}
	return usageFromState(state, tokenCount)
}

func (s *Store) readUsage(ctx context.Context, tenantID string) (stateRow, int64, error) {
	second := s.now().UTC().Unix()
	query := `SELECT ` + stateColumns + `,
COALESCE((SELECT SUM(w.quantity) FROM tenant_quota_token_windows w
 WHERE w.tenant_id = q.tenant_id
   AND w.window_second >= GREATEST($2, q.token_clock_second) - $3 + 1), 0)::BIGINT
FROM tenant_quota_state q WHERE q.tenant_id = $1`
	var state stateRow
	var tokenCount int64
	err := s.db.QueryRowContext(ctx, query, tenantID, second, core.TenantQuotaTokenWindowSeconds).Scan(
		&state.maxClients, &state.maxUsers, &state.maxSessions, &state.maxTokenRate,
		&state.clientsLimited, &state.usersLimited, &state.sessionsLimited, &state.tokenRateLimited,
		&state.quotaRevision, &state.clients, &state.users, &state.sessions,
		&state.clientsGeneration, &state.usersGeneration, &state.sessionsGeneration,
		&state.tokenClockSecond, &tokenCount,
	)
	return state, tokenCount, err
}

// IncrementUsage implements core.TenantQuotaStore.
func (s *Store) IncrementUsage(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	if err := validateMutation(ctx, tenantID, resource, delta); err != nil {
		return err
	}
	if resource == core.ResourceTokenRate {
		return s.incrementTokenRate(ctx, tenantID, delta)
	}
	return s.incrementGauge(ctx, tenantID, resource, delta)
}

func (s *Store) incrementGauge(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	return runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		column, generationColumn, current, limit, limited, generation := gaugeState(state, resource)
		if current > int64(math.MaxInt)-delta {
			return core.ErrInvalidQuotaOperation
		}
		if generation == math.MaxInt64 {
			return core.ErrInvalidQuotaOperation
		}
		if limited && current+delta > limit {
			return core.ErrQuotaExceeded
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state SET `+column+` = $2, `+
			generationColumn+` = $3 WHERE tenant_id = $1`, tenantID, current+delta, generation+1)
		return err
	})
}

// DecrementUsage implements core.TenantQuotaStore.
func (s *Store) DecrementUsage(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	if err := validateMutation(ctx, tenantID, resource, delta); err != nil {
		return err
	}
	if resource == core.ResourceTokenRate {
		return s.decrementTokenRate(ctx, tenantID, delta)
	}
	return s.decrementGauge(ctx, tenantID, resource, delta)
}

func (s *Store) decrementGauge(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	return runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		column, generationColumn, current, _, _, generation := gaugeState(state, resource)
		if generation == math.MaxInt64 {
			return core.ErrInvalidQuotaOperation
		}
		next := max(int64(0), current-delta)
		_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state SET `+column+` = $2, `+
			generationColumn+` = $3 WHERE tenant_id = $1`, tenantID, next, generation+1)
		return err
	})
}

func gaugeState(state stateRow, resource core.ResourceType) (string, string, int64, int64, bool, int64) {
	switch resource {
	case core.ResourceClients:
		return "clients", "clients_generation", state.clients, state.maxClients,
			state.maxClients > 0 || state.clientsLimited, state.clientsGeneration
	case core.ResourceUsers:
		return "users", "users_generation", state.users, state.maxUsers,
			state.maxUsers > 0 || state.usersLimited, state.usersGeneration
	default:
		return "sessions", "sessions_generation", state.sessions, state.maxSessions,
			state.maxSessions > 0 || state.sessionsLimited, state.sessionsGeneration
	}
}

// ResetUsage implements core.TenantQuotaStore.
func (s *Store) ResetUsage(ctx context.Context, tenantID string) error {
	if err := validateCall(ctx, tenantID); err != nil {
		return err
	}
	return runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if state.clientsGeneration == math.MaxInt64 || state.usersGeneration == math.MaxInt64 ||
			state.sessionsGeneration == math.MaxInt64 {
			return core.ErrInvalidQuotaOperation
		}
		if _, err := tx.ExecContext(ctx, `UPDATE tenant_quota_state
SET clients = 0, users = 0, sessions = 0,
clients_generation = clients_generation + 1,
users_generation = users_generation + 1,
sessions_generation = sessions_generation + 1 WHERE tenant_id = $1`, tenantID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM tenant_quota_resource_leases WHERE tenant_id = $1`, tenantID); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `DELETE FROM tenant_quota_token_windows WHERE tenant_id = $1`, tenantID)
		return err
	})
}
