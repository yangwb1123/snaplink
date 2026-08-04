package tenantquota

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/yangwb1123/snaplink/shared/core"
)

const stateColumns = `max_clients, max_users, max_sessions, max_token_rate,
clients_limited, users_limited, sessions_limited, token_rate_limited, quota_revision,
clients, users, sessions, clients_generation, users_generation, sessions_generation,
token_clock_second`

type stateRow struct {
	maxClients, maxUsers, maxSessions, maxTokenRate int64
	clientsLimited, usersLimited                    bool
	sessionsLimited, tokenRateLimited               bool
	quotaRevision                                   int64
	clients, users, sessions                        int64
	clientsGeneration, usersGeneration              int64
	sessionsGeneration, tokenClockSecond            int64
}

func validateCall(ctx context.Context, tenantID string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return core.ValidateQuotaTenantID(tenantID)
}

func validateMutation(ctx context.Context, tenantID string, resource core.ResourceType, delta int64) error {
	if err := validateCall(ctx, tenantID); err != nil {
		return err
	}
	if err := core.ValidateQuotaResource(resource); err != nil {
		return err
	}
	return core.ValidateQuotaDelta(delta)
}

func lockState(ctx context.Context, tx *sql.Tx, tenantID string) (stateRow, error) {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_quota_state (tenant_id)
VALUES ($1) ON CONFLICT (tenant_id) DO NOTHING`, tenantID)
	if err != nil {
		return stateRow{}, err
	}
	query := `SELECT ` + stateColumns + ` FROM tenant_quota_state WHERE tenant_id = $1 FOR UPDATE`
	return scanState(tx.QueryRowContext(ctx, query, tenantID))
}

func readState(ctx context.Context, db *sql.DB, tenantID string) (stateRow, error) {
	query := `SELECT ` + stateColumns + ` FROM tenant_quota_state WHERE tenant_id = $1`
	return scanState(db.QueryRowContext(ctx, query, tenantID))
}

func scanState(row *sql.Row) (stateRow, error) {
	var state stateRow
	err := row.Scan(
		&state.maxClients, &state.maxUsers, &state.maxSessions, &state.maxTokenRate,
		&state.clientsLimited, &state.usersLimited, &state.sessionsLimited, &state.tokenRateLimited,
		&state.quotaRevision, &state.clients, &state.users, &state.sessions,
		&state.clientsGeneration, &state.usersGeneration, &state.sessionsGeneration,
		&state.tokenClockSecond,
	)
	return state, err
}

func quotaFromState(state stateRow) (*core.TenantQuota, error) {
	values := []int64{state.maxClients, state.maxUsers, state.maxSessions, state.maxTokenRate}
	for _, value := range values {
		if value < 0 || value > int64(math.MaxInt) {
			return nil, fmt.Errorf("%w: persisted quota is out of range", core.ErrInvalidQuotaOperation)
		}
	}
	quota := &core.TenantQuota{
		MaxClients: int(state.maxClients), MaxUsers: int(state.maxUsers),
		MaxSessions: int(state.maxSessions), MaxTokenRate: int(state.maxTokenRate),
		ClientsLimited: state.clientsLimited, UsersLimited: state.usersLimited,
		SessionsLimited: state.sessionsLimited, TokenRateLimited: state.tokenRateLimited,
	}
	if err := core.ValidateTenantQuota(quota); err != nil {
		return nil, err
	}
	return quota, nil
}

func usageFromState(state stateRow, tokenCount int64) (*core.TenantUsage, error) {
	values := []int64{state.clients, state.users, state.sessions}
	for _, value := range values {
		if value < 0 || value > int64(math.MaxInt) {
			return nil, fmt.Errorf("%w: persisted usage is out of range", core.ErrInvalidQuotaOperation)
		}
	}
	return &core.TenantUsage{
		Clients: int(state.clients), Users: int(state.users), Sessions: int(state.sessions),
		TokenRate: float64(tokenCount) / float64(core.TenantQuotaTokenWindowSeconds),
	}, nil
}

func stateOrZero(state stateRow, err error) (stateRow, error) {
	if errors.Is(err, sql.ErrNoRows) {
		return stateRow{}, nil
	}
	return state, err
}
