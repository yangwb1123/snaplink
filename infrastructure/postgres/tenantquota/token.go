package tenantquota

import (
	"context"
	"database/sql"
	"math"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

type tokenWindow struct {
	second   int64
	quantity int64
}

func (s *Store) incrementTokenRate(ctx context.Context, tenantID string, delta int64) error {
	return runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		second := max(s.now().UTC().Unix(), state.tokenClockSecond)
		if err := cleanupTenantWindows(ctx, tx, tenantID, second); err != nil {
			return err
		}
		total, err := tokenWindowTotal(ctx, tx, tenantID, second)
		if err != nil {
			return err
		}
		limited := state.maxTokenRate > 0 || state.tokenRateLimited
		if err := checkTokenIncrement(state.maxTokenRate, total, delta, limited); err != nil {
			return err
		}
		return writeTokenIncrement(ctx, tx, tenantID, second, delta)
	})
}

func checkTokenIncrement(rate, total, delta int64, limited bool) error {
	if total > math.MaxInt64-delta {
		return core.ErrInvalidQuotaOperation
	}
	if rate > math.MaxInt64/core.TenantQuotaTokenWindowSeconds {
		return core.ErrInvalidQuotaOperation
	}
	if limited && total+delta > rate*core.TenantQuotaTokenWindowSeconds {
		return core.ErrQuotaExceeded
	}
	return nil
}

func cleanupTenantWindows(ctx context.Context, tx *sql.Tx, tenantID string, second int64) error {
	cutoff := second - core.TenantQuotaTokenWindowSeconds + 1
	_, err := tx.ExecContext(ctx, `DELETE FROM tenant_quota_token_windows
WHERE tenant_id = $1 AND window_second < $2`, tenantID, cutoff)
	return err
}

func tokenWindowTotal(ctx context.Context, tx *sql.Tx, tenantID string, second int64) (int64, error) {
	cutoff := second - core.TenantQuotaTokenWindowSeconds + 1
	var total int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(quantity), 0)::BIGINT
FROM tenant_quota_token_windows WHERE tenant_id = $1 AND window_second >= $2`, tenantID, cutoff).Scan(&total)
	return total, err
}

func writeTokenIncrement(ctx context.Context, tx *sql.Tx, tenantID string, second, delta int64) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO tenant_quota_token_windows (tenant_id, window_second, quantity)
VALUES ($1, $2, $3) ON CONFLICT (tenant_id, window_second)
DO UPDATE SET quantity = tenant_quota_token_windows.quantity + EXCLUDED.quantity`, tenantID, second, delta)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state
SET token_clock_second = $2 WHERE tenant_id = $1`, tenantID, second)
	return err
}

func (s *Store) decrementTokenRate(ctx context.Context, tenantID string, delta int64) error {
	return runLocked(ctx, s.db, func(tx *sql.Tx) error {
		state, err := lockState(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		second := max(s.now().UTC().Unix(), state.tokenClockSecond)
		if err := cleanupTenantWindows(ctx, tx, tenantID, second); err != nil {
			return err
		}
		windows, err := readTokenWindows(ctx, tx, tenantID, second)
		if err != nil {
			return err
		}
		if err := applyTokenDecrement(ctx, tx, tenantID, windows, delta); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `UPDATE tenant_quota_state SET token_clock_second = $2 WHERE tenant_id = $1`, tenantID, second)
		return err
	})
}

func readTokenWindows(ctx context.Context, tx *sql.Tx, tenantID string, second int64) ([]tokenWindow, error) {
	cutoff := second - core.TenantQuotaTokenWindowSeconds + 1
	rows, err := tx.QueryContext(ctx, `SELECT window_second, quantity
FROM tenant_quota_token_windows WHERE tenant_id = $1 AND window_second >= $2
ORDER BY window_second DESC FOR UPDATE`, tenantID, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	windows := make([]tokenWindow, 0, core.TenantQuotaTokenWindowSeconds)
	for rows.Next() {
		var window tokenWindow
		if err := rows.Scan(&window.second, &window.quantity); err != nil {
			return nil, err
		}
		windows = append(windows, window)
	}
	return windows, rows.Err()
}

func applyTokenDecrement(ctx context.Context, tx *sql.Tx, tenantID string, windows []tokenWindow, delta int64) error {
	for _, window := range windows {
		take := min(window.quantity, delta)
		remaining := window.quantity - take
		if err := writeTokenWindow(ctx, tx, tenantID, window.second, remaining); err != nil {
			return err
		}
		delta -= take
		if delta == 0 {
			break
		}
	}
	return nil
}

func writeTokenWindow(ctx context.Context, tx *sql.Tx, tenantID string, second, quantity int64) error {
	if quantity == 0 {
		_, err := tx.ExecContext(ctx, `DELETE FROM tenant_quota_token_windows
WHERE tenant_id = $1 AND window_second = $2`, tenantID, second)
		return err
	}
	_, err := tx.ExecContext(ctx, `UPDATE tenant_quota_token_windows SET quantity = $3
WHERE tenant_id = $1 AND window_second = $2`, tenantID, second, quantity)
	return err
}

// CleanupTokenRateWindows implements core.TenantQuotaWindowCleaner. Advancing
// the persisted clock in the same transaction prevents a slower replica from
// re-opening a window that this cleanup has expired.
func (s *Store) CleanupTokenRateWindows(ctx context.Context, now time.Time) (int64, error) {
	var removed int64
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		second := now.UTC().Unix()
		if _, err := tx.ExecContext(ctx, `UPDATE tenant_quota_state
SET token_clock_second = GREATEST(token_clock_second, $1)`, second); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM tenant_quota_token_windows w
WHERE w.window_second < (SELECT q.token_clock_second FROM tenant_quota_state q
 WHERE q.tenant_id = w.tenant_id) - $1 + 1`, core.TenantQuotaTokenWindowSeconds)
		if err != nil {
			return err
		}
		removed, err = result.RowsAffected()
		return err
	})
	return removed, err
}
