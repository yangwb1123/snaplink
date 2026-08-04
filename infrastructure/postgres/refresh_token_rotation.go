package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RecordRotation implements [oauthspi.RefreshTokenRotationLimiter]: it
// atomically bumps familyID's fixed-window counter and reports
// (count, exceeded, err). An empty familyID is a no-op (0, false, nil). The
// fixed window rolls over when RotationWindow > 0 and the current wall time
// is past window_start+RotationWindow. The read-modify-write runs under
// SERIALIZABLE via runTx so concurrent increments never silently lose a count
// (READ COMMITTED would be last-commit-wins) and CockroachDB 40001 retries
// match the rest of the package. Fail-open: a store error returns
// (0, false, err) — the caller treats that as non-exceeded per oauthspi.
func (s *RefreshTokenStore) RecordRotation(ctx context.Context, familyID string) (int, bool, error) {
	if familyID == "" {
		return 0, false, nil
	}
	var count int64
	exceeded := false
	err := runTx(ctx, s.db, serializable, func(tx *sql.Tx) error {
		var windowStartNs int64
		err := tx.QueryRowContext(ctx,
			`SELECT count, window_start FROM refresh_rotation_windows WHERE family_id = $1`, familyID,
		).Scan(&count, &windowStartNs)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("postgres: rotation query: %w", err)
		}
		nowNs := time.Now().UnixNano()
		// Roll over fixed window when configured and elapsed. A zero
		// window_start means the counter accumulates forever — reproduce
		// exactly (the velocity cap then never fires).
		if s.RotationWindow > 0 && windowStartNs > 0 &&
			time.Duration(nowNs-windowStartNs) >= s.RotationWindow {
			count = 0
			windowStartNs = 0
		}
		count++
		if windowStartNs == 0 {
			windowStartNs = nowNs
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO refresh_rotation_windows (family_id, count, window_start)
            VALUES ($1, $2, $3)
            ON CONFLICT (family_id) DO UPDATE
                SET count = excluded.count, window_start = excluded.window_start`,
			familyID, count, windowStartNs); err != nil {
			return fmt.Errorf("postgres: rotation upsert: %w", err)
		}
		exceeded = s.MaxRotationsPerWindow > 0 && s.RotationWindow > 0 &&
			count > int64(s.MaxRotationsPerWindow)
		return nil
	})
	if err != nil {
		return 0, false, fmt.Errorf("postgres: rotation: %w", err)
	}
	return int(count), exceeded, nil
}
