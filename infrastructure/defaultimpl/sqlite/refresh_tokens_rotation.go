package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// RecordRotation implements [oauth.RefreshTokenRotationLimiter]: it atomically
// bumps familyID's fixed-window counter and reports (count, exceeded, err).
// An empty familyID is a no-op (0, false, nil). The fixed window is rolled over
// when RotationWindow > 0 and the current wall time is past window_start+RotationWindow.
// Fail-open: a store error returns (0, false, err) — the caller treats that as
// non-exceeded per §2.
func (s *RefreshTokenStore) RecordRotation(ctx context.Context, familyID string) (int, bool, error) {
	if familyID == "" {
		return 0, false, nil
	}
	// A real BEGIN IMMEDIATE (not db.BeginTx's isolation-level hint, which
	// modernc.org/sqlite ignores — see beginImmediateRMW's doc) serializes
	// the RMW against concurrent writers.
	conn, err := beginImmediateRMW(ctx, s.db)
	if err != nil {
		return 0, false, fmt.Errorf("sqlite: rotation begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = conn.ExecContext(ctx, "ROLLBACK")
		}
		_ = conn.Close()
	}()
	return s.bumpRotationWindow(ctx, conn, familyID, &committed)
}

// bumpRotationWindow loads + rolls over + upserts familyID's fixed-window
// counter against conn's already-open BEGIN IMMEDIATE transaction, and sets
// *committed true on success. Kept separate from RecordRotation to stay
// within the function-length budget.
func (s *RefreshTokenStore) bumpRotationWindow(ctx context.Context, conn *sql.Conn, familyID string, committed *bool) (int, bool, error) {
	var count int64
	var windowStartNs int64
	err := conn.QueryRowContext(ctx,
		`SELECT count, window_start FROM refresh_rotation_windows WHERE family_id = ?`, familyID,
	).Scan(&count, &windowStartNs)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, false, fmt.Errorf("sqlite: rotation query: %w", err)
	}

	nowNs := time.Now().UnixNano()
	// Roll over fixed window when configured and elapsed.
	if s.RotationWindow > 0 && windowStartNs > 0 &&
		time.Duration(nowNs-windowStartNs) >= s.RotationWindow {
		count = 0
		windowStartNs = 0
	}
	count++
	if windowStartNs == 0 {
		windowStartNs = nowNs
	}

	_, err = conn.ExecContext(ctx, `
        INSERT INTO refresh_rotation_windows (family_id, count, window_start)
        VALUES (?, ?, ?)
        ON CONFLICT(family_id) DO UPDATE SET count=excluded.count, window_start=excluded.window_start`,
		familyID, count, windowStartNs)
	if err != nil {
		return 0, false, fmt.Errorf("sqlite: rotation upsert: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		return 0, false, fmt.Errorf("sqlite: rotation commit: %w", err)
	}
	*committed = true

	exceeded := s.MaxRotationsPerWindow > 0 && s.RotationWindow > 0 &&
		count > int64(s.MaxRotationsPerWindow)
	return int(count), exceeded, nil
}
