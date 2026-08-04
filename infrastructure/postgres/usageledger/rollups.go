package usageledger

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func (s *Store) ClosePeriod(
	ctx context.Context, command ledger.ClosePeriodCommand,
) (*ledger.Rollup, error) {
	if err := validateClose(command); err != nil {
		return nil, err
	}
	var rollup *ledger.Rollup
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		rollup, err = closePeriodTx(ctx, tx, command)
		return err
	})
	return rollup, err
}

func validateClose(command ledger.ClosePeriodCommand) error {
	if command.RollupID == "" || command.EventID == "" || command.TenantID == "" ||
		command.Dimension == "" || command.ClosedAt.IsZero() || command.ClosedAt.Before(command.Period.End) {
		return ledger.ErrInvalidPeriod
	}
	return command.Period.Validate()
}

func closePeriodTx(
	ctx context.Context, tx *sql.Tx, command ledger.ClosePeriodCommand,
) (*ledger.Rollup, error) {
	current, err := getRollupTx(ctx, tx, command.TenantID, command.Dimension, command.Period, true)
	if err == nil {
		return current, nil
	}
	if !errors.Is(err, ledger.ErrRollupNotFound) {
		return nil, err
	}
	key := keyFor(command.TenantID, command.Dimension, command.Period)
	state, err := lockBucketTx(ctx, tx, key, command.ClosedAt)
	if err != nil {
		return nil, err
	}
	if err := expireBucketTx(ctx, tx, &state, command.ClosedAt); err != nil {
		return nil, err
	}
	if state.closed {
		current, err := getRollupTx(
			ctx, tx, command.TenantID, command.Dimension, command.Period, false,
		)
		if err == nil {
			return current, nil
		}
		return nil, errors.New("usageledger/postgres: closed bucket has no rollup")
	}
	if state.reserved != 0 {
		return nil, ledger.ErrActiveReservations
	}
	rollup, err := buildRollupTx(ctx, tx, state, command)
	if err != nil {
		return nil, err
	}
	if err := insertRollupTx(ctx, tx, rollup); err != nil {
		return nil, err
	}
	if err := insertOutboxEventTx(ctx, tx, rollupOutboxEvent(rollup, command.EventID)); err != nil {
		return nil, err
	}
	if err := closeBucketTx(ctx, tx, key, command.ClosedAt); err != nil {
		return nil, err
	}
	return rollup, nil
}

func buildRollupTx(
	ctx context.Context, tx *sql.Tx, state bucketState, command ledger.ClosePeriodCommand,
) (*ledger.Rollup, error) {
	var quantity, count int64
	err := tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(quantity),0), COUNT(*)
FROM usage_ledger_facts WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4`,
		state.key.tenantID, state.key.dimension, state.key.start, state.key.end).Scan(&quantity, &count)
	if err != nil {
		return nil, fmt.Errorf("usageledger/postgres: aggregate facts: %w", err)
	}
	if quantity != state.committed || count != state.factCount {
		return nil, errors.New("usageledger/postgres: committed counter invariant violated")
	}
	rollup := &ledger.Rollup{
		ID: command.RollupID, TenantID: command.TenantID, Dimension: command.Dimension,
		Period: command.Period, Quantity: quantity, FactCount: count, Version: 1,
		ClosedAt: command.ClosedAt,
	}
	rollup.Digest = rollupDigest(rollup)
	return rollup, nil
}

func insertRollupTx(ctx context.Context, tx *sql.Tx, rollup *ledger.Rollup) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO usage_ledger_rollups (`+rollupColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT DO NOTHING`,
		rollup.ID, rollup.TenantID, rollup.Dimension,
		timeNano(rollup.Period.Start), timeNano(rollup.Period.End), rollup.Quantity,
		rollup.FactCount, rollup.Version, rollup.Digest, timeNano(rollup.ClosedAt))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: insert rollup: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err == nil && inserted != 1 {
		return ledger.ErrIdempotencyConflict
	}
	return err
}

func closeBucketTx(ctx context.Context, tx *sql.Tx, key bucketKey, at time.Time) error {
	result, err := tx.ExecContext(ctx, `UPDATE usage_ledger_buckets SET closed=TRUE, updated_at_ns=$5
WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4 AND closed=FALSE`,
		key.tenantID, key.dimension, key.start, key.end, timeNano(at))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: close bucket: %w", err)
	}
	updated, err := result.RowsAffected()
	if err == nil && updated != 1 {
		return ledger.ErrPeriodClosed
	}
	return err
}

func (s *Store) GetRollup(
	ctx context.Context, tenantID string, dimension ledger.Dimension, period ledger.Period,
) (*ledger.Rollup, error) {
	if err := period.Validate(); err != nil {
		return nil, err
	}
	return getRollupDB(ctx, s.db, tenantID, dimension, period)
}

func getRollupDB(
	ctx context.Context, db *sql.DB, tenantID string, dimension ledger.Dimension, period ledger.Period,
) (*ledger.Rollup, error) {
	rollup, err := scanRollup(db.QueryRowContext(ctx, `SELECT `+rollupColumns+`
FROM usage_ledger_rollups WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4`,
		tenantID, dimension, timeNano(period.Start), timeNano(period.End)))
	return rollup, notFound(err, ledger.ErrRollupNotFound)
}

func getRollupTx(
	ctx context.Context, tx *sql.Tx, tenantID string, dimension ledger.Dimension,
	period ledger.Period, locked bool,
) (*ledger.Rollup, error) {
	query := `SELECT ` + rollupColumns + ` FROM usage_ledger_rollups
WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4`
	if locked {
		query += ` FOR UPDATE`
	}
	rollup, err := scanRollup(tx.QueryRowContext(ctx, query,
		tenantID, dimension, timeNano(period.Start), timeNano(period.End)))
	return rollup, notFound(err, ledger.ErrRollupNotFound)
}

func rollupDigest(rollup *ledger.Rollup) string {
	canonical := joinKey(
		rollup.TenantID, string(rollup.Dimension), strconv.FormatInt(timeNano(rollup.Period.Start), 10),
		strconv.FormatInt(timeNano(rollup.Period.End), 10), strconv.FormatInt(rollup.Quantity, 10),
		strconv.FormatInt(rollup.FactCount, 10),
	)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

func rollupOutboxEvent(rollup *ledger.Rollup, eventID string) *commerce.OutboxEvent {
	payload := map[string]string{
		"dimension":     string(rollup.Dimension),
		"period_start":  rollup.Period.Start.UTC().Format(time.RFC3339Nano),
		"period_end":    rollup.Period.End.UTC().Format(time.RFC3339Nano),
		"quantity":      strconv.FormatInt(rollup.Quantity, 10),
		"fact_count":    strconv.FormatInt(rollup.FactCount, 10),
		"rollup_digest": rollup.Digest,
	}
	return &commerce.OutboxEvent{
		ID: eventID, TenantID: rollup.TenantID, Type: commerce.EventUsageRollupClosed,
		AggregateType: "usage_rollup", AggregateID: rollup.ID, AggregateVersion: rollup.Version,
		IdempotencyKey: "usage_rollup:" + rollup.ID, OccurredAt: rollup.ClosedAt,
		Payload: payload, PayloadDigest: payloadDigest(payload), Status: commerce.OutboxPending,
		CreatedAt: rollup.ClosedAt,
	}
}

func payloadDigest(payload map[string]string) string {
	keys := make([]string, 0, len(payload))
	for key := range payload {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		canonical.WriteString(joinKey(key, payload[key]))
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}

func joinKey(parts ...string) string {
	var builder strings.Builder
	for _, part := range parts {
		builder.WriteString(strconv.Itoa(len(part)))
		builder.WriteByte(':')
		builder.WriteString(part)
	}
	return builder.String()
}
