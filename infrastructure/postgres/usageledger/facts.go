package usageledger

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func (s *Store) AppendFact(
	ctx context.Context, command ledger.AppendCommand,
) (*ledger.UsageFact, *ledger.Counter, error) {
	if err := validateAppend(command); err != nil {
		return nil, nil, err
	}
	var fact *ledger.UsageFact
	var counter *ledger.Counter
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		fact, counter, err = appendFactTx(ctx, tx, command)
		return err
	})
	return fact, counter, err
}

func validateAppend(command ledger.AppendCommand) error {
	if err := command.Fact.Validate(); err != nil {
		return err
	}
	return command.Limit.Validate()
}

func appendFactTx(
	ctx context.Context, tx *sql.Tx, command ledger.AppendCommand,
) (*ledger.UsageFact, *ledger.Counter, error) {
	if err := verifySourceBindingTx(
		ctx, tx, command.Evidence, command.Fact.TenantID,
		command.Fact.SourceSystem, command.Fact.Dimension,
	); err != nil {
		return nil, nil, err
	}
	key := keyFor(command.Fact.TenantID, command.Fact.Dimension, command.Fact.Period)
	state, err := lockBucketTx(ctx, tx, key, command.Fact.CreatedAt)
	if err != nil {
		return nil, nil, err
	}
	if err := expireBucketTx(ctx, tx, &state, command.Fact.CreatedAt); err != nil {
		return nil, nil, err
	}
	replay, found, err := findFactReplayTx(ctx, tx, command.Fact)
	if err != nil {
		return nil, nil, err
	}
	if found {
		return replay, state.counter(command.Limit), nil
	}
	if state.closed {
		return nil, nil, ledger.ErrPeriodClosed
	}
	if err := capacityError(state, command.Fact.Quantity, command.Limit); err != nil {
		return nil, state.counter(command.Limit), err
	}
	if err := insertFactTx(ctx, tx, command.Fact); err != nil {
		return nil, nil, err
	}
	if err := addCommittedTx(ctx, tx, key, command.Fact.Quantity, 1, command.Fact.CreatedAt); err != nil {
		return nil, nil, err
	}
	state.committed += command.Fact.Quantity
	state.factCount++
	return cloneFact(command.Fact), state.counter(command.Limit), nil
}

func capacityError(state bucketState, quantity int64, limit commerce.LimitGrant) error {
	if state.committed > math.MaxInt64-state.reserved ||
		state.committed+state.reserved > math.MaxInt64-quantity {
		return ledger.ErrCounterOverflow
	}
	if !withinLimit(state.committed+state.reserved, quantity, limit) {
		return ledger.ErrQuotaExceeded
	}
	return nil
}

func lockBucketTx(
	ctx context.Context, tx *sql.Tx, key bucketKey, at time.Time,
) (bucketState, error) {
	state, err := selectBucketTx(ctx, tx, key)
	if err == nil {
		return state, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return bucketState{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO usage_ledger_buckets (
tenant_id, dimension, period_start_ns, period_end_ns, updated_at_ns
) VALUES ($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`,
		key.tenantID, key.dimension, key.start, key.end, timeNano(at))
	if err != nil {
		return bucketState{}, fmt.Errorf("usageledger/postgres: ensure bucket: %w", err)
	}
	return selectBucketTx(ctx, tx, key)
}

func selectBucketTx(ctx context.Context, tx *sql.Tx, key bucketKey) (bucketState, error) {
	state := bucketState{key: key}
	err := tx.QueryRowContext(ctx, `SELECT committed_quantity, reserved_quantity, fact_count, closed
FROM usage_ledger_buckets WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3
AND period_end_ns=$4 FOR UPDATE`, key.tenantID, key.dimension, key.start, key.end).Scan(
		&state.committed, &state.reserved, &state.factCount, &state.closed,
	)
	return state, err
}

func expireBucketTx(
	ctx context.Context, tx *sql.Tx, state *bucketState, at time.Time,
) error {
	rows, err := tx.QueryContext(ctx, `UPDATE usage_ledger_reservations SET
status='expired', version=version+1, updated_at_ns=$5
WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4
AND status='pending' AND expires_at_ns <= $5 RETURNING quantity`,
		state.key.tenantID, state.key.dimension, state.key.start, state.key.end, timeNano(at))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: expire reservations: %w", err)
	}
	expired, err := sumQuantities(rows)
	if err != nil || expired == 0 {
		return err
	}
	if expired > state.reserved {
		return errors.New("usageledger/postgres: reserved counter invariant violated")
	}
	if err := addReservedTx(ctx, tx, state.key, -expired, at); err != nil {
		return err
	}
	state.reserved -= expired
	return nil
}

func sumQuantities(rows *sql.Rows) (int64, error) {
	defer func() { _ = rows.Close() }()
	var total int64
	for rows.Next() {
		var quantity int64
		if err := rows.Scan(&quantity); err != nil {
			return 0, err
		}
		total += quantity
	}
	return total, rows.Err()
}

func addCommittedTx(
	ctx context.Context, tx *sql.Tx, key bucketKey, quantity, facts int64, at time.Time,
) error {
	_, err := tx.ExecContext(ctx, `UPDATE usage_ledger_buckets SET
committed_quantity=committed_quantity+$5, fact_count=fact_count+$6, updated_at_ns=$7
WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4`,
		key.tenantID, key.dimension, key.start, key.end, quantity, facts, timeNano(at))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: update committed counter: %w", err)
	}
	return nil
}

func addReservedTx(
	ctx context.Context, tx *sql.Tx, key bucketKey, quantity int64, at time.Time,
) error {
	result, err := tx.ExecContext(ctx, `UPDATE usage_ledger_buckets SET
reserved_quantity=reserved_quantity+$5, updated_at_ns=$6
WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4
AND reserved_quantity+$5 >= 0`, key.tenantID, key.dimension, key.start, key.end, quantity, timeNano(at))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: update reserved counter: %w", err)
	}
	updated, err := result.RowsAffected()
	if err == nil && updated != 1 {
		return errors.New("usageledger/postgres: reserved counter invariant violated")
	}
	return err
}

func insertFactTx(ctx context.Context, tx *sql.Tx, fact *ledger.UsageFact) error {
	metadata, err := encodeJSON(fact.Metadata)
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO usage_ledger_facts (`+factColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,CAST($11 AS JSONB)) ON CONFLICT DO NOTHING`,
		fact.ID, fact.TenantID, fact.SourceSystem, fact.Dimension, fact.Quantity,
		timeNano(fact.Period.Start), timeNano(fact.Period.End), fact.IdempotencyKey,
		timeNano(fact.OccurredAt), timeNano(fact.CreatedAt), metadata)
	if err != nil {
		return fmt.Errorf("usageledger/postgres: insert fact: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err == nil && inserted != 1 {
		return ledger.ErrIdempotencyConflict
	}
	return err
}

func findFactReplayTx(
	ctx context.Context, tx *sql.Tx, expected *ledger.UsageFact,
) (*ledger.UsageFact, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+factColumns+` FROM usage_ledger_facts
WHERE id=$1 OR (tenant_id=$2 AND source_system=$3 AND dimension=$4 AND idempotency_key=$5)
`, expected.ID, expected.TenantID, expected.SourceSystem, expected.Dimension, expected.IdempotencyKey)
	if err != nil {
		return nil, false, fmt.Errorf("usageledger/postgres: inspect fact replay: %w", err)
	}
	facts, err := readFacts(rows)
	if err != nil {
		return nil, false, err
	}
	if len(facts) == 0 {
		return nil, false, nil
	}
	if len(facts) != 1 || !sameFact(facts[0], expected) {
		return nil, false, ledger.ErrIdempotencyConflict
	}
	return facts[0], true, nil
}

func (s *Store) GetFact(ctx context.Context, id string) (*ledger.UsageFact, error) {
	fact, err := scanFact(s.db.QueryRowContext(ctx,
		`SELECT `+factColumns+` FROM usage_ledger_facts WHERE id=$1`, id))
	return fact, notFound(err, ledger.ErrFactNotFound)
}

func (s *Store) ListFacts(
	ctx context.Context, tenantID string, dimension ledger.Dimension, period ledger.Period,
) ([]*ledger.UsageFact, error) {
	if err := period.Validate(); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT `+factColumns+` FROM usage_ledger_facts
WHERE tenant_id=$1 AND dimension=$2 AND period_start_ns=$3 AND period_end_ns=$4
ORDER BY occurred_at_ns, id`, tenantID, dimension, timeNano(period.Start), timeNano(period.End))
	if err != nil {
		return nil, fmt.Errorf("usageledger/postgres: list facts: %w", err)
	}
	return readFacts(rows)
}

func readFacts(rows *sql.Rows) ([]*ledger.UsageFact, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*ledger.UsageFact, 0)
	for rows.Next() {
		fact, err := scanFact(rows)
		if err != nil {
			return nil, fmt.Errorf("usageledger/postgres: scan fact: %w", err)
		}
		result = append(result, fact)
	}
	return result, rows.Err()
}

func cloneFact(fact *ledger.UsageFact) *ledger.UsageFact {
	if fact == nil {
		return nil
	}
	copy := *fact
	copy.Metadata = make(map[string]string, len(fact.Metadata))
	for key, value := range fact.Metadata {
		copy.Metadata[key] = value
	}
	return &copy
}
