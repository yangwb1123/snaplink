package usageledger

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
)

func (s *Store) Reserve(
	ctx context.Context, command ledger.ReserveCommand,
) (*ledger.Reservation, *ledger.Counter, error) {
	if err := validateReserve(command); err != nil {
		return nil, nil, err
	}
	var reservation *ledger.Reservation
	var counter *ledger.Counter
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		reservation, counter, err = reserveTx(ctx, tx, command)
		return err
	})
	return reservation, counter, err
}

func validateReserve(command ledger.ReserveCommand) error {
	if err := command.Reservation.Validate(); err != nil {
		return err
	}
	if command.Reservation.Status != ledger.ReservationPending {
		return ledger.ErrInvalidReservation
	}
	if err := command.Limit.Validate(); err != nil {
		return err
	}
	if command.Reservation.Limit != command.Limit {
		return ledger.ErrInvalidReservation
	}
	return nil
}

func reserveTx(
	ctx context.Context, tx *sql.Tx, command ledger.ReserveCommand,
) (*ledger.Reservation, *ledger.Counter, error) {
	if err := verifySourceBindingTx(
		ctx, tx, command.Evidence, command.Reservation.TenantID,
		command.Reservation.SourceSystem, command.Reservation.Dimension,
	); err != nil {
		return nil, nil, err
	}
	key := keyFor(command.Reservation.TenantID, command.Reservation.Dimension, command.Reservation.Period)
	state, err := lockBucketTx(ctx, tx, key, command.Reservation.CreatedAt)
	if err != nil {
		return nil, nil, err
	}
	if err := expireBucketTx(ctx, tx, &state, command.Reservation.CreatedAt); err != nil {
		return nil, nil, err
	}
	replay, found, err := findReservationReplayTx(ctx, tx, command.Reservation)
	if err != nil {
		return nil, nil, err
	}
	if found {
		return replay, state.counter(command.Limit), nil
	}
	if state.closed {
		return nil, nil, ledger.ErrPeriodClosed
	}
	if err := capacityError(state, command.Reservation.Quantity, command.Limit); err != nil {
		return nil, state.counter(command.Limit), err
	}
	if err := insertReservationTx(ctx, tx, command.Reservation); err != nil {
		return nil, nil, err
	}
	if err := addReservedTx(ctx, tx, key, command.Reservation.Quantity, command.Reservation.CreatedAt); err != nil {
		return nil, nil, err
	}
	state.reserved += command.Reservation.Quantity
	return cloneReservation(command.Reservation), state.counter(command.Limit), nil
}

func insertReservationTx(ctx context.Context, tx *sql.Tx, reservation *ledger.Reservation) error {
	result, err := tx.ExecContext(ctx, `INSERT INTO usage_ledger_reservations (`+reservationColumns+`)
VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT DO NOTHING`,
		reservation.ID, reservation.TenantID, reservation.SourceSystem, reservation.Dimension,
		reservation.Quantity, timeNano(reservation.Period.Start), timeNano(reservation.Period.End),
		reservation.IdempotencyKey, reservation.Status, reservation.Limit.Soft, reservation.Limit.Hard,
		reservation.Limit.Unlimited, timeNano(reservation.ExpiresAt), reservation.FactID,
		reservation.ReleaseIdempotencyKey, reservation.Version, timeNano(reservation.CreatedAt),
		timeNano(reservation.UpdatedAt))
	if err != nil {
		return fmt.Errorf("usageledger/postgres: insert reservation: %w", err)
	}
	inserted, err := result.RowsAffected()
	if err == nil && inserted != 1 {
		return ledger.ErrIdempotencyConflict
	}
	return err
}

func findReservationReplayTx(
	ctx context.Context, tx *sql.Tx, expected *ledger.Reservation,
) (*ledger.Reservation, bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT `+reservationColumns+` FROM usage_ledger_reservations
WHERE id=$1 OR (tenant_id=$2 AND source_system=$3 AND dimension=$4 AND idempotency_key=$5)
`, expected.ID, expected.TenantID, expected.SourceSystem,
		expected.Dimension, expected.IdempotencyKey)
	if err != nil {
		return nil, false, fmt.Errorf("usageledger/postgres: inspect reservation replay: %w", err)
	}
	reservations, err := readReservations(rows)
	if err != nil {
		return nil, false, err
	}
	if len(reservations) == 0 {
		return nil, false, nil
	}
	if len(reservations) != 1 || !sameReservationCommand(reservations[0], expected) {
		return nil, false, ledger.ErrIdempotencyConflict
	}
	return reservations[0], true, nil
}

func (s *Store) CommitReservation(
	ctx context.Context, identity ledger.ReservationIdentity, fact *ledger.UsageFact,
) (*ledger.Reservation, *ledger.Counter, error) {
	return s.commitReservation(ctx, identity, fact, nil)
}

func (s *Store) CommitReservationAuthorized(
	ctx context.Context, identity ledger.ReservationIdentity, fact *ledger.UsageFact,
	evidence ledger.SourceBindingEvidence,
) (*ledger.Reservation, *ledger.Counter, error) {
	return s.commitReservation(ctx, identity, fact, &evidence)
}

func (s *Store) commitReservation(
	ctx context.Context, identity ledger.ReservationIdentity, fact *ledger.UsageFact,
	evidence *ledger.SourceBindingEvidence,
) (*ledger.Reservation, *ledger.Counter, error) {
	if err := identity.Validate(); err != nil {
		return nil, nil, err
	}
	if err := fact.Validate(); err != nil {
		return nil, nil, err
	}
	var reservation *ledger.Reservation
	var counter *ledger.Counter
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		reservation, counter, err = commitReservationTx(ctx, tx, identity, fact, evidence)
		return err
	})
	return reservation, counter, err
}

func commitReservationTx(
	ctx context.Context, tx *sql.Tx, identity ledger.ReservationIdentity, fact *ledger.UsageFact,
	evidence *ledger.SourceBindingEvidence,
) (*ledger.Reservation, *ledger.Counter, error) {
	reservationIdentity, err := loadBoundReservationTx(ctx, tx, identity, false)
	if err != nil {
		return nil, nil, err
	}
	if err := verifySourceBindingTx(
		ctx, tx, evidence, reservationIdentity.TenantID,
		reservationIdentity.SourceSystem, reservationIdentity.Dimension,
	); err != nil {
		return nil, nil, err
	}
	key := keyFor(reservationIdentity.TenantID, reservationIdentity.Dimension, reservationIdentity.Period)
	state, err := lockBucketTx(ctx, tx, key, fact.CreatedAt)
	if err != nil {
		return nil, nil, err
	}
	if err := expireBucketTx(ctx, tx, &state, fact.CreatedAt); err != nil {
		return nil, nil, err
	}
	reservation, err := loadBoundReservationTx(ctx, tx, identity, true)
	if err != nil {
		return nil, nil, err
	}
	if reservation.Status == ledger.ReservationCommitted {
		return committedReplayTx(ctx, tx, reservation, fact, state)
	}
	if reservation.Status != ledger.ReservationPending || !reservation.ExpiresAt.After(fact.CreatedAt) ||
		!factMatchesReservation(fact, reservation) {
		return nil, nil, ledger.ErrReservationConflict
	}
	if state.closed {
		return nil, nil, ledger.ErrPeriodClosed
	}
	return applyReservationCommitTx(ctx, tx, reservation, fact, state)
}

func committedReplayTx(
	ctx context.Context, tx *sql.Tx, reservation *ledger.Reservation,
	fact *ledger.UsageFact, state bucketState,
) (*ledger.Reservation, *ledger.Counter, error) {
	current, err := scanFact(tx.QueryRowContext(ctx,
		`SELECT `+factColumns+` FROM usage_ledger_facts WHERE id=$1 FOR UPDATE`, reservation.FactID))
	if err != nil || !sameFact(current, fact) {
		if err != nil {
			return nil, nil, notFound(err, ledger.ErrFactNotFound)
		}
		return nil, nil, ledger.ErrIdempotencyConflict
	}
	return reservation, state.counter(reservation.Limit), nil
}

func applyReservationCommitTx(
	ctx context.Context, tx *sql.Tx, reservation *ledger.Reservation,
	fact *ledger.UsageFact, state bucketState,
) (*ledger.Reservation, *ledger.Counter, error) {
	stored, found, err := findFactReplayTx(ctx, tx, fact)
	if err != nil {
		return nil, nil, err
	}
	if !found {
		if err := insertFactTx(ctx, tx, fact); err != nil {
			return nil, nil, err
		}
		stored = fact
		if err := addCommittedTx(ctx, tx, state.key, fact.Quantity, 1, fact.CreatedAt); err != nil {
			return nil, nil, err
		}
		state.committed, state.factCount = state.committed+fact.Quantity, state.factCount+1
	}
	if err := finishReservationTx(ctx, tx, reservation, stored.ID, fact.CreatedAt); err != nil {
		return nil, nil, err
	}
	if err := addReservedTx(ctx, tx, state.key, -reservation.Quantity, fact.CreatedAt); err != nil {
		return nil, nil, err
	}
	reservation.Status, reservation.FactID = ledger.ReservationCommitted, stored.ID
	reservation.Version++
	reservation.UpdatedAt, state.reserved = fact.CreatedAt, state.reserved-reservation.Quantity
	return reservation, state.counter(reservation.Limit), nil
}

func finishReservationTx(
	ctx context.Context, tx *sql.Tx, reservation *ledger.Reservation, factID string, at time.Time,
) error {
	result, err := tx.ExecContext(ctx, `UPDATE usage_ledger_reservations SET
status='committed', fact_id=$2, version=version+1, updated_at_ns=$3
WHERE id=$1 AND status='pending' AND version=$4`,
		reservation.ID, factID, timeNano(at), reservation.Version)
	if err != nil {
		return fmt.Errorf("usageledger/postgres: commit reservation: %w", err)
	}
	updated, err := result.RowsAffected()
	if err == nil && updated != 1 {
		return ledger.ErrReservationConflict
	}
	return err
}

func (s *Store) SweepExpiredReservations(ctx context.Context, now time.Time, limit int) (int, error) {
	if limit <= 0 {
		return 0, nil
	}
	count := 0
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		attemptCount := 0
		ids, err := findExpiredReservationIDsTx(ctx, tx, now, limit)
		if err != nil {
			return err
		}
		for _, id := range ids {
			expired, expireErr := expireReservationByIDTx(ctx, tx, id, now)
			if expireErr != nil {
				return expireErr
			}
			if expired {
				attemptCount++
			}
		}
		count = attemptCount
		return nil
	})
	return count, err
}

func findExpiredReservationIDsTx(
	ctx context.Context, tx *sql.Tx, now time.Time, limit int,
) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM usage_ledger_reservations
WHERE status='pending' AND expires_at_ns <= $1 ORDER BY expires_at_ns, id LIMIT $2`, timeNano(now), limit)
	if err != nil {
		return nil, fmt.Errorf("usageledger/postgres: find expired reservations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var result []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		result = append(result, id)
	}
	return result, rows.Err()
}

func expireReservationByIDTx(
	ctx context.Context, tx *sql.Tx, id string, now time.Time,
) (bool, error) {
	identity, err := loadReservationTx(ctx, tx, id, false)
	if err != nil {
		return false, err
	}
	key := keyFor(identity.TenantID, identity.Dimension, identity.Period)
	_, err = lockBucketTx(ctx, tx, key, now)
	if err != nil {
		return false, err
	}
	reservation, err := loadReservationTx(ctx, tx, id, true)
	if err != nil {
		return false, err
	}
	if reservation.Status != ledger.ReservationPending || reservation.ExpiresAt.After(now) {
		return false, nil
	}
	_, err = tx.ExecContext(ctx, `UPDATE usage_ledger_reservations SET
status='expired', version=version+1, updated_at_ns=$2 WHERE id=$1`, id, timeNano(now))
	if err != nil {
		return false, fmt.Errorf("usageledger/postgres: expire reservation: %w", err)
	}
	if err := addReservedTx(ctx, tx, key, -reservation.Quantity, now); err != nil {
		return false, err
	}
	return true, nil
}

func loadReservationTx(
	ctx context.Context, tx *sql.Tx, id string, locked bool,
) (*ledger.Reservation, error) {
	query := `SELECT ` + reservationColumns + ` FROM usage_ledger_reservations WHERE id=$1`
	if locked {
		query += ` FOR UPDATE`
	}
	reservation, err := scanReservation(tx.QueryRowContext(ctx, query, id))
	return reservation, notFound(err, ledger.ErrReservationNotFound)
}

func loadBoundReservationTx(
	ctx context.Context, tx *sql.Tx, identity ledger.ReservationIdentity, locked bool,
) (*ledger.Reservation, error) {
	query := `SELECT ` + reservationColumns + ` FROM usage_ledger_reservations
WHERE id=$1 AND tenant_id=$2 AND source_system=$3`
	if locked {
		query += ` FOR UPDATE`
	}
	reservation, err := scanReservation(tx.QueryRowContext(
		ctx, query, identity.ID, identity.TenantID, identity.SourceSystem,
	))
	return reservation, notFound(err, ledger.ErrReservationNotFound)
}

func (s *Store) GetReservation(
	ctx context.Context, identity ledger.ReservationIdentity,
) (*ledger.Reservation, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	query := `SELECT ` + reservationColumns + ` FROM usage_ledger_reservations
WHERE id=$1 AND tenant_id=$2 AND source_system=$3`
	reservation, err := scanReservation(s.db.QueryRowContext(
		ctx, query, identity.ID, identity.TenantID, identity.SourceSystem,
	))
	return reservation, notFound(err, ledger.ErrReservationNotFound)
}

func readReservations(rows *sql.Rows) ([]*ledger.Reservation, error) {
	defer func() { _ = rows.Close() }()
	result := make([]*ledger.Reservation, 0)
	for rows.Next() {
		reservation, err := scanReservation(rows)
		if err != nil {
			return nil, fmt.Errorf("usageledger/postgres: scan reservation: %w", err)
		}
		result = append(result, reservation)
	}
	return result, rows.Err()
}

func factMatchesReservation(fact *ledger.UsageFact, reservation *ledger.Reservation) bool {
	return fact.TenantID == reservation.TenantID && fact.SourceSystem == reservation.SourceSystem &&
		fact.Dimension == reservation.Dimension && fact.Quantity == reservation.Quantity &&
		timeNano(fact.Period.Start) == timeNano(reservation.Period.Start) &&
		timeNano(fact.Period.End) == timeNano(reservation.Period.End)
}

func cloneReservation(reservation *ledger.Reservation) *ledger.Reservation {
	if reservation == nil {
		return nil
	}
	copy := *reservation
	return &copy
}
