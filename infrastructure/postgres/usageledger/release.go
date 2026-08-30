package usageledger

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
)

func (s *Store) ReleaseReservation(
	ctx context.Context, identity ledger.ReservationIdentity, now time.Time,
) (*ledger.Reservation, error) {
	return s.releaseReservation(ctx, identity, now, nil, "")
}

func (s *Store) ReleaseReservationAuthorized(
	ctx context.Context, identity ledger.ReservationIdentity, now time.Time,
	evidence ledger.SourceBindingEvidence, idempotencyKey string,
) (*ledger.Reservation, error) {
	return s.releaseReservation(ctx, identity, now, &evidence, idempotencyKey)
}

func (s *Store) releaseReservation(
	ctx context.Context, identity ledger.ReservationIdentity, now time.Time,
	evidence *ledger.SourceBindingEvidence, idempotencyKey string,
) (*ledger.Reservation, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	var reservation *ledger.Reservation
	err := runLocked(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		reservation, err = releaseReservationTx(ctx, tx, identity, now, evidence, idempotencyKey)
		return err
	})
	return reservation, err
}

func releaseReservationTx(
	ctx context.Context, tx *sql.Tx, identity ledger.ReservationIdentity, now time.Time,
	evidence *ledger.SourceBindingEvidence, idempotencyKey string,
) (*ledger.Reservation, error) {
	reservationIdentity, err := loadBoundReservationTx(ctx, tx, identity, false)
	if err != nil {
		return nil, err
	}
	if err := verifySourceBindingTx(
		ctx, tx, evidence, reservationIdentity.TenantID,
		reservationIdentity.SourceSystem, reservationIdentity.Dimension,
	); err != nil {
		return nil, err
	}
	state, err := lockBucketTx(ctx, tx,
		keyFor(reservationIdentity.TenantID, reservationIdentity.Dimension, reservationIdentity.Period), now)
	if err != nil {
		return nil, err
	}
	if err := expireBucketTx(ctx, tx, &state, now); err != nil {
		return nil, err
	}
	reservation, err := loadBoundReservationTx(ctx, tx, identity, true)
	if err != nil {
		return nil, err
	}
	if reservation.Status == ledger.ReservationReleased || reservation.Status == ledger.ReservationExpired {
		return replayTerminalReleaseTx(ctx, tx, reservation, idempotencyKey)
	}
	if reservation.Status != ledger.ReservationPending {
		return nil, ledger.ErrReservationConflict
	}
	if err := adoptReleaseKey(reservation, idempotencyKey); err != nil {
		return nil, err
	}
	if err := setReservationReleasedTx(ctx, tx, reservation, now); err != nil {
		return nil, err
	}
	if err := addReservedTx(ctx, tx, state.key, -reservation.Quantity, now); err != nil {
		return nil, err
	}
	reservation.Status, reservation.UpdatedAt = ledger.ReservationReleased, now
	reservation.Version++
	return reservation, nil
}

func replayTerminalReleaseTx(
	ctx context.Context, tx *sql.Tx, reservation *ledger.Reservation, idempotencyKey string,
) (*ledger.Reservation, error) {
	previousKey := reservation.ReleaseIdempotencyKey
	if err := adoptReleaseKey(reservation, idempotencyKey); err != nil {
		return nil, err
	}
	if previousKey == "" && idempotencyKey != "" {
		if err := persistReleaseKeyTx(ctx, tx, reservation, idempotencyKey); err != nil {
			return nil, err
		}
	}
	return reservation, nil
}

func setReservationReleasedTx(
	ctx context.Context, tx *sql.Tx, reservation *ledger.Reservation, now time.Time,
) error {
	result, err := tx.ExecContext(ctx, `UPDATE usage_ledger_reservations SET
status='released', release_idempotency_key=$2, version=version+1, updated_at_ns=$3
WHERE id=$1 AND status='pending' AND version=$4`,
		reservation.ID, reservation.ReleaseIdempotencyKey, timeNano(now), reservation.Version)
	if err != nil {
		if uniqueViolation(err) {
			return ledger.ErrIdempotencyConflict
		}
		return fmt.Errorf("usageledger/postgres: release reservation: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil || updated != 1 {
		return ledger.ErrReservationConflict
	}
	return nil
}

func persistReleaseKeyTx(
	ctx context.Context, tx *sql.Tx, reservation *ledger.Reservation, key string,
) error {
	if key == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `UPDATE usage_ledger_reservations
SET release_idempotency_key=$2 WHERE id=$1`, reservation.ID, key)
	if err != nil {
		if uniqueViolation(err) {
			return ledger.ErrIdempotencyConflict
		}
		return fmt.Errorf("usageledger/postgres: persist release idempotency: %w", err)
	}
	return nil
}

func adoptReleaseKey(reservation *ledger.Reservation, key string) error {
	if key == "" {
		return nil
	}
	if !validReleaseIdempotencyKey(key) {
		return ledger.ErrInvalidReservation
	}
	if reservation.ReleaseIdempotencyKey != "" && reservation.ReleaseIdempotencyKey != key {
		return ledger.ErrIdempotencyConflict
	}
	reservation.ReleaseIdempotencyKey = key
	return nil
}

func validReleaseIdempotencyKey(key string) bool {
	return key != "" && len(key) <= 256 && key == strings.TrimSpace(key)
}
