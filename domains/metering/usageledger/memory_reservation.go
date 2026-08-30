package usageledger

import (
	"context"
	"time"
)

func (s *MemoryStore) Reserve(
	ctx context.Context, command ReserveCommand,
) (*Reservation, *Counter, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := validateReserve(command); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateEvidenceLocked(
		command.Evidence, command.Reservation.TenantID,
		command.Reservation.SourceSystem, command.Reservation.Dimension,
	); err != nil {
		return nil, nil, err
	}
	if reservation, counter, ok, err := s.reservationReplayLocked(command); ok || err != nil {
		return reservation, counter, err
	}
	if _, exists := s.reservations[command.Reservation.ID]; exists {
		return nil, nil, ErrIdempotencyConflict
	}
	key := bucketFor(command.Reservation.TenantID, command.Reservation.Dimension, command.Reservation.Period)
	if _, closed := s.rollups[key]; closed {
		return nil, nil, ErrPeriodClosed
	}
	counter := s.counterLocked(key, command.Reservation.CreatedAt, command.Limit)
	if additionOverflows(counter.Projected, command.Reservation.Quantity) {
		return nil, counter, ErrCounterOverflow
	}
	if !withinLimit(counter.Projected, command.Reservation.Quantity, command.Limit) {
		return nil, counter, ErrQuotaExceeded
	}
	reservation := cloneReservation(command.Reservation)
	s.reservations[reservation.ID] = reservation
	s.reservationKeys[reservationIdempotencyKey(reservation)] = reservation.ID
	s.reservationsByBucket[key] = append(s.reservationsByBucket[key], reservation.ID)
	counter = s.counterLocked(key, reservation.CreatedAt, command.Limit)
	return cloneReservation(reservation), counter, nil
}

func validateReserve(command ReserveCommand) error {
	if err := command.Reservation.Validate(); err != nil {
		return err
	}
	if err := command.Limit.Validate(); err != nil {
		return err
	}
	if command.Reservation.Limit != command.Limit {
		return ErrInvalidReservation
	}
	return nil
}

func (s *MemoryStore) reservationReplayLocked(
	command ReserveCommand,
) (*Reservation, *Counter, bool, error) {
	key := reservationIdempotencyKey(command.Reservation)
	id, ok := s.reservationKeys[key]
	if !ok {
		return nil, nil, false, nil
	}
	current := s.reservations[id]
	if !sameReservationCommand(current, command.Reservation) {
		return nil, nil, true, ErrIdempotencyConflict
	}
	bucket := bucketFor(current.TenantID, current.Dimension, current.Period)
	counter := s.counterLocked(bucket, command.Reservation.CreatedAt, command.Limit)
	return cloneReservation(current), counter, true, nil
}

func (s *MemoryStore) CommitReservation(
	ctx context.Context, identity ReservationIdentity, fact *UsageFact,
) (*Reservation, *Counter, error) {
	return s.commitReservation(ctx, identity, fact, nil)
}

func (s *MemoryStore) CommitReservationAuthorized(
	ctx context.Context, identity ReservationIdentity, fact *UsageFact, evidence SourceBindingEvidence,
) (*Reservation, *Counter, error) {
	return s.commitReservation(ctx, identity, fact, &evidence)
}

func (s *MemoryStore) commitReservation(
	ctx context.Context, identity ReservationIdentity, fact *UsageFact, evidence *SourceBindingEvidence,
) (*Reservation, *Counter, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := identity.Validate(); err != nil {
		return nil, nil, err
	}
	if err := fact.Validate(); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation, ok := s.reservations[identity.ID]
	if !ok || !reservationBoundTo(reservation, identity) {
		return nil, nil, ErrReservationNotFound
	}
	if err := s.validateEvidenceLocked(
		evidence, reservation.TenantID, reservation.SourceSystem, reservation.Dimension,
	); err != nil {
		return nil, nil, err
	}
	if reservation.Status == ReservationCommitted {
		return s.committedReplayLocked(reservation, fact)
	}
	if reservation.Status != ReservationPending || !reservation.ExpiresAt.After(fact.CreatedAt) {
		return nil, nil, ErrReservationConflict
	}
	if !factMatchesReservation(fact, reservation) {
		return nil, nil, ErrReservationConflict
	}
	key := bucketFor(reservation.TenantID, reservation.Dimension, reservation.Period)
	if _, closed := s.rollups[key]; closed {
		return nil, nil, ErrPeriodClosed
	}
	if _, exists := s.factKeys[factIdempotencyKey(fact)]; exists {
		return nil, nil, ErrIdempotencyConflict
	}
	if _, exists := s.facts[fact.ID]; exists {
		return nil, nil, ErrIdempotencyConflict
	}
	s.commitFactLocked(key, cloneFact(fact))
	reservation.Status, reservation.FactID = ReservationCommitted, fact.ID
	reservation.Version++
	reservation.UpdatedAt = fact.CreatedAt
	counter := s.counterLocked(key, fact.CreatedAt, reservation.Limit)
	return cloneReservation(reservation), counter, nil
}

func (s *MemoryStore) committedReplayLocked(
	reservation *Reservation, fact *UsageFact,
) (*Reservation, *Counter, error) {
	current := s.facts[reservation.FactID]
	if !sameFact(current, fact) {
		return nil, nil, ErrIdempotencyConflict
	}
	key := bucketFor(reservation.TenantID, reservation.Dimension, reservation.Period)
	counter := s.counterLocked(key, fact.CreatedAt, reservation.Limit)
	return cloneReservation(reservation), counter, nil
}

func (s *MemoryStore) ReleaseReservation(
	ctx context.Context, identity ReservationIdentity, now time.Time,
) (*Reservation, error) {
	return s.releaseReservation(ctx, identity, now, nil, "")
}

func (s *MemoryStore) ReleaseReservationAuthorized(
	ctx context.Context, identity ReservationIdentity, now time.Time, evidence SourceBindingEvidence,
	idempotencyKey string,
) (*Reservation, error) {
	return s.releaseReservation(ctx, identity, now, &evidence, idempotencyKey)
}

func (s *MemoryStore) releaseReservation(
	ctx context.Context, identity ReservationIdentity, now time.Time, evidence *SourceBindingEvidence,
	idempotencyKey string,
) (*Reservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation, ok := s.reservations[identity.ID]
	if !ok || !reservationBoundTo(reservation, identity) {
		return nil, ErrReservationNotFound
	}
	if err := s.validateEvidenceLocked(
		evidence, reservation.TenantID, reservation.SourceSystem, reservation.Dimension,
	); err != nil {
		return nil, err
	}
	if reservation.Status == ReservationPending && !reservation.ExpiresAt.After(now) {
		reservation.Status, reservation.UpdatedAt = ReservationExpired, now
		reservation.Version++
	}
	if reservation.Status == ReservationReleased || reservation.Status == ReservationExpired {
		if err := s.adoptReleaseKeyLocked(reservation, idempotencyKey); err != nil {
			return nil, err
		}
		return cloneReservation(reservation), nil
	}
	if reservation.Status != ReservationPending {
		return nil, ErrReservationConflict
	}
	if err := s.adoptReleaseKeyLocked(reservation, idempotencyKey); err != nil {
		return nil, err
	}
	reservation.Status, reservation.UpdatedAt = ReservationReleased, now
	reservation.Version++
	return cloneReservation(reservation), nil
}

func (s *MemoryStore) GetReservation(
	ctx context.Context, identity ReservationIdentity,
) (*Reservation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	reservation, ok := s.reservations[identity.ID]
	if !ok || !reservationBoundTo(reservation, identity) {
		return nil, ErrReservationNotFound
	}
	return cloneReservation(reservation), nil
}

func reservationBoundTo(reservation *Reservation, identity ReservationIdentity) bool {
	return reservation != nil && reservation.TenantID == identity.TenantID &&
		reservation.SourceSystem == identity.SourceSystem
}

func (s *MemoryStore) adoptReleaseKeyLocked(reservation *Reservation, key string) error {
	if key == "" {
		return nil
	}
	if !validReleaseIdempotencyKey(key) {
		return ErrInvalidReservation
	}
	if reservation.ReleaseIdempotencyKey != "" && reservation.ReleaseIdempotencyKey != key {
		return ErrIdempotencyConflict
	}
	keyID := joinKey(reservation.TenantID, reservation.SourceSystem, key)
	if owner, exists := s.releaseKeys[keyID]; exists && owner != reservation.ID {
		return ErrIdempotencyConflict
	}
	reservation.ReleaseIdempotencyKey = key
	s.releaseKeys[keyID] = reservation.ID
	return nil
}

func (s *MemoryStore) SweepExpiredReservations(
	ctx context.Context, now time.Time, limit int,
) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if limit <= 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	count := 0
	for _, reservation := range s.reservations {
		if count >= limit {
			break
		}
		if reservation.Status == ReservationPending && !reservation.ExpiresAt.After(now) {
			reservation.Status, reservation.UpdatedAt = ReservationExpired, now
			reservation.Version++
			count++
		}
	}
	return count, nil
}

func (s *MemoryStore) hasActiveReservationsLocked(key bucketKey, at time.Time) bool {
	for _, id := range s.reservationsByBucket[key] {
		reservation := s.reservations[id]
		if reservation.Status == ReservationPending && reservation.ExpiresAt.After(at) {
			return true
		}
	}
	return false
}

func reservationIdempotencyKey(reservation *Reservation) string {
	return joinKey(
		reservation.TenantID, reservation.SourceSystem,
		string(reservation.Dimension), reservation.IdempotencyKey,
	)
}

func sameReservationCommand(left, right *Reservation) bool {
	if left == nil || right == nil {
		return false
	}
	return left.TenantID == right.TenantID && left.SourceSystem == right.SourceSystem &&
		left.Dimension == right.Dimension && left.Quantity == right.Quantity &&
		periodEqual(left.Period, right.Period) && left.IdempotencyKey == right.IdempotencyKey &&
		left.Limit == right.Limit
}

func factMatchesReservation(fact *UsageFact, reservation *Reservation) bool {
	return fact.TenantID == reservation.TenantID && fact.SourceSystem == reservation.SourceSystem &&
		fact.Dimension == reservation.Dimension && periodEqual(fact.Period, reservation.Period) &&
		fact.Quantity == reservation.Quantity
}

func periodEqual(left, right Period) bool {
	return left.Start.Equal(right.Start) && left.End.Equal(right.End)
}
