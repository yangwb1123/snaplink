package usageledger

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type IDGenerator func(prefix string) (string, error)

type Service struct {
	store        Store
	entitlements commerce.EntitlementReader
	now          func() time.Time
	newID        IDGenerator
}

func NewService(
	store Store, entitlements commerce.EntitlementReader, now func() time.Time, newID IDGenerator,
) (*Service, error) {
	if store == nil || entitlements == nil {
		return nil, ErrStoreRequired
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if newID == nil {
		newID = randomID
	}
	return &Service{store: store, entitlements: entitlements, now: now, newID: newID}, nil
}

func randomID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}

type UsageCommand struct {
	ID             string
	TenantID       string
	SourceSystem   string
	Dimension      Dimension
	Quantity       int64
	Period         Period
	IdempotencyKey string
	OccurredAt     time.Time
	Metadata       map[string]string
}

func (s *Service) Append(ctx context.Context, command UsageCommand) (*UsageFact, *Counter, error) {
	return s.append(ctx, command, nil)
}

func (s *Service) append(
	ctx context.Context, command UsageCommand, evidence *SourceBindingEvidence,
) (*UsageFact, *Counter, error) {
	limit, err := s.entitledLimit(ctx, command.TenantID, command.Dimension)
	if err != nil {
		return nil, nil, err
	}
	fact, err := s.newFact(command)
	if err != nil {
		return nil, nil, err
	}
	return s.store.AppendFact(ctx, AppendCommand{Fact: fact, Limit: limit, Evidence: evidence})
}

type ReservationCommand struct {
	ID             string
	TenantID       string
	SourceSystem   string
	Dimension      Dimension
	Quantity       int64
	Period         Period
	IdempotencyKey string
	TTL            time.Duration
}

func (s *Service) Reserve(
	ctx context.Context, command ReservationCommand,
) (*Reservation, *Counter, error) {
	return s.reserve(ctx, command, nil)
}

func (s *Service) reserve(
	ctx context.Context, command ReservationCommand, evidence *SourceBindingEvidence,
) (*Reservation, *Counter, error) {
	limit, err := s.entitledLimit(ctx, command.TenantID, command.Dimension)
	if err != nil {
		return nil, nil, err
	}
	reservation, err := s.newReservation(command, limit)
	if err != nil {
		return nil, nil, err
	}
	return s.store.Reserve(ctx, ReserveCommand{
		Reservation: reservation, Limit: limit, Evidence: evidence,
	})
}

func (s *Service) Commit(
	ctx context.Context, identity ReservationIdentity, command UsageCommand,
) (*Reservation, *Counter, error) {
	if err := identity.Validate(); err != nil {
		return nil, nil, err
	}
	command.TenantID, command.SourceSystem = identity.TenantID, identity.SourceSystem
	fact, err := s.newFact(command)
	if err != nil {
		return nil, nil, err
	}
	return s.store.CommitReservation(ctx, identity, fact)
}

func (s *Service) Release(ctx context.Context, identity ReservationIdentity) (*Reservation, error) {
	if err := identity.Validate(); err != nil {
		return nil, err
	}
	return s.store.ReleaseReservation(ctx, identity, s.now())
}

const maxMachineUsageBackfill = 35 * 24 * time.Hour

// AppendAuthorized canonicalizes the billing bucket and carries binding
// evidence into the durable transaction. Machine callers cannot choose an
// arbitrary or overlapping Period.
func (s *Service) AppendAuthorized(
	ctx context.Context, evidence SourceBindingEvidence, command UsageCommand,
) (*UsageFact, *Counter, error) {
	if err := evidence.Validate(); err != nil {
		return nil, nil, err
	}
	now := s.now()
	if command.OccurredAt.IsZero() {
		command.OccurredAt = now
	}
	if command.OccurredAt.After(now) || command.OccurredAt.Before(now.Add(-maxMachineUsageBackfill)) {
		return nil, nil, ErrUsageTimeInvalid
	}
	command.TenantID, command.SourceSystem = evidence.TenantID, evidence.SourceSystem
	command.Period = MonthlyPeriod(command.OccurredAt)
	return s.append(ctx, command, &evidence)
}

func (s *Service) ReserveAuthorized(
	ctx context.Context, evidence SourceBindingEvidence, command ReservationCommand,
) (*Reservation, *Counter, error) {
	if err := evidence.Validate(); err != nil {
		return nil, nil, err
	}
	command.TenantID, command.SourceSystem = evidence.TenantID, evidence.SourceSystem
	command.Period = MonthlyPeriod(s.now())
	return s.reserve(ctx, command, &evidence)
}

type AuthorizedCommitCommand struct {
	ID             string
	IdempotencyKey string
	Metadata       map[string]string
}

func (s *Service) CommitAuthorized(
	ctx context.Context, evidence SourceBindingEvidence, reservationID string,
	command AuthorizedCommitCommand,
) (*Reservation, *Counter, error) {
	identity, err := authorizedReservationIdentity(evidence, reservationID)
	if err != nil {
		return nil, nil, err
	}
	reservation, err := s.store.GetReservation(ctx, identity)
	if err != nil {
		return nil, nil, err
	}
	fact, err := s.newFact(UsageCommand{
		ID: command.ID, TenantID: identity.TenantID, SourceSystem: identity.SourceSystem,
		Dimension: reservation.Dimension, Quantity: reservation.Quantity, Period: reservation.Period,
		IdempotencyKey: command.IdempotencyKey, OccurredAt: reservation.CreatedAt,
		Metadata: command.Metadata,
	})
	if err != nil {
		return nil, nil, err
	}
	return s.store.CommitReservationAuthorized(ctx, identity, fact, evidence)
}

func (s *Service) ReleaseAuthorized(
	ctx context.Context, evidence SourceBindingEvidence, reservationID string,
) (*Reservation, error) {
	identity, err := authorizedReservationIdentity(evidence, reservationID)
	if err != nil {
		return nil, err
	}
	return s.store.ReleaseReservationAuthorized(ctx, identity, s.now(), evidence)
}

func authorizedReservationIdentity(
	evidence SourceBindingEvidence, reservationID string,
) (ReservationIdentity, error) {
	if err := evidence.Validate(); err != nil {
		return ReservationIdentity{}, err
	}
	identity := ReservationIdentity{
		ID: reservationID, TenantID: evidence.TenantID, SourceSystem: evidence.SourceSystem,
	}
	return identity, identity.Validate()
}

func (s *Service) ClosePeriod(
	ctx context.Context, tenantID string, dimension Dimension, period Period,
) (*Rollup, error) {
	rollupID, err := s.newID("rollup")
	if err != nil {
		return nil, err
	}
	eventID, err := s.newID("evt")
	if err != nil {
		return nil, err
	}
	return s.store.ClosePeriod(ctx, ClosePeriodCommand{
		RollupID: rollupID, EventID: eventID, TenantID: tenantID,
		Dimension: dimension, Period: period, ClosedAt: s.now(),
	})
}

func (s *Service) entitledLimit(
	ctx context.Context, tenantID string, dimension Dimension,
) (commerce.LimitGrant, error) {
	snapshot, err := s.entitlements.CurrentEntitlement(ctx, tenantID)
	if err != nil {
		return commerce.LimitGrant{}, err
	}
	limit, ok := snapshot.Limit(limitKey(dimension), s.now())
	if !ok {
		return commerce.LimitGrant{}, ErrEntitlementMissing
	}
	return limit, nil
}

func (s *Service) newFact(command UsageCommand) (*UsageFact, error) {
	id, err := s.id(command.ID, "usage")
	if err != nil {
		return nil, err
	}
	now := s.now()
	fact := &UsageFact{
		ID: id, TenantID: command.TenantID, SourceSystem: command.SourceSystem,
		Dimension: command.Dimension, Quantity: command.Quantity, Period: command.Period,
		IdempotencyKey: command.IdempotencyKey, OccurredAt: command.OccurredAt,
		CreatedAt: now, Metadata: command.Metadata,
	}
	if fact.OccurredAt.IsZero() {
		fact.OccurredAt = now
	}
	return fact, fact.Validate()
}

func (s *Service) newReservation(
	command ReservationCommand, limit commerce.LimitGrant,
) (*Reservation, error) {
	id, err := s.id(command.ID, "reserve")
	if err != nil {
		return nil, err
	}
	if command.TTL <= 0 || command.TTL > maxReservationTTL {
		return nil, errors.Join(ErrInvalidReservation, errors.New("ttl must be between zero and 24 hours"))
	}
	now := s.now()
	reservation := &Reservation{
		ID: id, TenantID: command.TenantID, SourceSystem: command.SourceSystem,
		Dimension: command.Dimension, Quantity: command.Quantity, Period: command.Period,
		IdempotencyKey: command.IdempotencyKey, Status: ReservationPending,
		Limit:     limit,
		ExpiresAt: now.Add(command.TTL), Version: 1, CreatedAt: now, UpdatedAt: now,
	}
	return reservation, reservation.Validate()
}

func (s *Service) id(id, prefix string) (string, error) {
	if id != "" {
		return id, nil
	}
	return s.newID(prefix)
}
