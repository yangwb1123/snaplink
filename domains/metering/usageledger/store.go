package usageledger

import (
	"context"
	"errors"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

var (
	ErrStoreRequired       = errors.New("usage ledger: store required")
	ErrInvalidPeriod       = errors.New("usage ledger: invalid period")
	ErrInvalidFact         = errors.New("usage ledger: invalid fact")
	ErrInvalidReservation  = errors.New("usage ledger: invalid reservation")
	ErrFactNotFound        = errors.New("usage ledger: fact not found")
	ErrReservationNotFound = errors.New("usage ledger: reservation not found")
	ErrReservationConflict = errors.New("usage ledger: reservation conflict")
	ErrIdempotencyConflict = errors.New("usage ledger: idempotency conflict")
	ErrQuotaExceeded       = errors.New("usage ledger: quota exceeded")
	ErrCounterOverflow     = errors.New("usage ledger: counter overflow")
	ErrPeriodClosed        = errors.New("usage ledger: period closed")
	ErrActiveReservations  = errors.New("usage ledger: active reservations")
	ErrEntitlementMissing  = errors.New("usage ledger: entitlement missing")
	ErrRollupNotFound      = errors.New("usage ledger: rollup not found")
	ErrUsageTimeInvalid    = errors.New("usage ledger: usage time invalid")
)

type AppendCommand struct {
	Fact     *UsageFact
	Limit    commerce.LimitGrant
	Evidence *SourceBindingEvidence
}

type ReserveCommand struct {
	Reservation *Reservation
	Limit       commerce.LimitGrant
	Evidence    *SourceBindingEvidence
}

// ReservationIdentity is the authorization boundary for reservation
// mutations. Public callers must never address a reservation by its opaque ID
// alone: an ID learned from another tenant or source must behave as missing.
type ReservationIdentity struct {
	ID           string
	TenantID     string
	SourceSystem string
}

func (i ReservationIdentity) Validate() error {
	if i.ID == "" || i.TenantID == "" || i.SourceSystem == "" {
		return ErrInvalidReservation
	}
	return nil
}

type ClosePeriodCommand struct {
	RollupID  string
	EventID   string
	TenantID  string
	Dimension Dimension
	Period    Period
	ClosedAt  time.Time
}

type FactStore interface {
	AppendFact(ctx context.Context, command AppendCommand) (*UsageFact, *Counter, error)
	GetFact(ctx context.Context, id string) (*UsageFact, error)
	ListFacts(ctx context.Context, tenantID string, dimension Dimension, period Period) ([]*UsageFact, error)
}

type ReservationStore interface {
	Reserve(ctx context.Context, command ReserveCommand) (*Reservation, *Counter, error)
	GetReservation(ctx context.Context, identity ReservationIdentity) (*Reservation, error)
	CommitReservation(ctx context.Context, identity ReservationIdentity, fact *UsageFact) (*Reservation, *Counter, error)
	ReleaseReservation(ctx context.Context, identity ReservationIdentity, now time.Time) (*Reservation, error)
	SweepExpiredReservations(ctx context.Context, now time.Time, limit int) (int, error)
}

type AuthorizedReservationStore interface {
	CommitReservationAuthorized(
		ctx context.Context, identity ReservationIdentity, fact *UsageFact, evidence SourceBindingEvidence,
	) (*Reservation, *Counter, error)
	ReleaseReservationAuthorized(
		ctx context.Context, identity ReservationIdentity, now time.Time, evidence SourceBindingEvidence,
		idempotencyKey string,
	) (*Reservation, error)
}

type RollupStore interface {
	ClosePeriod(ctx context.Context, command ClosePeriodCommand) (*Rollup, error)
	GetRollup(ctx context.Context, tenantID string, dimension Dimension, period Period) (*Rollup, error)
}

type Store interface {
	FactStore
	ReservationStore
	AuthorizedReservationStore
	RollupStore
	commerce.OutboxStore
}
