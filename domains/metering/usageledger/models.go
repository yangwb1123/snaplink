// Package usageledger provides invoice-grade usage facts and quota
// reservations. Unlike best-effort telemetry, accepted facts are durable and
// idempotent; resource services may enforce limits atomically through it.
package usageledger

import (
	"errors"
	"maps"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type Dimension string

type Period struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

func (p Period) Validate() error {
	if p.Start.IsZero() || p.End.IsZero() || !p.Start.Before(p.End) {
		return ErrInvalidPeriod
	}
	return nil
}

func MonthlyPeriod(at time.Time) Period {
	at = at.UTC()
	start := time.Date(at.Year(), at.Month(), 1, 0, 0, 0, 0, time.UTC)
	return Period{Start: start, End: start.AddDate(0, 1, 0)}
}

type UsageFact struct {
	ID             string            `json:"id"`
	TenantID       string            `json:"tenant_id"`
	SourceSystem   string            `json:"source_system"`
	Dimension      Dimension         `json:"dimension"`
	Quantity       int64             `json:"quantity"`
	Period         Period            `json:"period"`
	IdempotencyKey string            `json:"idempotency_key"`
	OccurredAt     time.Time         `json:"occurred_at"`
	CreatedAt      time.Time         `json:"created_at"`
	Metadata       map[string]string `json:"metadata,omitempty"`
}

func (f *UsageFact) Validate() error {
	if f == nil || f.ID == "" || f.TenantID == "" || f.SourceSystem == "" || f.Dimension == "" {
		return errors.Join(ErrInvalidFact, errors.New("fact identity is required"))
	}
	if f.Quantity <= 0 || f.IdempotencyKey == "" || f.OccurredAt.IsZero() || f.CreatedAt.IsZero() {
		return errors.Join(ErrInvalidFact, errors.New("fact quantity, time or idempotency is invalid"))
	}
	if err := f.Period.Validate(); err != nil {
		return errors.Join(ErrInvalidFact, err)
	}
	if f.OccurredAt.Before(f.Period.Start) || !f.OccurredAt.Before(f.Period.End) {
		return errors.Join(ErrInvalidFact, errors.New("occurred_at is outside period"))
	}
	return validateMetadata(f.Metadata)
}

func validateMetadata(metadata map[string]string) error {
	if len(metadata) > 16 {
		return errors.Join(ErrInvalidFact, errors.New("too many metadata fields"))
	}
	for key, value := range metadata {
		normalized := strings.ToLower(strings.TrimSpace(key))
		if normalized == "" || len(key) > 64 || len(value) > 256 || sensitiveMetadataKey(normalized) {
			return errors.Join(ErrInvalidFact, errors.New("metadata field is invalid"))
		}
	}
	return nil
}

func sensitiveMetadataKey(key string) bool {
	for _, forbidden := range []string{"password", "token", "secret", "credential", "authorization", "pan", "cvv"} {
		if strings.Contains(key, forbidden) {
			return true
		}
	}
	return false
}

type ReservationStatus string

const maxReservationTTL = 24 * time.Hour

const (
	ReservationPending   ReservationStatus = "pending"
	ReservationCommitted ReservationStatus = "committed"
	ReservationReleased  ReservationStatus = "released"
	ReservationExpired   ReservationStatus = "expired"
)

type Reservation struct {
	ID             string              `json:"id"`
	TenantID       string              `json:"tenant_id"`
	SourceSystem   string              `json:"source_system"`
	Dimension      Dimension           `json:"dimension"`
	Quantity       int64               `json:"quantity"`
	Period         Period              `json:"period"`
	IdempotencyKey string              `json:"idempotency_key"`
	Status         ReservationStatus   `json:"status"`
	Limit          commerce.LimitGrant `json:"limit"`
	ExpiresAt      time.Time           `json:"expires_at"`
	FactID         string              `json:"fact_id,omitempty"`
	// ReleaseIdempotencyKey is persisted but never returned to callers. An
	// empty value marks a reservation created before DELETE idempotency was
	// introduced; its first keyed release adopts the key atomically.
	ReleaseIdempotencyKey string    `json:"-"`
	Version               uint64    `json:"version"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func (r *Reservation) Validate() error {
	if err := r.validateIdentity(); err != nil {
		return err
	}
	if err := r.Period.Validate(); err != nil {
		return errors.Join(ErrInvalidReservation, err)
	}
	if err := r.validateLifetime(); err != nil {
		return err
	}
	if !validReservationStatus(r.Status) {
		return errors.Join(ErrInvalidReservation, errors.New("reservation status is invalid"))
	}
	return r.Limit.Validate()
}

func (r *Reservation) validateIdentity() error {
	if r == nil || r.ID == "" || r.TenantID == "" || r.SourceSystem == "" || r.Dimension == "" {
		return errors.Join(ErrInvalidReservation, errors.New("reservation identity is required"))
	}
	return nil
}

func (r *Reservation) validateLifetime() error {
	if r.Quantity <= 0 || r.IdempotencyKey == "" || r.Version == 0 || r.ExpiresAt.IsZero() ||
		r.CreatedAt.IsZero() || r.CreatedAt.Before(r.Period.Start) || !r.CreatedAt.Before(r.Period.End) ||
		!r.ExpiresAt.After(r.CreatedAt) || r.ExpiresAt.After(r.CreatedAt.Add(maxReservationTTL)) {
		return errors.Join(ErrInvalidReservation, errors.New("reservation quantity or lifetime is invalid"))
	}
	return nil
}

func validReservationStatus(status ReservationStatus) bool {
	switch status {
	case ReservationPending, ReservationCommitted, ReservationReleased, ReservationExpired:
		return true
	default:
		return false
	}
}

type Counter struct {
	TenantID     string    `json:"tenant_id"`
	Dimension    Dimension `json:"dimension"`
	Period       Period    `json:"period"`
	Committed    int64     `json:"committed"`
	Reserved     int64     `json:"reserved"`
	Projected    int64     `json:"projected"`
	HardLimit    int64     `json:"hard_limit"`
	Unlimited    bool      `json:"unlimited,omitempty"`
	SoftExceeded bool      `json:"soft_exceeded,omitempty"`
	Remaining    int64     `json:"remaining,omitempty"`
}

type Rollup struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Dimension Dimension `json:"dimension"`
	Period    Period    `json:"period"`
	Quantity  int64     `json:"quantity"`
	FactCount int64     `json:"fact_count"`
	Version   uint64    `json:"version"`
	Digest    string    `json:"digest"`
	ClosedAt  time.Time `json:"closed_at"`
}

func cloneFact(fact *UsageFact) *UsageFact {
	if fact == nil {
		return nil
	}
	copy := *fact
	copy.Metadata = maps.Clone(fact.Metadata)
	return &copy
}

func cloneReservation(reservation *Reservation) *Reservation {
	if reservation == nil {
		return nil
	}
	copy := *reservation
	return &copy
}

func cloneRollup(rollup *Rollup) *Rollup {
	if rollup == nil {
		return nil
	}
	copy := *rollup
	return &copy
}

func limitKey(dimension Dimension) commerce.LimitKey { return commerce.LimitKey(dimension) }
