package usageledger

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type rowScanner interface {
	Scan(dest ...any) error
}

type bucketKey struct {
	tenantID  string
	dimension ledger.Dimension
	start     int64
	end       int64
}

type bucketState struct {
	key       bucketKey
	committed int64
	reserved  int64
	factCount int64
	closed    bool
}

func keyFor(tenantID string, dimension ledger.Dimension, period ledger.Period) bucketKey {
	return bucketKey{
		tenantID: tenantID, dimension: dimension,
		start: timeNano(period.Start), end: timeNano(period.End),
	}
}

func (b bucketState) counter(limit commerce.LimitGrant) *ledger.Counter {
	projected := b.committed + b.reserved
	counter := &ledger.Counter{
		TenantID: b.key.tenantID, Dimension: b.key.dimension,
		Period:    ledger.Period{Start: nanoTime(b.key.start), End: nanoTime(b.key.end)},
		Committed: b.committed, Reserved: b.reserved, Projected: projected,
		HardLimit: limit.Hard, Unlimited: limit.Unlimited,
		SoftExceeded: limit.Soft > 0 && projected > limit.Soft,
	}
	if !limit.Unlimited {
		counter.Remaining = max(0, limit.Hard-projected)
	}
	return counter
}

func withinLimit(current, delta int64, limit commerce.LimitGrant) bool {
	return limit.Unlimited || (delta <= limit.Hard && current <= limit.Hard-delta)
}

func encodeJSON(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("usageledger/postgres: encode JSON: %w", err)
	}
	return string(encoded), nil
}

func decodeJSON(encoded []byte, target any) error {
	if err := json.Unmarshal(encoded, target); err != nil {
		return fmt.Errorf("usageledger/postgres: decode JSON: %w", err)
	}
	return nil
}

func timeNano(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UTC().UnixNano()
}

func nanoTime(value int64) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(0, value).UTC()
}

const factColumns = `id, tenant_id, source_system, dimension, quantity,
period_start_ns, period_end_ns, idempotency_key, occurred_at_ns, created_at_ns, metadata`

func scanFact(scanner rowScanner) (*ledger.UsageFact, error) {
	fact := &ledger.UsageFact{}
	var dimension string
	var start, end, occurred, created int64
	var metadata []byte
	err := scanner.Scan(
		&fact.ID, &fact.TenantID, &fact.SourceSystem, &dimension, &fact.Quantity,
		&start, &end, &fact.IdempotencyKey, &occurred, &created, &metadata,
	)
	if err != nil {
		return nil, err
	}
	fact.Dimension = ledger.Dimension(dimension)
	fact.Period = ledger.Period{Start: nanoTime(start), End: nanoTime(end)}
	fact.OccurredAt, fact.CreatedAt = nanoTime(occurred), nanoTime(created)
	if err := decodeJSON(metadata, &fact.Metadata); err != nil {
		return nil, err
	}
	return fact, nil
}

const reservationColumns = `id, tenant_id, source_system, dimension, quantity,
period_start_ns, period_end_ns, idempotency_key, status, limit_soft, limit_hard,
limit_unlimited, expires_at_ns, fact_id, release_idempotency_key, version, created_at_ns, updated_at_ns`

func scanReservation(scanner rowScanner) (*ledger.Reservation, error) {
	reservation := &ledger.Reservation{}
	var dimension, status string
	var start, end, expires, created, updated int64
	err := scanner.Scan(
		&reservation.ID, &reservation.TenantID, &reservation.SourceSystem, &dimension,
		&reservation.Quantity, &start, &end, &reservation.IdempotencyKey, &status,
		&reservation.Limit.Soft, &reservation.Limit.Hard, &reservation.Limit.Unlimited,
		&expires, &reservation.FactID, &reservation.ReleaseIdempotencyKey,
		&reservation.Version, &created, &updated,
	)
	if err != nil {
		return nil, err
	}
	reservation.Dimension, reservation.Status = ledger.Dimension(dimension), ledger.ReservationStatus(status)
	reservation.Period = ledger.Period{Start: nanoTime(start), End: nanoTime(end)}
	reservation.ExpiresAt, reservation.CreatedAt = nanoTime(expires), nanoTime(created)
	reservation.UpdatedAt = nanoTime(updated)
	return reservation, nil
}

const rollupColumns = `id, tenant_id, dimension, period_start_ns, period_end_ns,
quantity, fact_count, version, digest, closed_at_ns`

func scanRollup(scanner rowScanner) (*ledger.Rollup, error) {
	rollup := &ledger.Rollup{}
	var dimension string
	var start, end, closed int64
	err := scanner.Scan(
		&rollup.ID, &rollup.TenantID, &dimension, &start, &end, &rollup.Quantity,
		&rollup.FactCount, &rollup.Version, &rollup.Digest, &closed,
	)
	if err != nil {
		return nil, err
	}
	rollup.Dimension = ledger.Dimension(dimension)
	rollup.Period = ledger.Period{Start: nanoTime(start), End: nanoTime(end)}
	rollup.ClosedAt = nanoTime(closed)
	return rollup, nil
}

const outboxColumns = `id, tenant_id, event_type, aggregate_type, aggregate_id,
aggregate_version, idempotency_key, occurred_at_ns, payload, payload_digest,
status, attempts, next_attempt_at_ns, lease_owner, lease_until_ns, last_error,
delivered_at_ns, created_at_ns`

func scanOutbox(scanner rowScanner) (*commerce.OutboxEvent, error) {
	event := &commerce.OutboxEvent{}
	var eventType, status string
	var payload []byte
	var occurred, next, lease, delivered, created int64
	err := scanner.Scan(
		&event.ID, &event.TenantID, &eventType, &event.AggregateType, &event.AggregateID,
		&event.AggregateVersion, &event.IdempotencyKey, &occurred, &payload, &event.PayloadDigest,
		&status, &event.Attempts, &next, &event.LeaseOwner, &lease, &event.LastError, &delivered, &created,
	)
	if err != nil {
		return nil, err
	}
	if err := decodeJSON(payload, &event.Payload); err != nil {
		return nil, err
	}
	event.Type, event.Status = commerce.EventType(eventType), commerce.OutboxStatus(status)
	event.OccurredAt, event.NextAttemptAt = nanoTime(occurred), nanoTime(next)
	event.LeaseUntil, event.DeliveredAt, event.CreatedAt = nanoTime(lease), nanoTime(delivered), nanoTime(created)
	return event, nil
}

func sameFact(left, right *ledger.UsageFact) bool {
	if left == nil || right == nil {
		return false
	}
	leftCopy, rightCopy := *left, *right
	leftCopy.ID, leftCopy.CreatedAt = "", time.Time{}
	rightCopy.ID, rightCopy.CreatedAt = "", time.Time{}
	leftCopy.Metadata, rightCopy.Metadata = maps.Clone(left.Metadata), maps.Clone(right.Metadata)
	return reflect.DeepEqual(leftCopy, rightCopy)
}

func sameReservationCommand(left, right *ledger.Reservation) bool {
	if left == nil || right == nil {
		return false
	}
	leftCopy, rightCopy := *left, *right
	leftCopy.ID, leftCopy.CreatedAt, leftCopy.UpdatedAt = "", time.Time{}, time.Time{}
	rightCopy.ID, rightCopy.CreatedAt, rightCopy.UpdatedAt = "", time.Time{}, time.Time{}
	leftCopy.Status, leftCopy.FactID, leftCopy.Version = ledger.ReservationPending, "", 1
	rightCopy.Status, rightCopy.FactID, rightCopy.Version = ledger.ReservationPending, "", 1
	return reflect.DeepEqual(leftCopy, rightCopy)
}

func notFound(err, sentinel error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return sentinel
	}
	return err
}
