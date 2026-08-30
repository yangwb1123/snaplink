package usageledger

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type MemoryStore struct {
	mu                   sync.RWMutex
	facts                map[string]*UsageFact
	factKeys             map[string]string
	factsByBucket        map[bucketKey][]string
	reservations         map[string]*Reservation
	reservationKeys      map[string]string
	releaseKeys          map[string]string
	reservationsByBucket map[bucketKey][]string
	rollups              map[bucketKey]*Rollup
	outbox               map[string]*commerce.OutboxEvent
	outboxKeys           map[string]string
	bindings             map[string]*SourceBinding
}

type bucketKey struct {
	tenantID  string
	dimension Dimension
	startNano int64
	endNano   int64
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		facts: make(map[string]*UsageFact), factKeys: make(map[string]string),
		factsByBucket: make(map[bucketKey][]string), reservations: make(map[string]*Reservation),
		reservationKeys: make(map[string]string), releaseKeys: make(map[string]string),
		reservationsByBucket: make(map[bucketKey][]string),
		rollups:              make(map[bucketKey]*Rollup), outbox: make(map[string]*commerce.OutboxEvent),
		outboxKeys: make(map[string]string), bindings: make(map[string]*SourceBinding),
	}
}

func (s *MemoryStore) AppendFact(
	ctx context.Context, command AppendCommand,
) (*UsageFact, *Counter, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if err := validateAppend(command); err != nil {
		return nil, nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateEvidenceLocked(
		command.Evidence, command.Fact.TenantID, command.Fact.SourceSystem, command.Fact.Dimension,
	); err != nil {
		return nil, nil, err
	}
	if fact, counter, ok, err := s.factReplayLocked(command); ok || err != nil {
		return fact, counter, err
	}
	if _, exists := s.facts[command.Fact.ID]; exists {
		return nil, nil, ErrIdempotencyConflict
	}
	key := bucketFor(command.Fact.TenantID, command.Fact.Dimension, command.Fact.Period)
	if _, closed := s.rollups[key]; closed {
		return nil, nil, ErrPeriodClosed
	}
	counter := s.counterLocked(key, command.Fact.CreatedAt, command.Limit)
	if additionOverflows(counter.Projected, command.Fact.Quantity) {
		return nil, counter, ErrCounterOverflow
	}
	if !withinLimit(counter.Projected, command.Fact.Quantity, command.Limit) {
		return nil, counter, ErrQuotaExceeded
	}
	fact := cloneFact(command.Fact)
	s.commitFactLocked(key, fact)
	counter = s.counterLocked(key, fact.CreatedAt, command.Limit)
	return cloneFact(fact), counter, nil
}

func validateAppend(command AppendCommand) error {
	if err := command.Fact.Validate(); err != nil {
		return err
	}
	return command.Limit.Validate()
}

func (s *MemoryStore) factReplayLocked(
	command AppendCommand,
) (*UsageFact, *Counter, bool, error) {
	key := factIdempotencyKey(command.Fact)
	id, ok := s.factKeys[key]
	if !ok {
		return nil, nil, false, nil
	}
	current := s.facts[id]
	if !sameFact(current, command.Fact) {
		return nil, nil, true, ErrIdempotencyConflict
	}
	bucket := bucketFor(current.TenantID, current.Dimension, current.Period)
	counter := s.counterLocked(bucket, command.Fact.CreatedAt, command.Limit)
	return cloneFact(current), counter, true, nil
}

func (s *MemoryStore) commitFactLocked(key bucketKey, fact *UsageFact) {
	s.facts[fact.ID] = fact
	s.factKeys[factIdempotencyKey(fact)] = fact.ID
	s.factsByBucket[key] = append(s.factsByBucket[key], fact.ID)
}

func (s *MemoryStore) GetFact(ctx context.Context, id string) (*UsageFact, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	fact, ok := s.facts[id]
	if !ok {
		return nil, ErrFactNotFound
	}
	return cloneFact(fact), nil
}

func (s *MemoryStore) ListFacts(
	ctx context.Context, tenantID string, dimension Dimension, period Period,
) ([]*UsageFact, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := period.Validate(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := bucketFor(tenantID, dimension, period)
	result := make([]*UsageFact, 0, len(s.factsByBucket[key]))
	for _, id := range s.factsByBucket[key] {
		result = append(result, cloneFact(s.facts[id]))
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].OccurredAt.Equal(result[right].OccurredAt) {
			return result[left].ID < result[right].ID
		}
		return result[left].OccurredAt.Before(result[right].OccurredAt)
	})
	return result, nil
}

func (s *MemoryStore) ClosePeriod(
	ctx context.Context, command ClosePeriodCommand,
) (*Rollup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateClose(command); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := bucketFor(command.TenantID, command.Dimension, command.Period)
	if current, ok := s.rollups[key]; ok {
		return cloneRollup(current), nil
	}
	if s.hasActiveReservationsLocked(key, command.ClosedAt) {
		return nil, ErrActiveReservations
	}
	rollup := s.buildRollupLocked(key, command)
	event := rollupOutboxEvent(rollup, command.EventID)
	if err := s.prepareOutboxLocked(event); err != nil {
		return nil, err
	}
	s.rollups[key] = rollup
	s.commitOutboxLocked(event)
	return cloneRollup(rollup), nil
}

func validateClose(command ClosePeriodCommand) error {
	if command.RollupID == "" || command.EventID == "" || command.TenantID == "" ||
		command.Dimension == "" || command.ClosedAt.IsZero() || command.ClosedAt.Before(command.Period.End) {
		return ErrInvalidPeriod
	}
	return command.Period.Validate()
}

func (s *MemoryStore) buildRollupLocked(key bucketKey, command ClosePeriodCommand) *Rollup {
	var quantity int64
	for _, id := range s.factsByBucket[key] {
		quantity += s.facts[id].Quantity
	}
	rollup := &Rollup{
		ID: command.RollupID, TenantID: command.TenantID, Dimension: command.Dimension,
		Period: command.Period, Quantity: quantity, FactCount: int64(len(s.factsByBucket[key])),
		Version: 1, ClosedAt: command.ClosedAt,
	}
	rollup.Digest = rollupDigest(rollup)
	return rollup
}

func (s *MemoryStore) GetRollup(
	ctx context.Context, tenantID string, dimension Dimension, period Period,
) (*Rollup, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rollup, ok := s.rollups[bucketFor(tenantID, dimension, period)]
	if !ok {
		return nil, ErrRollupNotFound
	}
	return cloneRollup(rollup), nil
}

func (s *MemoryStore) counterLocked(
	key bucketKey, at time.Time, limit commerce.LimitGrant,
) *Counter {
	committed, reserved := int64(0), int64(0)
	for _, id := range s.factsByBucket[key] {
		committed += s.facts[id].Quantity
	}
	for _, id := range s.reservationsByBucket[key] {
		reservation := s.reservations[id]
		if reservation.Status == ReservationPending && reservation.ExpiresAt.After(at) {
			reserved += reservation.Quantity
		}
	}
	return newCounter(key, committed, reserved, limit)
}

func newCounter(key bucketKey, committed, reserved int64, limit commerce.LimitGrant) *Counter {
	projected := committed + reserved
	counter := &Counter{
		TenantID: key.tenantID, Dimension: key.dimension,
		Period:    Period{Start: time.Unix(0, key.startNano).UTC(), End: time.Unix(0, key.endNano).UTC()},
		Committed: committed, Reserved: reserved, Projected: projected,
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

func additionOverflows(current, delta int64) bool {
	return current < 0 || delta < 0 || current > int64(^uint64(0)>>1)-delta
}

func bucketFor(tenantID string, dimension Dimension, period Period) bucketKey {
	return bucketKey{
		tenantID: tenantID, dimension: dimension,
		startNano: period.Start.UTC().UnixNano(), endNano: period.End.UTC().UnixNano(),
	}
}

func factIdempotencyKey(fact *UsageFact) string {
	return joinKey(fact.TenantID, fact.SourceSystem, string(fact.Dimension), fact.IdempotencyKey)
}

func sameFact(left, right *UsageFact) bool {
	if left == nil || right == nil {
		return false
	}
	leftCopy, rightCopy := cloneFact(left), cloneFact(right)
	leftCopy.ID, leftCopy.CreatedAt = "", time.Time{}
	rightCopy.ID, rightCopy.CreatedAt = "", time.Time{}
	return reflect.DeepEqual(leftCopy, rightCopy)
}

func rollupDigest(rollup *Rollup) string {
	canonical := joinKey(
		rollup.TenantID, string(rollup.Dimension), strconv.FormatInt(rollup.Period.Start.UnixNano(), 10),
		strconv.FormatInt(rollup.Period.End.UnixNano(), 10), strconv.FormatInt(rollup.Quantity, 10),
		strconv.FormatInt(rollup.FactCount, 10),
	)
	digest := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(digest[:])
}

func rollupOutboxEvent(rollup *Rollup, eventID string) *commerce.OutboxEvent {
	payload := map[string]string{
		"dimension": string(rollup.Dimension), "period_start": rollup.Period.Start.UTC().Format(time.RFC3339Nano),
		"period_end": rollup.Period.End.UTC().Format(time.RFC3339Nano),
		"quantity":   strconv.FormatInt(rollup.Quantity, 10), "fact_count": strconv.FormatInt(rollup.FactCount, 10),
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
	canonical := ""
	for _, key := range keys {
		canonical += joinKey(key, payload[key])
	}
	digest := sha256.Sum256([]byte(canonical))
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
