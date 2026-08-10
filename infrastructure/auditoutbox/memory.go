package auditoutbox

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// MemoryOutboxStore is the in-process reference implementation of the
// governance outbox (per AGENTS.md every storage concern gets a real
// Memory* implementation). Append is idempotent per (tenant, fact) —
// re-appending the SAME fact (same audit event) is a no-op, while a
// conflicting fact under the same idempotency key is rejected, mirroring
// the commerce store's conflict semantics. Implements
// [commerce.OutboxStore] so auditgovernance.NewRelay drains it.
type MemoryOutboxStore struct {
	mu     sync.Mutex
	events map[string]*commerce.OutboxEvent
	keys   map[string]string // tenantID + idempotencyKey -> event ID
}

// NewMemoryOutboxStore returns an empty store.
func NewMemoryOutboxStore() *MemoryOutboxStore {
	return &MemoryOutboxStore{
		events: make(map[string]*commerce.OutboxEvent),
		keys:   make(map[string]string),
	}
}

// Append enqueues one fact. Same-fact re-append (identical projection of
// the same audit event) is idempotent; a different fact under the same
// ID or (tenant, idempotency key) is commerce.ErrIdempotencyConflict.
func (s *MemoryOutboxStore) Append(_ context.Context, event *commerce.OutboxEvent) error {
	if event == nil {
		return errors.New("auditoutbox: nil fact")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := event.TenantID + "\x00" + event.IdempotencyKey
	if current, exists := s.events[event.ID]; exists {
		if sameFact(current, event) {
			return nil
		}
		return commerce.ErrIdempotencyConflict
	}
	if id, exists := s.keys[key]; exists && !sameFact(s.events[id], event) {
		return commerce.ErrIdempotencyConflict
	}
	s.events[event.ID] = cloneFact(event)
	s.keys[key] = event.ID
	return nil
}

// AppendFromAudit projects e through [FactFromAudit] and enqueues it.
// The class/tenant gates apply here too, so a memory-path caller gets
// the same fail-closed behavior as the sqlite path.
func (s *MemoryOutboxStore) AppendFromAudit(ctx context.Context, e *audit.Event) error {
	fact, err := FactFromAudit(e)
	if err != nil {
		return err
	}
	return s.Append(ctx, fact)
}

// ClaimOutbox implements [commerce.OutboxStore].
func (s *MemoryOutboxStore) ClaimOutbox(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("auditoutbox: invalid outbox claim")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	eligible := s.eligibleLocked(now)
	if limit > len(eligible) {
		limit = len(eligible)
	}
	result := make([]*commerce.OutboxEvent, 0, limit)
	for _, event := range eligible[:limit] {
		event.Status, event.LeaseOwner, event.LeaseUntil = commerce.OutboxLeased, owner, now.Add(lease)
		event.Attempts++
		result = append(result, cloneFact(event))
	}
	return result, nil
}

func (s *MemoryOutboxStore) eligibleLocked(now time.Time) []*commerce.OutboxEvent {
	result := make([]*commerce.OutboxEvent, 0, len(s.events))
	for _, event := range s.events {
		pending := event.Status == commerce.OutboxPending && !event.NextAttemptAt.After(now)
		expiredLease := event.Status == commerce.OutboxLeased && !event.LeaseUntil.After(now)
		if pending || expiredLease {
			result = append(result, event)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].CreatedAt.Equal(result[right].CreatedAt) {
			return result[left].ID < result[right].ID
		}
		return result[left].CreatedAt.Before(result[right].CreatedAt)
	})
	return result
}

// CompleteOutbox implements [commerce.OutboxStore].
func (s *MemoryOutboxStore) CompleteOutbox(
	ctx context.Context, id, owner string, deliveredAt time.Time,
) error {
	return s.updateLeased(ctx, id, owner, func(event *commerce.OutboxEvent) {
		event.Status, event.DeliveredAt = commerce.OutboxDelivered, deliveredAt
		clearLease(event)
	})
}

// FailOutbox implements [commerce.OutboxStore].
func (s *MemoryOutboxStore) FailOutbox(
	ctx context.Context, id, owner, reason string, now, nextAttempt time.Time, maxAttempts int,
) error {
	return s.updateLeased(ctx, id, owner, func(event *commerce.OutboxEvent) {
		event.LastError = boundedError(reason)
		if maxAttempts > 0 && event.Attempts >= maxAttempts {
			event.Status = commerce.OutboxDead
		} else {
			event.Status, event.NextAttemptAt = commerce.OutboxPending, nextAttempt
		}
		clearLease(event)
	})
}

// QuarantineOutbox implements [commerce.OutboxStore].
func (s *MemoryOutboxStore) QuarantineOutbox(
	ctx context.Context, id, owner, reason string, _ time.Time,
) error {
	return s.updateLeased(ctx, id, owner, func(event *commerce.OutboxEvent) {
		event.Status, event.LastError = commerce.OutboxQuarantined, boundedError(reason)
		clearLease(event)
	})
}

// ListDeadOutbox implements [commerce.OutboxStore].
func (s *MemoryOutboxStore) ListDeadOutbox(ctx context.Context, limit int) ([]*commerce.OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*commerce.OutboxEvent, 0)
	for _, event := range s.events {
		if event.Status == commerce.OutboxDead || event.Status == commerce.OutboxQuarantined {
			result = append(result, cloneFact(event))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].CreatedAt.Before(result[right].CreatedAt) })
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

// ReplayOutbox implements [commerce.OutboxStore].
func (s *MemoryOutboxStore) ReplayOutbox(ctx context.Context, id string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[id]
	if !ok {
		return commerce.ErrOutboxNotFound
	}
	if event.Status != commerce.OutboxDead && event.Status != commerce.OutboxQuarantined {
		return commerce.ErrOutboxLeaseLost
	}
	event.Status, event.Attempts, event.NextAttemptAt = commerce.OutboxPending, 0, now
	event.LastError = ""
	clearLease(event)
	return nil
}

// Pending reports the facts that have not reached a terminal state —
// the durability assertion surface for tests (the connector is proven
// durable by observing pending facts BEFORE the relay runs).
func (s *MemoryOutboxStore) Pending(ctx context.Context) ([]*commerce.OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	result := make([]*commerce.OutboxEvent, 0)
	for _, event := range s.events {
		if event.Status == commerce.OutboxPending || event.Status == commerce.OutboxLeased {
			result = append(result, cloneFact(event))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].CreatedAt.Before(result[right].CreatedAt) })
	return result, nil
}

func (s *MemoryOutboxStore) updateLeased(
	ctx context.Context, id, owner string, update func(*commerce.OutboxEvent),
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.events[id]
	if !ok {
		return commerce.ErrOutboxNotFound
	}
	if event.Status != commerce.OutboxLeased || event.LeaseOwner != owner {
		return commerce.ErrOutboxLeaseLost
	}
	update(event)
	return nil
}

func sameFact(left, right *commerce.OutboxEvent) bool {
	return left != nil && right != nil && left.TenantID == right.TenantID &&
		left.Type == right.Type && left.AggregateType == right.AggregateType &&
		left.AggregateID == right.AggregateID && left.AggregateVersion == right.AggregateVersion &&
		left.IdempotencyKey == right.IdempotencyKey && left.PayloadDigest == right.PayloadDigest
}

func cloneFact(event *commerce.OutboxEvent) *commerce.OutboxEvent {
	if event == nil {
		return nil
	}
	copy := *event
	copy.Payload = make(map[string]string, len(event.Payload))
	for key, value := range event.Payload {
		copy.Payload[key] = value
	}
	return &copy
}

func clearLease(event *commerce.OutboxEvent) {
	event.LeaseOwner, event.LeaseUntil = "", time.Time{}
}

func boundedError(reason string) string {
	if len(reason) > 1024 {
		return reason[:1024]
	}
	return reason
}
