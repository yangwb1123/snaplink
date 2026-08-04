package usageledger

import (
	"context"
	"errors"
	"maps"
	"sort"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func (s *MemoryStore) prepareOutboxLocked(event *commerce.OutboxEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	key := outboxIdempotencyKey(event)
	if current, ok := s.outbox[event.ID]; ok && !sameOutboxFact(current, event) {
		return commerce.ErrIdempotencyConflict
	}
	if id, ok := s.outboxKeys[key]; ok && !sameOutboxFact(s.outbox[id], event) {
		return commerce.ErrIdempotencyConflict
	}
	return nil
}

func (s *MemoryStore) commitOutboxLocked(event *commerce.OutboxEvent) {
	key := outboxIdempotencyKey(event)
	if _, exists := s.outboxKeys[key]; exists {
		return
	}
	copy := cloneOutbox(event)
	s.outbox[copy.ID], s.outboxKeys[key] = copy, copy.ID
}

func outboxIdempotencyKey(event *commerce.OutboxEvent) string {
	return joinKey(event.TenantID, event.IdempotencyKey)
}

func sameOutboxFact(left, right *commerce.OutboxEvent) bool {
	return left != nil && right != nil && left.TenantID == right.TenantID &&
		left.Type == right.Type && left.AggregateType == right.AggregateType &&
		left.AggregateID == right.AggregateID && left.AggregateVersion == right.AggregateVersion &&
		left.IdempotencyKey == right.IdempotencyKey && left.PayloadDigest == right.PayloadDigest
}

func cloneOutbox(event *commerce.OutboxEvent) *commerce.OutboxEvent {
	if event == nil {
		return nil
	}
	copy := *event
	copy.Payload = maps.Clone(event.Payload)
	return &copy
}

func (s *MemoryStore) ClaimOutbox(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("usage ledger: invalid outbox claim")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	events := s.eligibleOutboxLocked(now)
	if limit > len(events) {
		limit = len(events)
	}
	result := make([]*commerce.OutboxEvent, 0, limit)
	for _, event := range events[:limit] {
		event.Status, event.LeaseOwner, event.LeaseUntil = commerce.OutboxLeased, owner, now.Add(lease)
		event.Attempts++
		result = append(result, cloneOutbox(event))
	}
	return result, nil
}

func (s *MemoryStore) eligibleOutboxLocked(now time.Time) []*commerce.OutboxEvent {
	result := make([]*commerce.OutboxEvent, 0, len(s.outbox))
	for _, event := range s.outbox {
		pending := event.Status == commerce.OutboxPending && !event.NextAttemptAt.After(now)
		expired := event.Status == commerce.OutboxLeased && !event.LeaseUntil.After(now)
		if pending || expired {
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

func (s *MemoryStore) CompleteOutbox(
	ctx context.Context, id, owner string, deliveredAt time.Time,
) error {
	return s.updateLeasedOutbox(ctx, id, owner, func(event *commerce.OutboxEvent) {
		event.Status, event.DeliveredAt = commerce.OutboxDelivered, deliveredAt
		clearLease(event)
	})
}

func (s *MemoryStore) FailOutbox(
	ctx context.Context, id, owner, reason string, now, nextAttempt time.Time, maxAttempts int,
) error {
	_ = now
	return s.updateLeasedOutbox(ctx, id, owner, func(event *commerce.OutboxEvent) {
		event.LastError = boundedError(reason)
		if maxAttempts > 0 && event.Attempts >= maxAttempts {
			event.Status = commerce.OutboxDead
		} else {
			event.Status, event.NextAttemptAt = commerce.OutboxPending, nextAttempt
		}
		clearLease(event)
	})
}

func (s *MemoryStore) QuarantineOutbox(
	ctx context.Context, id, owner, reason string, now time.Time,
) error {
	_ = now
	return s.updateLeasedOutbox(ctx, id, owner, func(event *commerce.OutboxEvent) {
		event.Status, event.LastError = commerce.OutboxQuarantined, boundedError(reason)
		clearLease(event)
	})
}

func (s *MemoryStore) updateLeasedOutbox(
	ctx context.Context, id, owner string, update func(*commerce.OutboxEvent),
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.outbox[id]
	if !ok {
		return commerce.ErrOutboxNotFound
	}
	if event.Status != commerce.OutboxLeased || event.LeaseOwner != owner {
		return commerce.ErrOutboxLeaseLost
	}
	update(event)
	return nil
}

func (s *MemoryStore) ListDeadOutbox(
	ctx context.Context, limit int,
) ([]*commerce.OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*commerce.OutboxEvent, 0)
	for _, event := range s.outbox {
		if event.Status == commerce.OutboxDead || event.Status == commerce.OutboxQuarantined {
			result = append(result, cloneOutbox(event))
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].CreatedAt.Before(result[right].CreatedAt) })
	if limit > 0 && limit < len(result) {
		result = result[:limit]
	}
	return result, nil
}

func (s *MemoryStore) ReplayOutbox(ctx context.Context, id string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.outbox[id]
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

func clearLease(event *commerce.OutboxEvent) {
	event.LeaseOwner, event.LeaseUntil = "", time.Time{}
}

func boundedError(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > 1024 {
		return reason[:1024]
	}
	return reason
}

var _ Store = (*MemoryStore)(nil)
