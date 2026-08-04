package commerce

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

const maxOutboxErrorLength = 1024

func (s *MemoryStore) prepareOutboxLocked(events []*OutboxEvent) ([]*OutboxEvent, error) {
	prepared := cloneOutboxEvents(events)
	seenIDs := make(map[string]struct{}, len(prepared))
	seenKeys := make(map[string]struct{}, len(prepared))
	for _, event := range prepared {
		if err := event.Validate(); err != nil {
			return nil, err
		}
		key := commerceKey(event.TenantID, event.IdempotencyKey)
		if _, duplicate := seenIDs[event.ID]; duplicate {
			return nil, ErrIdempotencyConflict
		}
		if _, duplicate := seenKeys[key]; duplicate {
			return nil, ErrIdempotencyConflict
		}
		seenIDs[event.ID], seenKeys[key] = struct{}{}, struct{}{}
		if err := s.validateOutboxIdentityLocked(event, key); err != nil {
			return nil, err
		}
	}
	return prepared, nil
}

func (s *MemoryStore) validateOutboxIdentityLocked(event *OutboxEvent, key string) error {
	if current, exists := s.outbox[event.ID]; exists && !sameOutboxFact(current, event) {
		return ErrIdempotencyConflict
	}
	if id, exists := s.outboxKeys[key]; exists && !sameOutboxFact(s.outbox[id], event) {
		return ErrIdempotencyConflict
	}
	return nil
}

func sameOutboxFact(left, right *OutboxEvent) bool {
	return left != nil && right != nil && left.TenantID == right.TenantID &&
		left.Type == right.Type && left.AggregateType == right.AggregateType &&
		left.AggregateID == right.AggregateID && left.AggregateVersion == right.AggregateVersion &&
		left.IdempotencyKey == right.IdempotencyKey && left.PayloadDigest == right.PayloadDigest
}

func (s *MemoryStore) outboxReplayLocked(event *OutboxEvent) bool {
	id, ok := s.outboxKeys[commerceKey(event.TenantID, event.IdempotencyKey)]
	return ok && sameOutboxFact(s.outbox[id], event)
}

func (s *MemoryStore) commitOutboxLocked(events []*OutboxEvent) {
	for _, event := range events {
		key := commerceKey(event.TenantID, event.IdempotencyKey)
		if _, exists := s.outboxKeys[key]; exists {
			continue
		}
		s.outbox[event.ID] = event
		s.outboxKeys[key] = event.ID
		if event.Type == EventEntitlementPublished {
			s.quotaOutbox[event.ID] = cloneOutboxEvent(event)
		}
	}
}

func (s *MemoryStore) ClaimOutbox(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("commerce: invalid outbox claim")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	eligible := s.eligibleOutboxLocked(now)
	if limit > len(eligible) {
		limit = len(eligible)
	}
	result := make([]*OutboxEvent, 0, limit)
	for _, event := range eligible[:limit] {
		event.Status, event.LeaseOwner, event.LeaseUntil = OutboxLeased, owner, now.Add(lease)
		event.Attempts++
		result = append(result, cloneOutboxEvent(event))
	}
	return result, nil
}

func (s *MemoryStore) eligibleOutboxLocked(now time.Time) []*OutboxEvent {
	result := make([]*OutboxEvent, 0, len(s.outbox))
	for _, event := range s.outbox {
		pending := event.Status == OutboxPending && !event.NextAttemptAt.After(now)
		expiredLease := event.Status == OutboxLeased && !event.LeaseUntil.After(now)
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

func (s *MemoryStore) CompleteOutbox(
	ctx context.Context, id, owner string, deliveredAt time.Time,
) error {
	return s.updateLeasedOutbox(ctx, id, owner, func(event *OutboxEvent) {
		event.Status, event.DeliveredAt = OutboxDelivered, deliveredAt
		clearLease(event)
	})
}

func (s *MemoryStore) FailOutbox(
	ctx context.Context, id, owner, reason string, now, nextAttempt time.Time, maxAttempts int,
) error {
	return s.updateLeasedOutbox(ctx, id, owner, func(event *OutboxEvent) {
		event.LastError = boundedOutboxError(reason)
		if maxAttempts > 0 && event.Attempts >= maxAttempts {
			event.Status = OutboxDead
		} else {
			event.Status, event.NextAttemptAt = OutboxPending, nextAttempt
		}
		clearLease(event)
	})
}

func (s *MemoryStore) QuarantineOutbox(
	ctx context.Context, id, owner, reason string, _ time.Time,
) error {
	return s.updateLeasedOutbox(ctx, id, owner, func(event *OutboxEvent) {
		event.Status, event.LastError = OutboxQuarantined, boundedOutboxError(reason)
		clearLease(event)
	})
}

func (s *MemoryStore) updateLeasedOutbox(
	ctx context.Context, id, owner string, update func(*OutboxEvent),
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.outbox[id]
	if !ok {
		return ErrOutboxNotFound
	}
	if event.Status != OutboxLeased || event.LeaseOwner != owner {
		return ErrOutboxLeaseLost
	}
	update(event)
	return nil
}

func (s *MemoryStore) ListDeadOutbox(ctx context.Context, limit int) ([]*OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*OutboxEvent, 0)
	for _, event := range s.outbox {
		if event.Status == OutboxDead || event.Status == OutboxQuarantined {
			result = append(result, cloneOutboxEvent(event))
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
		return ErrOutboxNotFound
	}
	if event.Status != OutboxDead && event.Status != OutboxQuarantined {
		return ErrOutboxLeaseLost
	}
	event.Status, event.Attempts, event.NextAttemptAt = OutboxPending, 0, now
	event.LastError = ""
	clearLease(event)
	return nil
}

func clearLease(event *OutboxEvent) {
	event.LeaseOwner, event.LeaseUntil = "", time.Time{}
}

func boundedOutboxError(reason string) string {
	reason = strings.TrimSpace(reason)
	if len(reason) > maxOutboxErrorLength {
		return reason[:maxOutboxErrorLength]
	}
	return reason
}

func (s *MemoryStore) ClaimQuotaProjectionDeliveries(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*OutboxEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || lease <= 0 || limit <= 0 {
		return nil, errors.New("commerce: invalid quota projection claim")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	eligible := eligibleOutboxFrom(s.quotaOutbox, now)
	if limit > len(eligible) {
		limit = len(eligible)
	}
	result := make([]*OutboxEvent, 0, limit)
	for _, event := range eligible[:limit] {
		event.Status, event.LeaseOwner, event.LeaseUntil = OutboxLeased, owner, now.Add(lease)
		event.Attempts++
		result = append(result, cloneOutboxEvent(event))
	}
	return result, nil
}

func eligibleOutboxFrom(events map[string]*OutboxEvent, now time.Time) []*OutboxEvent {
	oldest := make(map[string]*OutboxEvent)
	for _, event := range events {
		if event.Status == OutboxDelivered {
			continue
		}
		current := oldest[event.TenantID]
		if current == nil || outboxBefore(event, current) {
			oldest[event.TenantID] = event
		}
	}
	result := make([]*OutboxEvent, 0, len(oldest))
	for _, event := range oldest {
		pending := event.Status == OutboxPending && !event.NextAttemptAt.After(now)
		expired := event.Status == OutboxLeased && !event.LeaseUntil.After(now)
		if pending || expired {
			result = append(result, event)
		}
	}
	sort.Slice(result, func(left, right int) bool {
		return outboxBefore(result[left], result[right])
	})
	return result
}

func outboxBefore(left, right *OutboxEvent) bool {
	if left.CreatedAt.Equal(right.CreatedAt) {
		return left.ID < right.ID
	}
	return left.CreatedAt.Before(right.CreatedAt)
}

func (s *MemoryStore) CompleteQuotaProjectionDelivery(
	ctx context.Context, eventID, owner string, revision uint64, deliveredAt time.Time,
) error {
	return s.updateLeasedQuotaDelivery(ctx, eventID, owner, func(event *OutboxEvent) error {
		if revision < event.AggregateVersion {
			return ErrRevisionConflict
		}
		event.Status, event.DeliveredAt = OutboxDelivered, deliveredAt
		clearLease(event)
		return nil
	})
}

func (s *MemoryStore) FailQuotaProjectionDelivery(
	ctx context.Context, eventID, owner, reason string, _ time.Time, nextAttempt time.Time,
) error {
	return s.updateLeasedQuotaDelivery(ctx, eventID, owner, func(event *OutboxEvent) error {
		event.Status, event.NextAttemptAt = OutboxPending, nextAttempt
		event.LastError = boundedOutboxError(reason)
		clearLease(event)
		return nil
	})
}

func (s *MemoryStore) updateLeasedQuotaDelivery(
	ctx context.Context, eventID, owner string, update func(*OutboxEvent) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	event, ok := s.quotaOutbox[eventID]
	if !ok {
		return ErrOutboxNotFound
	}
	if event.Status != OutboxLeased || event.LeaseOwner != owner {
		return ErrOutboxLeaseLost
	}
	return update(event)
}

func (s *MemoryStore) QuotaProjectionDeliveryReady(
	ctx context.Context, now time.Time, maxLag time.Duration,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if maxLag <= 0 {
		return ErrQuotaProjectionLag
	}
	threshold := now.Add(-maxLag)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, event := range s.quotaOutbox {
		if event.Status != OutboxDelivered && !event.CreatedAt.After(threshold) {
			return ErrQuotaProjectionLag
		}
	}
	return nil
}

var _ QuotaProjectionDeliveryStore = (*MemoryStore)(nil)
