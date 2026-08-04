package usageledger

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type entitlementStub struct {
	snapshot *commerce.EntitlementSnapshot
}

func (s entitlementStub) CurrentEntitlement(
	context.Context, string,
) (*commerce.EntitlementSnapshot, error) {
	return s.snapshot, nil
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func newTestService(t *testing.T, hard int64) (*Service, *MemoryStore, *testClock, Period) {
	t.Helper()
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	period := MonthlyPeriod(now)
	clock := &testClock{now: now}
	snapshot := &commerce.EntitlementSnapshot{
		TenantID: "tenant-1", Active: true, Revision: 1,
		Limits: map[commerce.LimitKey]commerce.LimitGrant{
			commerce.LimitMessagesPerMonth: {Soft: max(0, hard-2), Hard: hard},
		},
		EffectiveAt: period.Start, ExpiresAt: period.End,
	}
	store := NewMemoryStore()
	sequence := 0
	service, err := NewService(store, entitlementStub{snapshot: snapshot}, clock.Now, func(prefix string) (string, error) {
		sequence++
		return fmt.Sprintf("%s-%d", prefix, sequence), nil
	})
	if err != nil {
		t.Fatalf("NewService() error = %v", err)
	}
	return service, store, clock, period
}

func usageCommand(id, key string, quantity int64, period Period) UsageCommand {
	return UsageCommand{
		ID: id, TenantID: "tenant-1", SourceSystem: "aero-im",
		Dimension: Dimension(commerce.LimitMessagesPerMonth), Quantity: quantity,
		Period: period, IdempotencyKey: key, OccurredAt: period.Start.Add(time.Hour),
	}
}

func reservationCommand(id, key string, quantity int64, period Period) ReservationCommand {
	return ReservationCommand{
		ID: id, TenantID: "tenant-1", SourceSystem: "aero-im",
		Dimension: Dimension(commerce.LimitMessagesPerMonth), Quantity: quantity,
		Period: period, IdempotencyKey: key, TTL: time.Hour,
	}
}

func TestServiceAppendIsIdempotentAndRejectsConflicts(t *testing.T) {
	service, _, clock, period := newTestService(t, 10)
	first, counter, err := service.Append(context.Background(), usageCommand("usage-1", "send-1", 2, period))
	if err != nil || first.ID != "usage-1" || counter.Committed != 2 {
		t.Fatalf("Append() = (%+v, %+v, %v)", first, counter, err)
	}
	clock.Advance(time.Minute)
	replay, counter, err := service.Append(context.Background(), usageCommand("usage-2", "send-1", 2, period))
	if err != nil || replay.ID != first.ID || counter.Committed != 2 {
		t.Fatalf("Append() replay = (%+v, %+v, %v)", replay, counter, err)
	}
	_, _, err = service.Append(context.Background(), usageCommand("usage-3", "send-1", 3, period))
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Append() conflict error = %v", err)
	}
	_, _, err = service.Append(context.Background(), usageCommand("usage-1", "send-2", 1, period))
	if !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("Append() duplicate ID error = %v", err)
	}
}

func TestServiceReservationLifecycleAndReplay(t *testing.T) {
	service, _, clock, period := newTestService(t, 10)
	first, counter, err := service.Reserve(context.Background(), reservationCommand("reserve-1", "message-1", 4, period))
	if err != nil || counter.Reserved != 4 || counter.Projected != 4 {
		t.Fatalf("Reserve() = (%+v, %+v, %v)", first, counter, err)
	}
	clock.Advance(time.Minute)
	replay, _, err := service.Reserve(context.Background(), reservationCommand("reserve-2", "message-1", 4, period))
	if err != nil || replay.ID != first.ID || !replay.ExpiresAt.Equal(first.ExpiresAt) {
		t.Fatalf("Reserve() replay = (%+v, %v)", replay, err)
	}
	fact := usageCommand("usage-1", "usage-message-1", 4, period)
	identity := ReservationIdentity{ID: first.ID, TenantID: first.TenantID, SourceSystem: first.SourceSystem}
	committed, counter, err := service.Commit(context.Background(), identity, fact)
	if err != nil || committed.Status != ReservationCommitted || counter.Committed != 4 || counter.Reserved != 0 {
		t.Fatalf("Commit() = (%+v, %+v, %v)", committed, counter, err)
	}
	clock.Advance(time.Minute)
	fact.ID = "usage-2"
	committed, counter, err = service.Commit(context.Background(), identity, fact)
	if err != nil || committed.FactID != "usage-1" || counter.Projected != 4 {
		t.Fatalf("Commit() replay = (%+v, %+v, %v)", committed, counter, err)
	}
}

func TestServiceRejectsMissingEntitlementAndSensitiveMetadata(t *testing.T) {
	service, _, _, period := newTestService(t, 10)
	command := usageCommand("usage-1", "send-1", 1, period)
	command.Dimension = "unknown_dimension"
	if _, _, err := service.Append(context.Background(), command); !errors.Is(err, ErrEntitlementMissing) {
		t.Fatalf("Append() missing entitlement error = %v", err)
	}
	command = usageCommand("usage-2", "send-2", 1, period)
	command.Metadata = map[string]string{"access_token": "redacted?"}
	if _, _, err := service.Append(context.Background(), command); !errors.Is(err, ErrInvalidFact) {
		t.Fatalf("Append() sensitive metadata error = %v", err)
	}
}
