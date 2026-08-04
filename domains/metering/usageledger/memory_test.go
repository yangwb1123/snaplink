package usageledger

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func TestMemoryStoreEnforcesHardLimitAtomically(t *testing.T) {
	store := NewMemoryStore()
	period := MonthlyPeriod(time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC))
	limit := commerce.LimitGrant{Soft: 8, Hard: 10}
	createdAt := period.Start.Add(time.Hour)
	var accepted atomic.Int64
	var rejected atomic.Int64
	var wait sync.WaitGroup
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go reserveOne(t, store, period, limit, createdAt, index, &accepted, &rejected, &wait)
	}
	wait.Wait()
	if accepted.Load() != 10 || rejected.Load() != 90 {
		t.Fatalf("accepted = %d, rejected = %d", accepted.Load(), rejected.Load())
	}
	key := bucketFor("tenant-1", Dimension(commerce.LimitMessagesPerMonth), period)
	store.mu.RLock()
	counter := store.counterLocked(key, createdAt, limit)
	store.mu.RUnlock()
	if counter.Projected != 10 || counter.Remaining != 0 || !counter.SoftExceeded {
		t.Fatalf("counter = %+v", counter)
	}
}

func reserveOne(
	t *testing.T, store *MemoryStore, period Period, limit commerce.LimitGrant,
	createdAt time.Time, index int, accepted, rejected *atomic.Int64, wait *sync.WaitGroup,
) {
	t.Helper()
	defer wait.Done()
	reservation := testReservation(index, period, limit, createdAt)
	_, _, err := store.Reserve(context.Background(), ReserveCommand{Reservation: reservation, Limit: limit})
	switch {
	case err == nil:
		accepted.Add(1)
	case errors.Is(err, ErrQuotaExceeded):
		rejected.Add(1)
	default:
		t.Errorf("Reserve(%d) error = %v", index, err)
	}
}

func testReservation(
	index int, period Period, limit commerce.LimitGrant, createdAt time.Time,
) *Reservation {
	return &Reservation{
		ID: fmt.Sprintf("reserve-%d", index), TenantID: "tenant-1", SourceSystem: "aero-im",
		Dimension: Dimension(commerce.LimitMessagesPerMonth), Quantity: 1, Period: period,
		IdempotencyKey: fmt.Sprintf("message-%d", index), Status: ReservationPending,
		Limit: limit, ExpiresAt: createdAt.Add(time.Hour), Version: 1,
		CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

func TestMemoryStoreReleaseAndSweepFreeReservedCapacity(t *testing.T) {
	store := NewMemoryStore()
	period := MonthlyPeriod(time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC))
	limit := commerce.LimitGrant{Hard: 2}
	createdAt := period.Start.Add(time.Hour)
	first := testReservation(1, period, limit, createdAt)
	second := testReservation(2, period, limit, createdAt)
	reserveForTest(t, store, first, limit)
	reserveForTest(t, store, second, limit)
	if _, _, err := store.Reserve(context.Background(), ReserveCommand{
		Reservation: testReservation(3, period, limit, createdAt), Limit: limit,
	}); !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("Reserve() full error = %v", err)
	}
	if _, err := store.ReleaseReservation(context.Background(), reservationIdentity(first), createdAt.Add(time.Minute)); err != nil {
		t.Fatalf("ReleaseReservation() error = %v", err)
	}
	third := testReservation(3, period, limit, createdAt)
	reserveForTest(t, store, third, limit)
	expired, err := store.SweepExpiredReservations(context.Background(), createdAt.Add(2*time.Hour), 10)
	if err != nil || expired != 2 {
		t.Fatalf("SweepExpiredReservations() = (%d, %v)", expired, err)
	}
	reserveForTest(t, store, testReservation(4, period, limit, createdAt.Add(2*time.Hour)), limit)
}

func reserveForTest(t *testing.T, store *MemoryStore, reservation *Reservation, limit commerce.LimitGrant) {
	t.Helper()
	if _, _, err := store.Reserve(context.Background(), ReserveCommand{Reservation: reservation, Limit: limit}); err != nil {
		t.Fatalf("Reserve() error = %v", err)
	}
}

func TestMemoryStoreClosesPeriodWithRollupAndOutbox(t *testing.T) {
	store := NewMemoryStore()
	period := MonthlyPeriod(time.Date(2026, 7, 15, 0, 0, 0, 0, time.UTC))
	limit := commerce.LimitGrant{Hard: 20}
	createdAt := period.Start.Add(time.Hour)
	appendFactForTest(t, store, testFact("usage-1", "fact-1", 3, period, createdAt), limit)
	appendFactForTest(t, store, testFact("usage-2", "fact-2", 4, period, createdAt), limit)
	reservation := testReservation(1, period, limit, period.End.Add(-5*time.Minute))
	reservation.ExpiresAt = period.End.Add(5 * time.Minute)
	reserveForTest(t, store, reservation, limit)
	command := closeCommand(period, period.End.Add(time.Minute))
	if _, err := store.ClosePeriod(context.Background(), command); !errors.Is(err, ErrActiveReservations) {
		t.Fatalf("ClosePeriod() active reservation error = %v", err)
	}
	if _, err := store.ReleaseReservation(context.Background(), reservationIdentity(reservation), period.End); err != nil {
		t.Fatalf("ReleaseReservation() error = %v", err)
	}
	rollup, err := store.ClosePeriod(context.Background(), command)
	if err != nil || rollup.Quantity != 7 || rollup.FactCount != 2 || rollup.Digest == "" {
		t.Fatalf("ClosePeriod() = (%+v, %v)", rollup, err)
	}
	assertClosedPeriod(t, store, period, limit, createdAt)
	assertRollupOutbox(t, store, rollup, command.ClosedAt)
}

func reservationIdentity(reservation *Reservation) ReservationIdentity {
	return ReservationIdentity{
		ID: reservation.ID, TenantID: reservation.TenantID, SourceSystem: reservation.SourceSystem,
	}
}

func testFact(id, key string, quantity int64, period Period, createdAt time.Time) *UsageFact {
	return &UsageFact{
		ID: id, TenantID: "tenant-1", SourceSystem: "aero-im",
		Dimension: Dimension(commerce.LimitMessagesPerMonth), Quantity: quantity,
		Period: period, IdempotencyKey: key, OccurredAt: createdAt, CreatedAt: createdAt,
	}
}

func appendFactForTest(t *testing.T, store *MemoryStore, fact *UsageFact, limit commerce.LimitGrant) {
	t.Helper()
	if _, _, err := store.AppendFact(context.Background(), AppendCommand{Fact: fact, Limit: limit}); err != nil {
		t.Fatalf("AppendFact() error = %v", err)
	}
}

func closeCommand(period Period, closedAt time.Time) ClosePeriodCommand {
	return ClosePeriodCommand{
		RollupID: "rollup-1", EventID: "event-1", TenantID: "tenant-1",
		Dimension: Dimension(commerce.LimitMessagesPerMonth), Period: period, ClosedAt: closedAt,
	}
}

func assertClosedPeriod(
	t *testing.T, store *MemoryStore, period Period, limit commerce.LimitGrant, createdAt time.Time,
) {
	t.Helper()
	_, _, err := store.AppendFact(context.Background(), AppendCommand{
		Fact: testFact("usage-3", "fact-3", 1, period, createdAt), Limit: limit,
	})
	if !errors.Is(err, ErrPeriodClosed) {
		t.Fatalf("AppendFact() closed error = %v", err)
	}
	_, _, err = store.Reserve(context.Background(), ReserveCommand{
		Reservation: testReservation(2, period, limit, createdAt), Limit: limit,
	})
	if !errors.Is(err, ErrPeriodClosed) {
		t.Fatalf("Reserve() closed error = %v", err)
	}
}

func assertRollupOutbox(t *testing.T, store *MemoryStore, rollup *Rollup, now time.Time) {
	t.Helper()
	events, err := store.ClaimOutbox(context.Background(), "relay-1", now, time.Minute, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("ClaimOutbox() = (%+v, %v)", events, err)
	}
	event := events[0]
	if event.Type != commerce.EventUsageRollupClosed || event.AggregateID != rollup.ID ||
		event.Payload["rollup_digest"] != rollup.Digest {
		t.Fatalf("outbox event = %+v", event)
	}
}
