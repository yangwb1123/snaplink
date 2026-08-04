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

func sourceBinding(id, clientID string, enabled bool) *SourceBinding {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	return &SourceBinding{
		ID: id, ClientID: clientID, TenantID: "tenant-1", SourceSystem: "aero-im",
		AllowedDimensions: []Dimension{"messages_per_month"}, Enabled: enabled,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func TestSourceResolverCollapsesUnknownDisabledAndAmbiguous(t *testing.T) {
	cases := map[string][]*SourceBinding{
		"unknown":  nil,
		"disabled": {sourceBinding("disabled", "machine", false)},
		"ambiguous": {
			sourceBinding("first", "machine", true), sourceBinding("second", "machine", true),
		},
	}
	for name, bindings := range cases {
		t.Run(name, func(t *testing.T) {
			resolver, err := NewSourceResolver(bindingReaderStub{bindings: bindings})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := resolver.Resolve(context.Background(), "machine"); !errors.Is(err, ErrSourceBindingUnauthorized) {
				t.Fatalf("Resolve() error = %v", err)
			}
		})
	}
}

type bindingReaderStub struct {
	bindings []*SourceBinding
}

func (s bindingReaderStub) SaveSourceBinding(
	context.Context, *SourceBinding, uint64,
) (*SourceBinding, error) {
	return nil, errors.New("unexpected save")
}

func (s bindingReaderStub) ListSourceBindingsByClient(context.Context, string) ([]*SourceBinding, error) {
	return s.bindings, nil
}

func TestMemorySourceBindingsEnforceOneEnabledBindingPerClient(t *testing.T) {
	store := NewMemorySourceBindingStore()
	first := sourceBinding("first", "machine", true)
	if _, err := store.SaveSourceBinding(context.Background(), first, 0); err != nil {
		t.Fatal(err)
	}
	second := sourceBinding("second", "machine", true)
	if _, err := store.SaveSourceBinding(context.Background(), second, 0); !errors.Is(err, ErrSourceBindingConflict) {
		t.Fatalf("second enabled binding error = %v", err)
	}
	second.Enabled = false
	if _, err := store.SaveSourceBinding(context.Background(), second, 0); err != nil {
		t.Fatalf("disabled history error = %v", err)
	}
}

func TestMemorySourceBindingConcurrentCreationHasSingleWinner(t *testing.T) {
	store := NewMemorySourceBindingStore()
	results := make(chan error, 32)
	var wait sync.WaitGroup
	for index := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := store.SaveSourceBinding(
				context.Background(), sourceBinding(fmt.Sprintf("binding-%d", index), "machine", true), 0,
			)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, ErrSourceBindingConflict) {
			t.Fatalf("SaveSourceBinding() error = %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("enabled binding winners = %d, want 1", winners)
	}
}

func TestMemoryReservationMutationRequiresTenantAndSource(t *testing.T) {
	store := NewMemoryStore()
	period := MonthlyPeriod(time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC))
	created := period.Start.Add(time.Hour)
	limit := testLimitGrant(2)
	reservation := testReservation(1, period, limit, created)
	reserveForTest(t, store, reservation, limit)
	wrong := reservationIdentity(reservation)
	wrong.TenantID = "tenant-other"
	if _, err := store.ReleaseReservation(context.Background(), wrong, created.Add(time.Minute)); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("cross-tenant release error = %v", err)
	}
	fact := testFact("fact-bound", "bound", 1, period, created)
	if _, _, err := store.CommitReservation(context.Background(), wrong, fact); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("cross-tenant commit error = %v", err)
	}
}

func testLimitGrant(hard int64) commerce.LimitGrant {
	return commerce.LimitGrant{Hard: hard}
}

func TestAuthorizedServiceCanonicalizesPeriodsAndCommitFacts(t *testing.T) {
	service, store, clock, period := newTestService(t, 10)
	binding := sourceBinding("canonical-source", "machine-canonical", true)
	binding.CreatedAt, binding.UpdatedAt = clock.Now(), clock.Now()
	if _, err := store.SaveSourceBinding(context.Background(), binding, 0); err != nil {
		t.Fatal(err)
	}
	evidence := binding.Evidence()
	malicious := usageCommand("usage-canonical", "append-canonical", 1, Period{
		Start: period.Start.Add(2 * time.Hour), End: period.End.Add(-2 * time.Hour),
	})
	malicious.TenantID, malicious.SourceSystem = "tenant-other", "evil"
	fact, _, err := service.AppendAuthorized(context.Background(), evidence, malicious)
	if err != nil || !periodEqual(fact.Period, period) || fact.TenantID != binding.TenantID ||
		fact.SourceSystem != binding.SourceSystem {
		t.Fatalf("authorized append = %+v, %v", fact, err)
	}
	reservationCommand := reservationCommand("reserve-canonical", "reserve-canonical", 2, Period{
		Start: period.Start.AddDate(1, 0, 0), End: period.End.AddDate(1, 0, 0),
	})
	reservation, _, err := service.ReserveAuthorized(context.Background(), evidence, reservationCommand)
	if err != nil || !periodEqual(reservation.Period, period) {
		t.Fatalf("authorized reserve = %+v, %v", reservation, err)
	}
	committed, _, err := service.CommitAuthorized(
		context.Background(), evidence, reservation.ID,
		AuthorizedCommitCommand{ID: "fact-canonical", IdempotencyKey: "commit-canonical"},
	)
	if err != nil || committed.Status != ReservationCommitted {
		t.Fatalf("authorized commit = %+v, %v", committed, err)
	}
	stored, err := store.GetFact(context.Background(), committed.FactID)
	if err != nil || stored.Dimension != reservation.Dimension || stored.Quantity != reservation.Quantity ||
		!periodEqual(stored.Period, reservation.Period) || !stored.OccurredAt.Equal(reservation.CreatedAt) {
		t.Fatalf("canonical committed fact = %+v, %v", stored, err)
	}
}

func TestAuthorizedAppendRejectsFutureBackfillAndStaleBinding(t *testing.T) {
	service, store, clock, period := newTestService(t, 10)
	binding := sourceBinding("stale-source", "machine-stale", true)
	binding.CreatedAt, binding.UpdatedAt = clock.Now(), clock.Now()
	if _, err := store.SaveSourceBinding(context.Background(), binding, 0); err != nil {
		t.Fatal(err)
	}
	evidence := binding.Evidence()
	command := usageCommand("future", "future", 1, period)
	command.OccurredAt = clock.Now().Add(time.Nanosecond)
	if _, _, err := service.AppendAuthorized(context.Background(), evidence, command); !errors.Is(err, ErrUsageTimeInvalid) {
		t.Fatalf("future usage error = %v", err)
	}
	command.ID, command.IdempotencyKey = "old", "old"
	command.OccurredAt = clock.Now().Add(-maxMachineUsageBackfill - time.Nanosecond)
	if _, _, err := service.AppendAuthorized(context.Background(), evidence, command); !errors.Is(err, ErrUsageTimeInvalid) {
		t.Fatalf("old usage error = %v", err)
	}
	binding.Enabled, binding.Revision = false, 2
	binding.UpdatedAt = clock.Now().Add(time.Minute)
	if _, err := store.SaveSourceBinding(context.Background(), binding, 1); err != nil {
		t.Fatal(err)
	}
	command.ID, command.IdempotencyKey, command.OccurredAt = "stale", "stale", clock.Now()
	if _, _, err := service.AppendAuthorized(context.Background(), evidence, command); !errors.Is(err, ErrSourceBindingUnauthorized) {
		t.Fatalf("stale binding append error = %v", err)
	}
	facts, err := store.ListFacts(context.Background(), binding.TenantID,
		Dimension(commerce.LimitMessagesPerMonth), period)
	if err != nil || len(facts) != 0 {
		t.Fatalf("facts after rejected writes = %d, %v", len(facts), err)
	}
}

func TestMemoryEvidenceCannotAuthorizeAnotherTenantFact(t *testing.T) {
	store := NewMemoryStore()
	binding := sourceBinding("identity-source", "identity-machine", true)
	if _, err := store.SaveSourceBinding(context.Background(), binding, 0); err != nil {
		t.Fatal(err)
	}
	period := MonthlyPeriod(binding.CreatedAt)
	fact := testFact("cross-tenant-fact", "cross-tenant-key", 1, period, binding.CreatedAt)
	fact.TenantID = "tenant-other"
	evidence := binding.Evidence()
	if _, _, err := store.AppendFact(context.Background(), AppendCommand{
		Fact: fact, Limit: commerce.LimitGrant{Hard: 10}, Evidence: &evidence,
	}); !errors.Is(err, ErrSourceBindingUnauthorized) {
		t.Fatalf("cross-tenant evidence error = %v", err)
	}
}
