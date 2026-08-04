package usageledger

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	ledger "github.com/yangwb1123/snaplink/domains/metering/usageledger"
)

func pgSourceBinding(id, clientID string, enabled bool) *ledger.SourceBinding {
	return &ledger.SourceBinding{
		ID: id, ClientID: clientID, TenantID: "tenant-pg", SourceSystem: "aero-vault",
		AllowedDimensions: []ledger.Dimension{"storage_bytes"}, Enabled: enabled,
		Revision: 1, CreatedAt: integrationNow, UpdatedAt: integrationNow,
	}
}

func TestPostgresSourceBindingsResolveAndUpdateOptimistically(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	binding := pgSourceBinding("source-a", "vault-machine", true)
	stored, err := store.SaveSourceBinding(ctx, binding, 0)
	if err != nil || stored.Revision != 1 {
		t.Fatalf("create binding = %+v, %v", stored, err)
	}
	resolver, err := ledger.NewSourceResolver(store)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolver.Resolve(ctx, binding.ClientID)
	if err != nil || resolved.TenantID != binding.TenantID || !resolved.Allows("storage_bytes") {
		t.Fatalf("resolve binding = %+v, %v", resolved, err)
	}
	binding.Revision, binding.UpdatedAt, binding.Enabled = 2, integrationNow.Add(time.Minute), false
	if _, err := store.SaveSourceBinding(ctx, binding, 1); err != nil {
		t.Fatalf("disable binding: %v", err)
	}
	if _, err := resolver.Resolve(ctx, binding.ClientID); !errors.Is(err, ledger.ErrSourceBindingUnauthorized) {
		t.Fatalf("disabled resolve error = %v", err)
	}
}

func TestPostgresSourceBindingsHaveOneConcurrentEnabledWinner(t *testing.T) {
	store := integrationStore(t)
	results := make(chan error, 24)
	var wait sync.WaitGroup
	for index := range 24 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			binding := pgSourceBinding(fmt.Sprintf("source-%02d", index), "shared-machine", true)
			_, err := store.SaveSourceBinding(context.Background(), binding, 0)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	winners := 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ledger.ErrSourceBindingConflict):
		default:
			t.Fatalf("concurrent binding error = %v", err)
		}
	}
	if winners != 1 {
		t.Fatalf("enabled binding winners = %d, want 1", winners)
	}
}

func TestPostgresReservationMutationsAreTenantAndSourceBound(t *testing.T) {
	store := integrationStore(t)
	limit := testLimit(10)
	reservation := testReservation(
		"reserve-bound", "reserve-bound-key", 2, testPeriod(),
		integrationNow, integrationNow.Add(time.Hour), limit,
	)
	if _, _, err := store.Reserve(context.Background(), ledger.ReserveCommand{
		Reservation: reservation, Limit: limit,
	}); err != nil {
		t.Fatal(err)
	}
	wrong := pgReservationIdentity(reservation)
	wrong.SourceSystem = "aero-im"
	if _, err := store.ReleaseReservation(context.Background(), wrong, integrationNow.Add(time.Minute)); !errors.Is(err, ledger.ErrReservationNotFound) {
		t.Fatalf("cross-source release error = %v", err)
	}
	fact := testFact("usage-bound", "usage-bound-key", 2)
	if _, _, err := store.CommitReservation(context.Background(), wrong, fact); !errors.Is(err, ledger.ErrReservationNotFound) {
		t.Fatalf("cross-source commit error = %v", err)
	}
	if _, _, err := store.CommitReservation(
		context.Background(), pgReservationIdentity(reservation), fact,
	); err != nil {
		t.Fatalf("bound commit: %v", err)
	}
}

func TestPostgresUsageMutationRejectsStaleAndMissingBindingEvidence(t *testing.T) {
	store := integrationStore(t)
	ctx := context.Background()
	binding := pgSourceBinding("evidence-source", "evidence-machine", true)
	if _, err := store.SaveSourceBinding(ctx, binding, 0); err != nil {
		t.Fatal(err)
	}
	evidence := binding.Evidence()
	binding.Enabled, binding.Revision = false, 2
	binding.UpdatedAt = integrationNow.Add(time.Minute)
	if _, err := store.SaveSourceBinding(ctx, binding, 1); err != nil {
		t.Fatal(err)
	}
	fact := testFact("evidence-fact", "evidence-key", 1)
	if _, _, err := store.AppendFact(ctx, ledger.AppendCommand{
		Fact: fact, Limit: testLimit(10), Evidence: &evidence,
	}); !errors.Is(err, ledger.ErrSourceBindingUnauthorized) {
		t.Fatalf("stale evidence error = %v", err)
	}
	missing := evidence
	missing.BindingID = "missing-source"
	if _, _, err := store.AppendFact(ctx, ledger.AppendCommand{
		Fact: fact, Limit: testLimit(10), Evidence: &missing,
	}); !errors.Is(err, ledger.ErrSourceBindingUnauthorized) {
		t.Fatalf("missing evidence error = %v", err)
	}
	active := pgSourceBinding("identity-source", "identity-machine", true)
	if _, err := store.SaveSourceBinding(ctx, active, 0); err != nil {
		t.Fatal(err)
	}
	activeEvidence := active.Evidence()
	forged := testFact("forged-fact", "forged-key", 1)
	forged.TenantID = "tenant-other"
	if _, _, err := store.AppendFact(ctx, ledger.AppendCommand{
		Fact: forged, Limit: testLimit(10), Evidence: &activeEvidence,
	}); !errors.Is(err, ledger.ErrSourceBindingUnauthorized) {
		t.Fatalf("cross-tenant evidence error = %v", err)
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM usage_ledger_facts`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("facts after rejected evidence = %d, %v", count, err)
	}
}
