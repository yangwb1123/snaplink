package main

import (
	"context"
	"errors"
	"io"
	"log"
	"testing"
	"time"
)

type fakeRelayStore struct {
	claim       inboxClaim
	delivery    trustedDelivery
	resolveErr  error
	claimIssued bool
	acked       chan trustedDelivery
	nacked      chan string
	quarantined chan string
}

func (s *fakeRelayStore) ClaimInbox(context.Context, string, time.Duration, int) ([]inboxClaim, error) {
	if s.claimIssued {
		return nil, nil
	}
	s.claimIssued = true
	return []inboxClaim{s.claim}, nil
}

func (s *fakeRelayStore) ResolveClaim(context.Context, inboxClaim) (trustedDelivery, error) {
	return s.delivery, s.resolveErr
}

func (s *fakeRelayStore) AckInbox(_ context.Context, delivery trustedDelivery) error {
	s.acked <- delivery
	return nil
}

func (s *fakeRelayStore) NackInbox(_ context.Context, _ inboxClaim, _ time.Duration, category string) error {
	s.nacked <- category
	return nil
}

func (s *fakeRelayStore) QuarantineInbox(_ context.Context, _ inboxClaim, category string) error {
	s.quarantined <- category
	return nil
}

func TestRelayWorkerDeliversAndAcknowledgesTrustedFact(t *testing.T) {
	store := testRelayStore()
	billing := &fakeBillingGateway{order: testPaymentOrder()}
	worker := testRelayWorker(store, billing)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	select {
	case delivery := <-store.acked:
		if delivery.EventID != "evt_one" || len(billing.deliveries) != 1 {
			t.Fatalf("delivery=%+v Billing deliveries=%+v", delivery, billing.deliveries)
		}
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("relay did not acknowledge delivery")
	}
	<-done
}

func TestRelayWorkerReparksUnresolvedOutOfOrderEvent(t *testing.T) {
	store := testRelayStore()
	store.resolveErr = errMappingNotFound
	worker := testRelayWorker(store, &fakeBillingGateway{order: testPaymentOrder()})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	select {
	case category := <-store.nacked:
		if category != "mapping" {
			t.Fatalf("retry category = %q", category)
		}
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("relay did not repark unresolved event")
	}
	<-done
}

func TestRelayWorkerQuarantinesImmutableFactConflict(t *testing.T) {
	store := testRelayStore()
	store.resolveErr = errCheckoutConflict
	worker := testRelayWorker(store, &fakeBillingGateway{order: testPaymentOrder()})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	select {
	case category := <-store.quarantined:
		if category != "mapping_conflict" {
			t.Fatalf("quarantine category = %q", category)
		}
		cancel()
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("relay did not quarantine immutable conflict")
	}
	<-done
}

func TestRelayWorkerTreatsMissingTenantBindingAsPermanent(t *testing.T) {
	worker := testRelayWorker(testRelayStore(), &fakeBillingGateway{order: testPaymentOrder()})
	worker.bindings = map[string]*tenantBinding{}
	err := worker.deliver(context.Background(), testTrustedDelivery())
	if !permanentDeliveryError(err) || deliveryCategory(err) != "binding" {
		t.Fatalf("missing binding error=%v category=%q", err, deliveryCategory(err))
	}
}

func TestValidateDeliveryOrderRejectsAmountAndStateMismatch(t *testing.T) {
	order := testPaymentOrder()
	delivery := testTrustedDelivery()
	if err := validateDeliveryOrder(order, delivery); err != nil {
		t.Fatalf("valid delivery error = %v", err)
	}
	delivery.AmountMinor++
	if err := validateDeliveryOrder(order, delivery); !errors.Is(err, errCheckoutConflict) {
		t.Fatalf("amount mismatch error = %v", err)
	}
	delivery = testTrustedDelivery()
	order.Status = "failed"
	if err := validateDeliveryOrder(order, delivery); !errors.Is(err, errDeliveryNotReady) {
		t.Fatalf("state mismatch error = %v", err)
	}
}

func TestDeliveryBackoffIsDeterministicAndCapped(t *testing.T) {
	digest := []byte("12345678deterministic")
	if deliveryBackoff(3, digest) != deliveryBackoff(3, digest) {
		t.Fatal("backoff jitter was not deterministic")
	}
	if got := deliveryBackoff(100, digest); got > 5*time.Minute {
		t.Fatalf("backoff = %v, exceeds cap", got)
	}
}

func testRelayStore() *fakeRelayStore {
	claim := inboxClaim{providerFact: providerFact{EventID: "evt_one"}, Digest: []byte("12345678")}
	return &fakeRelayStore{
		claim: claim, delivery: testTrustedDelivery(),
		acked: make(chan trustedDelivery, 1), nacked: make(chan string, 1),
		quarantined: make(chan string, 1),
	}
}

func testRelayWorker(store relayStore, billing billingGateway) *relayWorker {
	config := runtimeConfig{
		TenantBindings: map[string]*tenantBinding{"tenant-one": {TenantID: "tenant-one"}},
		PollInterval:   time.Hour, ClaimLease: 3 * time.Second, BatchSize: 1, DeliveryConcurrency: 1,
	}
	return newRelayWorker(config, store, billing, "owner-one", log.New(io.Discard, "", 0), nil)
}

func testTrustedDelivery() trustedDelivery {
	return trustedDelivery{
		EventID: "evt_one", TenantID: "tenant-one", OrderID: "order-one",
		ProviderOrderID: "pi_one", Type: eventCaptured, Currency: "USD", AmountMinor: 1250,
		OccurredAt: time.Now().UTC(), ClaimOwner: "owner-one", ClaimGeneration: 1,
	}
}
