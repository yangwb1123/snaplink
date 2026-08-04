package commerce_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func TestSubscriptionWritesBusinessAndEntitlementOutboxFacts(t *testing.T) {
	service, store := newTestService(t)
	publishTestPlan(t, service, "full", 1)
	createTestSubscription(t, service, "sub-1", "tenant-1", "full", 1)

	events, err := store.ClaimOutbox(context.Background(), "relay-a", testNow, time.Minute, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("expected two atomic facts, got %d: %v", len(events), err)
	}
	types := map[commerce.EventType]bool{}
	for _, event := range events {
		types[event.Type] = true
		if event.PayloadDigest == "" || event.AggregateVersion != 1 || event.Status != commerce.OutboxLeased {
			t.Fatalf("invalid claimed event: %+v", event)
		}
	}
	if !types[commerce.EventSubscriptionCreated] || !types[commerce.EventEntitlementPublished] {
		t.Fatalf("missing expected event types: %+v", types)
	}
}

func TestOutboxLeaseRetryDeadLetterAndReplay(t *testing.T) {
	service, store := newTestService(t)
	_, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 100, IdempotencyKey: "payment:1",
	})
	if err != nil {
		t.Fatal(err)
	}

	claimed, err := store.ClaimOutbox(context.Background(), "relay-a", testNow, time.Minute, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim failed: %+v %v", claimed, err)
	}
	if err := store.CompleteOutbox(context.Background(), claimed[0].ID, "relay-b", testNow); !errors.Is(err, commerce.ErrOutboxLeaseLost) {
		t.Fatalf("wrong owner should lose lease: %v", err)
	}
	if err := store.FailOutbox(
		context.Background(), claimed[0].ID, "relay-a", "governance unavailable", testNow,
		testNow.Add(time.Minute), 1,
	); err != nil {
		t.Fatal(err)
	}
	dead, err := store.ListDeadOutbox(context.Background(), 10)
	if err != nil || len(dead) != 1 || dead[0].Status != commerce.OutboxDead {
		t.Fatalf("event not dead-lettered: %+v %v", dead, err)
	}
	if err := store.ReplayOutbox(context.Background(), dead[0].ID, testNow.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.ClaimOutbox(
		context.Background(), "relay-b", testNow.Add(2*time.Minute), time.Minute, 1,
	)
	if err != nil || len(replayed) != 1 || replayed[0].Attempts != 1 {
		t.Fatalf("replay claim failed: %+v %v", replayed, err)
	}
	if err := store.CompleteOutbox(context.Background(), replayed[0].ID, "relay-b", testNow.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if dead, _ := store.ListDeadOutbox(context.Background(), 10); len(dead) != 0 {
		t.Fatalf("delivered event remained in dead list: %+v", dead)
	}
}

func TestExpiredOutboxLeaseIsRecoverable(t *testing.T) {
	service, store := newTestService(t)
	_, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 100, IdempotencyKey: "payment:1",
	})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := store.ClaimOutbox(context.Background(), "relay-a", testNow, time.Minute, 1)
	if second, _ := store.ClaimOutbox(context.Background(), "relay-b", testNow.Add(30*time.Second), time.Minute, 1); len(second) != 0 {
		t.Fatalf("live lease was stolen: %+v", second)
	}
	recovered, err := store.ClaimOutbox(
		context.Background(), "relay-b", testNow.Add(2*time.Minute), time.Minute, 1,
	)
	if err != nil || len(recovered) != 1 || recovered[0].ID != first[0].ID || recovered[0].Attempts != 2 {
		t.Fatalf("expired lease not recovered: %+v %v", recovered, err)
	}
}

func TestQuotaProjectionDeliveryIsIndependentAndLagGated(t *testing.T) {
	service, store := newTestService(t)
	publishTestPlan(t, service, "full", 1)
	createTestSubscription(t, service, "sub-quota", "tenant-quota", "full", 1)

	auditEvents, err := store.ClaimOutbox(context.Background(), "audit", testNow, time.Minute, 10)
	if err != nil || len(auditEvents) != 2 {
		t.Fatalf("claim audit facts: %d %v", len(auditEvents), err)
	}
	quotaEvents, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "quota", testNow, time.Minute, 10)
	if err != nil || len(quotaEvents) != 1 || quotaEvents[0].Type != commerce.EventEntitlementPublished {
		t.Fatalf("independent quota fact missing: %+v %v", quotaEvents, err)
	}
	for _, event := range auditEvents {
		if err := store.CompleteOutbox(context.Background(), event.ID, "audit", testNow); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.FailQuotaProjectionDelivery(context.Background(), quotaEvents[0].ID, "quota", "down", testNow, testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.QuotaProjectionDeliveryReady(context.Background(), testNow.Add(2*time.Minute), time.Minute); !errors.Is(err, commerce.ErrQuotaProjectionLag) {
		t.Fatalf("old quota backlog readiness = %v", err)
	}
	retried, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "quota-2", testNow.Add(time.Minute), time.Minute, 1)
	if err != nil || len(retried) != 1 || retried[0].Attempts != 2 {
		t.Fatalf("quota retry = %+v %v", retried, err)
	}
	if err := store.CompleteQuotaProjectionDelivery(context.Background(), retried[0].ID, "quota-2", 1, testNow.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.QuotaProjectionDeliveryReady(context.Background(), testNow.Add(2*time.Minute), time.Minute); err != nil {
		t.Fatalf("delivered quota readiness = %v", err)
	}
}

func TestQuotaProjectionSerializesEntitlementsPerTenant(t *testing.T) {
	service, store := newTestService(t)
	publishTestPlan(t, service, "full", 1)
	subscription, _ := createTestSubscription(t, service, "sub-serial", "tenant-serial", "full", 1)
	if _, _, err := service.TransitionSubscription(context.Background(), commerce.TransitionSubscriptionCommand{
		SubscriptionID: subscription.ID, To: commerce.SubscriptionPastDue, ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "worker-a", testNow, time.Minute, 10)
	if err != nil || len(first) != 1 || first[0].AggregateVersion != 1 {
		t.Fatalf("first claim=%+v error=%v", first, err)
	}
	second, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "worker-b", testNow, time.Minute, 10)
	if err != nil || len(second) != 0 {
		t.Fatalf("newer tenant revision bypassed live predecessor: %+v %v", second, err)
	}
	if err := store.CompleteQuotaProjectionDelivery(context.Background(), first[0].ID, "worker-a", 2, testNow); err != nil {
		t.Fatal(err)
	}
	second, err = store.ClaimQuotaProjectionDeliveries(context.Background(), "worker-b", testNow, time.Minute, 10)
	if err != nil || len(second) != 1 || second[0].AggregateVersion != 2 {
		t.Fatalf("second claim=%+v error=%v", second, err)
	}
}
