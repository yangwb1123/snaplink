package commerce_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

var testNow = time.Date(2026, time.August, 4, 12, 0, 0, 0, time.UTC)

func newTestService(t *testing.T) (*commerce.Service, *commerce.MemoryStore) {
	t.Helper()
	store := commerce.NewMemoryStore()
	var sequence atomic.Uint64
	service, err := commerce.NewService(
		store,
		commerce.WithClock(func() time.Time { return testNow }),
		commerce.WithIDGenerator(func(prefix string) (string, error) {
			return fmt.Sprintf("%s_%d", prefix, sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service, store
}

func publishTestPlan(t *testing.T, service *commerce.Service, id string, version uint64) {
	t.Helper()
	err := service.PublishPlan(context.Background(), &commerce.Plan{
		ID: id, Version: version, Name: id, Status: commerce.PlanActive,
		Interval: commerce.IntervalMonth, Price: commerce.Money{Currency: "USD", MinorUnits: 4900},
		GracePeriodDays: 7,
		Features: map[commerce.FeatureKey]bool{
			commerce.FeatureCoreSSO: true, commerce.FeatureMultiTenant: true,
		},
		Limits: map[commerce.LimitKey]commerce.LimitGrant{
			commerce.LimitUsers: {Soft: 90, Hard: 100},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func createTestSubscription(
	t *testing.T, service *commerce.Service, id, tenantID, planID string, version uint64,
) (*commerce.Subscription, *commerce.EntitlementSnapshot) {
	t.Helper()
	subscription, entitlement, err := service.CreateSubscription(context.Background(), commerce.CreateSubscriptionCommand{
		ID: id, TenantID: tenantID, Plan: commerce.PlanRef{ID: planID, Version: version},
	})
	if err != nil {
		t.Fatal(err)
	}
	return subscription, entitlement
}

func TestCreateSubscriptionPublishesVersionedEntitlement(t *testing.T) {
	service, store := newTestService(t)
	publishTestPlan(t, service, "minimal", 1)

	subscription, entitlement := createTestSubscription(t, service, "sub-1", "tenant-1", "minimal", 1)
	if subscription.Status != commerce.SubscriptionActive || subscription.Revision != 1 {
		t.Fatalf("unexpected subscription: %+v", subscription)
	}
	if !entitlement.FeatureEnabled(commerce.FeatureCoreSSO, testNow) {
		t.Fatal("core_sso entitlement should be active")
	}
	limit, ok := entitlement.Limit(commerce.LimitUsers, testNow)
	if !ok || limit.Hard != 100 {
		t.Fatalf("unexpected users limit: %+v, ok=%v", limit, ok)
	}

	stored, err := store.CurrentEntitlement(context.Background(), "tenant-1")
	if err != nil || stored.Revision != subscription.Revision {
		t.Fatalf("stored entitlement mismatch: %+v, %v", stored, err)
	}
	entitlement.Features[commerce.FeatureCoreSSO] = false
	again, _ := store.CurrentEntitlement(context.Background(), "tenant-1")
	if !again.Features[commerce.FeatureCoreSSO] {
		t.Fatal("returned entitlement aliases stored state")
	}
}

func TestSubscriptionStateMachineAndOptimisticRevision(t *testing.T) {
	service, store := newTestService(t)
	publishTestPlan(t, service, "full", 1)
	subscription, _ := createTestSubscription(t, service, "sub-1", "tenant-1", "full", 1)

	pastDue, entitlement, err := service.TransitionSubscription(context.Background(), commerce.TransitionSubscriptionCommand{
		SubscriptionID: subscription.ID, To: commerce.SubscriptionPastDue, ExpectedRevision: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pastDue.Revision != 2 || !pastDue.GraceUntil.Equal(pastDue.CurrentPeriodEnd.AddDate(0, 0, 7)) {
		t.Fatalf("grace period not projected: %+v", pastDue)
	}
	if !entitlement.Active || !entitlement.ExpiresAt.Equal(pastDue.GraceUntil) {
		t.Fatalf("past-due entitlement should use grace: %+v", entitlement)
	}

	_, _, err = service.TransitionSubscription(context.Background(), commerce.TransitionSubscriptionCommand{
		SubscriptionID: subscription.ID, To: commerce.SubscriptionActive, ExpectedRevision: 1,
	})
	if !errors.Is(err, commerce.ErrRevisionConflict) {
		t.Fatalf("expected revision conflict, got %v", err)
	}

	canceled, inactive, err := service.TransitionSubscription(context.Background(), commerce.TransitionSubscriptionCommand{
		SubscriptionID: subscription.ID, To: commerce.SubscriptionCanceled, ExpectedRevision: 2,
	})
	if err != nil || inactive.Active || canceled.Revision != 3 {
		t.Fatalf("cancel failed: subscription=%+v entitlement=%+v err=%v", canceled, inactive, err)
	}
	_, _, err = service.TransitionSubscription(context.Background(), commerce.TransitionSubscriptionCommand{
		SubscriptionID: subscription.ID, To: commerce.SubscriptionActive, ExpectedRevision: 3,
	})
	if !errors.Is(err, commerce.ErrTransitionDenied) {
		t.Fatalf("terminal transition should fail: %v", err)
	}

	all, err := store.ListSubscriptionsByTenant(context.Background(), "tenant-1")
	if err != nil || len(all) != 1 {
		t.Fatalf("unexpected subscription history: %d, %v", len(all), err)
	}
}

func TestChangePlanAndSingleLiveSubscription(t *testing.T) {
	service, _ := newTestService(t)
	publishTestPlan(t, service, "minimal", 1)
	publishTestPlan(t, service, "full", 1)
	subscription, _ := createTestSubscription(t, service, "sub-1", "tenant-1", "minimal", 1)

	changed, entitlement, err := service.ChangePlan(context.Background(), commerce.ChangePlanCommand{
		SubscriptionID: subscription.ID, Plan: commerce.PlanRef{ID: "full", Version: 1}, ExpectedRevision: 1,
	})
	if err != nil || changed.Plan.ID != "full" || entitlement.Plan.ID != "full" {
		t.Fatalf("plan change failed: %+v %+v %v", changed, entitlement, err)
	}
	_, _, err = service.CreateSubscription(context.Background(), commerce.CreateSubscriptionCommand{
		ID: "sub-2", TenantID: "tenant-1", Plan: commerce.PlanRef{ID: "full", Version: 1},
	})
	if !errors.Is(err, commerce.ErrTenantSubscribed) {
		t.Fatalf("second live subscription should fail: %v", err)
	}
}

func TestPlanAndMoneyValidation(t *testing.T) {
	service, store := newTestService(t)
	err := service.PublishPlan(context.Background(), &commerce.Plan{
		ID: "bad", Version: 1, Name: "bad", Status: commerce.PlanActive,
		Interval: commerce.IntervalMonth, Price: commerce.Money{Currency: "usd", MinorUnits: 1},
	})
	if !errors.Is(err, commerce.ErrInvalidMoney) {
		t.Fatalf("expected invalid money, got %v", err)
	}
	publishTestPlan(t, service, "minimal", 1)
	plan, _ := store.GetPlan(context.Background(), "minimal", 1)
	plan.Price.MinorUnits++
	if err := store.PutPlan(context.Background(), plan); !errors.Is(err, commerce.ErrPlanConflict) {
		t.Fatalf("immutable plan version should conflict: %v", err)
	}
}
