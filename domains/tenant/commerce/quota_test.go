package commerce_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func TestEntitlementEnforcerFeatureAndLimit(t *testing.T) {
	service, store := newTestService(t)
	publishTestPlan(t, service, "minimal", 1)
	_, entitlement := createTestSubscription(t, service, "sub-1", "tenant-1", "minimal", 1)
	enforcer, err := commerce.NewEnforcer(store, func() time.Time { return testNow })
	if err != nil {
		t.Fatal(err)
	}
	if err := enforcer.RequireFeature(context.Background(), "tenant-1", commerce.FeatureCoreSSO); err != nil {
		t.Fatal(err)
	}
	if err := enforcer.RequireFeature(context.Background(), "tenant-1", commerce.FeatureVault); !errors.Is(err, commerce.ErrNotEntitled) {
		t.Fatalf("expected not entitled, got %v", err)
	}
	decision, err := enforcer.EvaluateLimit(context.Background(), "tenant-1", commerce.LimitUsers, 90, 1)
	if err != nil || !decision.Allowed || !decision.SoftExceeded || decision.Remaining != 9 {
		t.Fatalf("unexpected soft-limit decision: %+v %v", decision, err)
	}
	decision, err = enforcer.EvaluateLimit(context.Background(), "tenant-1", commerce.LimitUsers, 100, 1)
	if err != nil || decision.Allowed || decision.Reason != commerce.DecisionLimitExceeded {
		t.Fatalf("unexpected hard-limit decision: %+v %v", decision, err)
	}

	quota := commerce.ProjectCoreQuota(entitlement, testNow)
	if quota.MaxUsers != 100 || quota.MaxClients != 0 {
		t.Fatalf("unexpected core projection: %+v", quota)
	}
}

func TestProjectCoreQuotaPreservesHardZeroAndRevision(t *testing.T) {
	snapshot := &commerce.EntitlementSnapshot{
		TenantID: "tenant-zero", Revision: 7, Active: true,
		EffectiveAt: testNow.Add(-time.Minute),
		Features:    map[commerce.FeatureKey]bool{commerce.FeatureCoreSSO: true},
		Limits: map[commerce.LimitKey]commerce.LimitGrant{
			commerce.LimitClients: {Hard: 0},
			commerce.LimitUsers:   {Unlimited: true},
		},
	}
	quota := commerce.ProjectCoreQuota(snapshot, testNow)
	if quota.MaxClients != 0 || !quota.ClientsLimited {
		t.Fatalf("hard zero was lost: %+v", quota)
	}
	if quota.MaxUsers != 0 || quota.UsersLimited {
		t.Fatalf("unlimited grant became finite: %+v", quota)
	}
	projection := commerce.ProjectQuotaProjection(snapshot, testNow)
	if projection.Revision != 7 || projection.Quota != quota {
		t.Fatalf("versioned projection = %+v", projection)
	}
}

func TestProjectCoreQuotaClosesInactiveAndCoreDisabledEntitlements(t *testing.T) {
	for _, snapshot := range []*commerce.EntitlementSnapshot{
		{TenantID: "inactive", Revision: 1, EffectiveAt: testNow.Add(-time.Hour)},
		{TenantID: "disabled", Revision: 2, Active: true, EffectiveAt: testNow.Add(-time.Hour)},
		{TenantID: "expired", Revision: 3, Active: true, EffectiveAt: testNow.Add(-time.Hour),
			ExpiresAt: testNow.Add(-time.Minute), Features: map[commerce.FeatureKey]bool{commerce.FeatureCoreSSO: true}},
	} {
		quota := commerce.ProjectCoreQuota(snapshot, testNow)
		if quota.MaxClients != 0 || quota.MaxUsers != 0 || quota.MaxSessions != 0 || quota.MaxTokenRate != 0 ||
			!quota.ClientsLimited || !quota.UsersLimited || !quota.SessionsLimited || !quota.TokenRateLimited {
			t.Fatalf("inactive projection reopened quota: %+v", quota)
		}
	}
}
