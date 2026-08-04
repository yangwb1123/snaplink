package quotaprojection

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/shared/core"
)

var relayNow = time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)

type relayStore struct {
	event             *commerce.OutboxEvent
	events            []*commerce.OutboxEvent
	claimLimits       []int
	completedRevision uint64
	failureReason     string
	nextAttempt       time.Time
	readyErr          error
}

func (s *relayStore) ClaimQuotaProjectionDeliveries(
	_ context.Context, _ string, _ time.Time, _ time.Duration, limit int,
) ([]*commerce.OutboxEvent, error) {
	s.claimLimits = append(s.claimLimits, limit)
	if len(s.events) > 0 {
		event := s.events[0]
		s.events = s.events[1:]
		return []*commerce.OutboxEvent{event}, nil
	}
	if s.event == nil {
		return nil, nil
	}
	event := s.event
	s.event = nil
	return []*commerce.OutboxEvent{event}, nil
}

func TestRelayClaimsEachDeliveryWithAFreshLease(t *testing.T) {
	store := &relayStore{events: []*commerce.OutboxEvent{testRelayEvent(2), testRelayEvent(3)}}
	relay := newTestRelay(t, store, fixedEntitlementReader(testEntitlement(4, true)), projectionClientFunc(func(
		_ context.Context, _ *commerce.OutboxEvent, projection core.TenantQuotaProjection,
	) (Receipt, error) {
		return Receipt{TenantID: "tenant-a", Revision: projection.Revision}, nil
	}))
	result, err := relay.RunOnce(context.Background())
	if err != nil || result.Delivered != 2 || result.Claimed != 2 {
		t.Fatalf("RunOnce()=%+v error=%v", result, err)
	}
	for _, limit := range store.claimLimits {
		if limit != 1 {
			t.Fatalf("claim limits=%v", store.claimLimits)
		}
	}
}

func (s *relayStore) CompleteQuotaProjectionDelivery(
	_ context.Context, _ string, _ string, revision uint64, _ time.Time,
) error {
	s.completedRevision = revision
	return nil
}

func (s *relayStore) FailQuotaProjectionDelivery(
	_ context.Context, _ string, _ string, reason string, _ time.Time, next time.Time,
) error {
	s.failureReason, s.nextAttempt = reason, next
	return nil
}

func (s *relayStore) QuotaProjectionDeliveryReady(
	context.Context, time.Time, time.Duration,
) error {
	return s.readyErr
}

type entitlementReaderFunc func(context.Context, string) (*commerce.EntitlementSnapshot, error)

func (f entitlementReaderFunc) CurrentEntitlement(
	ctx context.Context, tenantID string,
) (*commerce.EntitlementSnapshot, error) {
	return f(ctx, tenantID)
}

type projectionClientFunc func(
	context.Context, *commerce.OutboxEvent, core.TenantQuotaProjection,
) (Receipt, error)

func (f projectionClientFunc) Publish(
	ctx context.Context, event *commerce.OutboxEvent, projection core.TenantQuotaProjection,
) (Receipt, error) {
	return f(ctx, event, projection)
}

func TestRelayPublishesLatestRevisionAndCompletesClaim(t *testing.T) {
	store := &relayStore{event: testRelayEvent(2)}
	snapshot := testEntitlement(4, true)
	var published core.TenantQuotaProjection
	relay := newTestRelay(t, store, fixedEntitlementReader(snapshot), projectionClientFunc(func(
		_ context.Context, _ *commerce.OutboxEvent, projection core.TenantQuotaProjection,
	) (Receipt, error) {
		published = projection
		return Receipt{TenantID: "tenant-a", Revision: projection.Revision, Applied: true}, nil
	}))
	result, err := relay.RunOnce(context.Background())
	if err != nil || result.Delivered != 1 || result.Retried != 0 {
		t.Fatalf("RunOnce() = %+v, %v", result, err)
	}
	if published.Revision != 4 || store.completedRevision != 4 || published.Quota.MaxClients != 9 {
		t.Fatalf("published = %+v, completed revision = %d", published, store.completedRevision)
	}
}

func TestRelayMissingEntitlementRetriesWithoutPublishingUnlimited(t *testing.T) {
	store := &relayStore{event: testRelayEvent(2)}
	calls := 0
	relay := newTestRelay(t, store, entitlementReaderFunc(func(
		context.Context, string,
	) (*commerce.EntitlementSnapshot, error) {
		return nil, commerce.ErrEntitlementNotFound
	}), projectionClientFunc(func(
		context.Context, *commerce.OutboxEvent, core.TenantQuotaProjection,
	) (Receipt, error) {
		calls++
		return Receipt{}, nil
	}))
	result, err := relay.RunOnce(context.Background())
	if err != nil || result.Retried != 1 || calls != 0 {
		t.Fatalf("RunOnce() = %+v, %v, publish calls = %d", result, err, calls)
	}
	if store.failureReason != reasonEntitlementMissing || !store.nextAttempt.After(relayNow) {
		t.Fatalf("retry = %q at %v", store.failureReason, store.nextAttempt)
	}
}

func TestRelayProjectsInactiveEntitlementAsExplicitHardZero(t *testing.T) {
	store := &relayStore{event: testRelayEvent(2)}
	snapshot := testEntitlement(2, false)
	relay := newTestRelay(t, store, fixedEntitlementReader(snapshot), projectionClientFunc(func(
		_ context.Context, _ *commerce.OutboxEvent, projection core.TenantQuotaProjection,
	) (Receipt, error) {
		quota := projection.Quota
		if quota.MaxClients != 0 || !quota.ClientsLimited || !quota.UsersLimited ||
			!quota.SessionsLimited || !quota.TokenRateLimited {
			t.Fatalf("inactive quota = %+v", quota)
		}
		return Receipt{TenantID: "tenant-a", Revision: projection.Revision}, nil
	}))
	if result, err := relay.RunOnce(context.Background()); err != nil || result.Delivered != 1 {
		t.Fatalf("RunOnce() = %+v, %v", result, err)
	}
}

func TestRelayPersistsAuthorizationRetryThenPauses(t *testing.T) {
	store := &relayStore{event: testRelayEvent(2)}
	relay := newTestRelay(t, store, fixedEntitlementReader(testEntitlement(2, true)), projectionClientFunc(func(
		context.Context, *commerce.OutboxEvent, core.TenantQuotaProjection,
	) (Receipt, error) {
		return Receipt{}, ErrAuthorizationRejected
	}))
	result, err := relay.RunOnce(context.Background())
	if !errors.Is(err, ErrAuthorizationRejected) || result.Retried != 1 ||
		store.failureReason != reasonAuthorization {
		t.Fatalf("RunOnce() = %+v, %v, reason = %q", result, err, store.failureReason)
	}
}

func TestRelayReadinessDelegatesDurableLag(t *testing.T) {
	store := &relayStore{readyErr: commerce.ErrQuotaProjectionLag}
	relay := newTestRelay(t, store, fixedEntitlementReader(testEntitlement(2, true)), projectionClientFunc(func(
		context.Context, *commerce.OutboxEvent, core.TenantQuotaProjection,
	) (Receipt, error) {
		return Receipt{}, nil
	}))
	if err := relay.Ready(context.Background()); !errors.Is(err, commerce.ErrQuotaProjectionLag) {
		t.Fatalf("Ready() error = %v", err)
	}
}

func newTestRelay(
	t *testing.T, store commerce.QuotaProjectionDeliveryStore,
	reader commerce.EntitlementReader, client Client,
) *Relay {
	t.Helper()
	relay, err := NewRelay(store, reader, client, RelayConfig{
		Owner: "worker-a", InitialBackoff: time.Second, MaxBackoff: time.Second,
	}, WithRelayClock(func() time.Time { return relayNow }))
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	return relay
}

func fixedEntitlementReader(snapshot *commerce.EntitlementSnapshot) commerce.EntitlementReader {
	return entitlementReaderFunc(func(context.Context, string) (*commerce.EntitlementSnapshot, error) {
		return snapshot, nil
	})
}

func testRelayEvent(revision uint64) *commerce.OutboxEvent {
	return &commerce.OutboxEvent{
		ID: "evt-1", TenantID: "tenant-a", Type: commerce.EventEntitlementPublished,
		AggregateVersion: revision, Attempts: 1,
	}
}

func testEntitlement(revision uint64, active bool) *commerce.EntitlementSnapshot {
	return &commerce.EntitlementSnapshot{
		TenantID: "tenant-a", Revision: revision, Active: active,
		Features: map[commerce.FeatureKey]bool{commerce.FeatureCoreSSO: true},
		Limits: map[commerce.LimitKey]commerce.LimitGrant{
			commerce.LimitClients: {Hard: 9},
		},
		EffectiveAt: relayNow.Add(-time.Hour), ExpiresAt: relayNow.Add(time.Hour),
	}
}
