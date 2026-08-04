package commerce

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"time"
)

type IDGenerator func(prefix string) (string, error)

type Service struct {
	store Store
	now   func() time.Time
	newID IDGenerator
}

type Option func(*Service)

func WithClock(now func() time.Time) Option {
	return func(service *Service) {
		if now != nil {
			service.now = now
		}
	}
}

func WithIDGenerator(generator IDGenerator) Option {
	return func(service *Service) {
		if generator != nil {
			service.newID = generator
		}
	}

}

func NewService(store Store, options ...Option) (*Service, error) {
	if store == nil {
		return nil, ErrStoreRequired
	}
	service := &Service{
		store: store,
		now:   func() time.Time { return time.Now().UTC() },
		newID: randomID,
	}
	for _, option := range options {
		option(service)
	}
	return service, nil
}

func randomID(prefix string) (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return prefix + "_" + hex.EncodeToString(value[:]), nil
}

func (s *Service) PublishPlan(ctx context.Context, plan *Plan) error {
	if plan == nil {
		return ErrInvalidPlan
	}
	copy := clonePlan(plan)
	if copy.CreatedAt.IsZero() {
		copy.CreatedAt = s.now()
	}
	if err := copy.Validate(); err != nil {
		return err
	}
	return s.store.PutPlan(ctx, copy)
}

func (s *Service) activePlan(ctx context.Context, ref PlanRef) (*Plan, error) {
	plan, err := s.store.GetPlan(ctx, ref.ID, ref.Version)
	if err != nil {
		return nil, err
	}
	if plan.Status != PlanActive {
		return nil, ErrPlanRetired
	}
	return plan, nil
}

func (s *Service) commandID(id, prefix string) (string, error) {
	if id != "" {
		return id, nil
	}
	return s.newID(prefix)
}

func (s *Service) subscriptionEvents(
	subscription *Subscription, entitlement *EntitlementSnapshot, eventType EventType, now time.Time,
) ([]*OutboxEvent, error) {
	contract, err := s.newSubscriptionEvent(subscription, eventType, "subscription", now)
	if err != nil {
		return nil, err
	}
	projection, err := s.newSubscriptionEvent(subscription, EventEntitlementPublished, "entitlement", now)
	if err != nil {
		return nil, err
	}
	projection.Payload["active"] = strconv.FormatBool(entitlement.Active)
	projection.PayloadDigest = digestPayload(projection.Payload)
	return []*OutboxEvent{contract, projection}, nil
}

func (s *Service) newSubscriptionEvent(
	subscription *Subscription, eventType EventType, aggregateType string, now time.Time,
) (*OutboxEvent, error) {
	id, err := s.newID("evt")
	if err != nil {
		return nil, err
	}
	payload := map[string]string{
		"plan_id": subscription.Plan.ID, "plan_version": strconv.FormatUint(subscription.Plan.Version, 10),
		"status": string(subscription.Status),
	}
	key := fmt.Sprintf("%s:%s:%d:%s", aggregateType, subscription.ID, subscription.Revision, eventType)
	return &OutboxEvent{
		ID: id, TenantID: subscription.TenantID, Type: eventType, AggregateType: aggregateType,
		AggregateID: subscription.ID, AggregateVersion: subscription.Revision, IdempotencyKey: key,
		OccurredAt: now, Payload: payload, PayloadDigest: digestPayload(payload),
		Status: OutboxPending, CreatedAt: now,
	}, nil
}

func entitlementFor(plan *Plan, subscription *Subscription, now time.Time) *EntitlementSnapshot {
	expires := subscription.CurrentPeriodEnd
	if subscription.Status == SubscriptionPastDue && subscription.GraceUntil.After(expires) {
		expires = subscription.GraceUntil
	}
	active := grantsAccess(subscription.Status)
	if !active {
		expires = now
	}
	return &EntitlementSnapshot{
		TenantID: subscription.TenantID, SubscriptionID: subscription.ID, Plan: subscription.Plan,
		Revision: subscription.Revision, Active: active, Features: cloneFeatures(plan.Features),
		Limits: cloneLimits(plan.Limits), EffectiveAt: now, ExpiresAt: expires, GeneratedAt: now,
	}
}

func validateSubscriptionMutation(mutation SubscriptionMutation) error {
	if err := mutation.Subscription.Validate(); err != nil {
		return err
	}
	if !entitlementMatchesSubscription(mutation.Entitlement, mutation.Subscription) {
		return errors.New("commerce: entitlement revision mismatch")
	}
	if len(mutation.Events) == 0 {
		return errors.New("commerce: subscription outbox event required")
	}
	for _, event := range mutation.Events {
		if err := event.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func entitlementMatchesSubscription(entitlement *EntitlementSnapshot, subscription *Subscription) bool {
	return entitlement != nil && entitlement.TenantID == subscription.TenantID &&
		entitlement.SubscriptionID == subscription.ID && entitlement.Plan == subscription.Plan &&
		entitlement.Revision == subscription.Revision
}

func digestPayload(payload map[string]string) string {
	encoded, _ := json.Marshal(payload)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func clonePlan(plan *Plan) *Plan {
	if plan == nil {
		return nil
	}
	copy := *plan
	copy.Features = cloneFeatures(plan.Features)
	copy.Limits = cloneLimits(plan.Limits)
	return &copy
}

func cloneFeatures(features map[FeatureKey]bool) map[FeatureKey]bool {
	return maps.Clone(features)
}

func cloneLimits(limits map[LimitKey]LimitGrant) map[LimitKey]LimitGrant {
	return maps.Clone(limits)
}

func cloneSubscription(subscription *Subscription) *Subscription {
	if subscription == nil {
		return nil
	}
	copy := *subscription
	return &copy
}

func cloneEntitlement(entitlement *EntitlementSnapshot) *EntitlementSnapshot {
	if entitlement == nil {
		return nil
	}
	copy := *entitlement
	copy.Features = cloneFeatures(entitlement.Features)
	copy.Limits = cloneLimits(entitlement.Limits)
	return &copy
}

func cloneLedgerEntry(entry *LedgerEntry) *LedgerEntry {
	if entry == nil {
		return nil
	}
	copy := *entry
	return &copy
}

func cloneWallet(wallet *Wallet) *Wallet {
	if wallet == nil {
		return nil
	}
	copy := *wallet
	return &copy
}

func clonePaymentOrder(order *PaymentOrder) *PaymentOrder {
	if order == nil {
		return nil
	}
	copy := *order
	return &copy
}

func clonePaymentEvent(event *PaymentEvent) *PaymentEvent {
	if event == nil {
		return nil
	}
	copy := *event
	return &copy
}

func cloneOutboxEvent(event *OutboxEvent) *OutboxEvent {
	if event == nil {
		return nil
	}
	copy := *event
	copy.Payload = maps.Clone(event.Payload)
	return &copy
}

func periodEnd(start time.Time, interval BillingInterval) time.Time {
	switch interval {
	case IntervalMonth:
		return start.AddDate(0, 1, 0)
	case IntervalYear:
		return start.AddDate(1, 0, 0)
	default:
		return time.Time{}
	}
}

func laterTime(left, right time.Time) time.Time {
	if right.After(left) {
		return right
	}
	return left
}
