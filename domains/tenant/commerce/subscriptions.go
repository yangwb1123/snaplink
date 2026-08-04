package commerce

import (
	"context"
	"time"
)

type CreateSubscriptionCommand struct {
	ID                     string
	TenantID               string
	Plan                   PlanRef
	TrialEnd               time.Time
	Provider               string
	ProviderSubscriptionID string
}

func (s *Service) CreateSubscription(
	ctx context.Context, command CreateSubscriptionCommand,
) (*Subscription, *EntitlementSnapshot, error) {
	plan, err := s.activePlan(ctx, command.Plan)
	if err != nil {
		return nil, nil, err
	}
	id, err := s.commandID(command.ID, "sub")
	if err != nil {
		return nil, nil, err
	}
	now := s.now()
	subscription := newSubscription(command, id, plan, now)
	entitlement := entitlementFor(plan, subscription, now)
	events, err := s.subscriptionEvents(subscription, entitlement, EventSubscriptionCreated, now)
	if err != nil {
		return nil, nil, err
	}
	mutation := SubscriptionMutation{Subscription: subscription, Entitlement: entitlement, Events: events}
	if err := s.store.ApplySubscription(ctx, mutation); err != nil {
		return nil, nil, err
	}
	return cloneSubscription(subscription), cloneEntitlement(entitlement), nil
}

func newSubscription(command CreateSubscriptionCommand, id string, plan *Plan, now time.Time) *Subscription {
	status := SubscriptionActive
	periodFinish := periodEnd(now, plan.Interval)
	if plan.Interval != IntervalNone && command.TrialEnd.After(now) {
		status = SubscriptionTrialing
		periodFinish = command.TrialEnd
	}
	return &Subscription{
		ID: id, TenantID: command.TenantID, Plan: PlanRef{ID: plan.ID, Version: plan.Version},
		Renewal: renewalTerms(plan), Status: status,
		CurrentPeriodStart: now, CurrentPeriodEnd: periodFinish, TrialEnd: command.TrialEnd,
		Provider: command.Provider, ProviderSubscriptionID: command.ProviderSubscriptionID,
		RenewalNextAttemptAt: periodFinish, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
}

func renewalTerms(plan *Plan) RenewalTerms {
	return RenewalTerms{
		Interval: plan.Interval, Price: plan.Price, GracePeriodDays: plan.GracePeriodDays,
	}
}

type ChangePlanCommand struct {
	SubscriptionID   string
	Plan             PlanRef
	ExpectedRevision uint64
}

func (s *Service) ChangePlan(
	ctx context.Context, command ChangePlanCommand,
) (*Subscription, *EntitlementSnapshot, error) {
	current, err := s.store.GetSubscription(ctx, command.SubscriptionID)
	if err != nil {
		return nil, nil, err
	}
	if terminalStatus(current.Status) {
		return nil, nil, ErrTransitionDenied
	}
	if err := expectedRevision(current, command.ExpectedRevision); err != nil {
		return nil, nil, err
	}
	plan, err := s.activePlan(ctx, command.Plan)
	if err != nil {
		return nil, nil, err
	}
	next := cloneSubscription(current)
	next.Plan = PlanRef{ID: plan.ID, Version: plan.Version}
	next.Renewal = renewalTerms(plan)
	advanceSubscription(next, s.now())
	return s.applySubscription(ctx, current.Revision, next, plan, EventSubscriptionPlanChanged)
}

type TransitionSubscriptionCommand struct {
	SubscriptionID   string
	To               SubscriptionStatus
	ExpectedRevision uint64
}

func (s *Service) TransitionSubscription(
	ctx context.Context, command TransitionSubscriptionCommand,
) (*Subscription, *EntitlementSnapshot, error) {
	current, err := s.store.GetSubscription(ctx, command.SubscriptionID)
	if err != nil {
		return nil, nil, err
	}
	if err := expectedRevision(current, command.ExpectedRevision); err != nil {
		return nil, nil, err
	}
	if current.Status == command.To {
		entitlement, getErr := s.store.CurrentEntitlement(ctx, current.TenantID)
		return current, entitlement, getErr
	}
	if !canTransition(current.Status, command.To) {
		return nil, nil, ErrTransitionDenied
	}
	plan, err := s.store.GetPlan(ctx, current.Plan.ID, current.Plan.Version)
	if err != nil {
		return nil, nil, err
	}
	next := cloneSubscription(current)
	now := s.now()
	applyStatus(next, command.To, now)
	advanceSubscription(next, now)
	return s.applySubscription(ctx, current.Revision, next, plan, EventSubscriptionStatusChanged)
}

type RenewSubscriptionCommand struct {
	SubscriptionID   string
	ExpectedRevision uint64
}

func (s *Service) RenewSubscription(
	ctx context.Context, command RenewSubscriptionCommand,
) (*Subscription, *EntitlementSnapshot, error) {
	current, err := s.store.GetSubscription(ctx, command.SubscriptionID)
	if err != nil {
		return nil, nil, err
	}
	if terminalStatus(current.Status) || current.Status == SubscriptionPaused || current.CancelAtPeriodEnd {
		return nil, nil, ErrTransitionDenied
	}
	if err := expectedRevision(current, command.ExpectedRevision); err != nil {
		return nil, nil, err
	}
	plan, err := s.store.GetPlan(ctx, current.Plan.ID, current.Plan.Version)
	if err != nil {
		return nil, nil, err
	}
	next := cloneSubscription(current)
	now := s.now()
	start := laterTime(now, current.CurrentPeriodEnd)
	next.CurrentPeriodStart, next.CurrentPeriodEnd = start, periodEnd(start, next.Renewal.Interval)
	next.Status, next.GraceUntil = SubscriptionActive, time.Time{}
	next.RenewalNextAttemptAt = next.CurrentPeriodEnd
	advanceSubscription(next, now)
	return s.applySubscription(ctx, current.Revision, next, plan, EventSubscriptionRenewed)
}

func (s *Service) applySubscription(
	ctx context.Context, expected uint64, next *Subscription, plan *Plan, eventType EventType,
) (*Subscription, *EntitlementSnapshot, error) {
	now := s.now()
	entitlement := entitlementFor(plan, next, now)
	events, err := s.subscriptionEvents(next, entitlement, eventType, now)
	if err != nil {
		return nil, nil, err
	}
	mutation := SubscriptionMutation{
		ExpectedRevision: expected, Subscription: next, Entitlement: entitlement, Events: events,
	}
	if err := s.store.ApplySubscription(ctx, mutation); err != nil {
		return nil, nil, err
	}
	return cloneSubscription(next), cloneEntitlement(entitlement), nil
}

func grantsAccess(status SubscriptionStatus) bool {
	return status == SubscriptionTrialing || status == SubscriptionActive || status == SubscriptionPastDue
}

func advanceSubscription(subscription *Subscription, now time.Time) {
	subscription.Revision++
	subscription.UpdatedAt = now
}

func applyStatus(subscription *Subscription, status SubscriptionStatus, now time.Time) {
	subscription.Status = status
	if status == SubscriptionPastDue {
		base := laterTime(now, subscription.CurrentPeriodEnd)
		subscription.GraceUntil = base.AddDate(0, 0, subscription.Renewal.GracePeriodDays)
		subscription.RenewalNextAttemptAt = now
	}
	if status == SubscriptionCanceled || status == SubscriptionExpired {
		subscription.CanceledAt = now
		subscription.CancelAtPeriodEnd = false
		subscription.RenewalNextAttemptAt = time.Time{}
	}
	if status == SubscriptionActive {
		subscription.GraceUntil = time.Time{}
		subscription.RenewalNextAttemptAt = subscription.CurrentPeriodEnd
	}
}

var transitionTargets = map[SubscriptionStatus][]SubscriptionStatus{
	SubscriptionPending:  {SubscriptionTrialing, SubscriptionActive, SubscriptionCanceled},
	SubscriptionTrialing: {SubscriptionActive, SubscriptionPastDue, SubscriptionCanceled, SubscriptionExpired},
	SubscriptionActive:   {SubscriptionPastDue, SubscriptionPaused, SubscriptionCanceled, SubscriptionExpired},
	SubscriptionPastDue:  {SubscriptionActive, SubscriptionPaused, SubscriptionCanceled, SubscriptionExpired},
	SubscriptionPaused:   {SubscriptionActive, SubscriptionCanceled, SubscriptionExpired},
}

func canTransition(from, to SubscriptionStatus) bool {
	for _, target := range transitionTargets[from] {
		if target == to {
			return true
		}
	}
	return false
}

func terminalStatus(status SubscriptionStatus) bool {
	return status == SubscriptionCanceled || status == SubscriptionExpired
}

func expectedRevision(subscription *Subscription, expected uint64) error {
	if expected != 0 && subscription.Revision != expected {
		return ErrRevisionConflict
	}
	return nil
}

const maxRenewalBatchSize = 500

type SettleRenewalsCommand struct {
	Owner      string
	Lease      time.Duration
	RetryDelay time.Duration
	Limit      int
}

func (command SettleRenewalsCommand) validate() error {
	if command.Owner == "" || command.Lease <= 0 || command.RetryDelay <= 0 ||
		command.Limit <= 0 || command.Limit > maxRenewalBatchSize {
		return ErrInvalidRenewal
	}
	return nil
}

// SettleDueSubscriptions claims and atomically settles one bounded batch.
// Each claim is independently committed so a later operational error leaves
// earlier results durable and the failed claim recoverable after its lease.
func (s *Service) SettleDueSubscriptions(
	ctx context.Context, command SettleRenewalsCommand,
) ([]*RenewalResult, error) {
	if err := command.validate(); err != nil {
		return nil, err
	}
	now := s.now()
	claims, err := s.store.ClaimDueRenewals(ctx, command.Owner, now, command.Lease, command.Limit)
	if err != nil {
		return nil, err
	}
	results := make([]*RenewalResult, 0, len(claims))
	for _, claim := range claims {
		result, settleErr := s.settleRenewalClaimAt(ctx, claim, command.RetryDelay, s.now())
		if settleErr != nil {
			return results, settleErr
		}
		results = append(results, result)
	}
	return results, nil
}

// InspectRenewalBacklog reports durable global settlement lag without claiming
// work, so health reporting does not change worker ownership.
func (s *Service) InspectRenewalBacklog(ctx context.Context, now time.Time) (RenewalBacklog, error) {
	return s.store.InspectRenewalBacklog(ctx, now)
}

func (s *Service) SettleRenewalClaim(
	ctx context.Context, claim *RenewalClaim, retryDelay time.Duration,
) (*RenewalResult, error) {
	return s.settleRenewalClaimAt(ctx, claim, retryDelay, s.now())
}

func (s *Service) settleRenewalClaimAt(
	ctx context.Context, claim *RenewalClaim, retryDelay time.Duration, now time.Time,
) (*RenewalResult, error) {
	if claim == nil || claim.Subscription == nil || retryDelay <= 0 {
		return nil, ErrInvalidRenewal
	}
	entitlement, err := s.store.CurrentEntitlement(ctx, claim.Subscription.TenantID)
	if err != nil {
		return nil, err
	}
	mutation, err := s.projectRenewal(claim, entitlement, retryDelay, now)
	if err != nil {
		return nil, err
	}
	return s.store.ApplyRenewal(ctx, mutation)
}

func (s *Service) projectRenewal(
	claim *RenewalClaim, entitlement *EntitlementSnapshot, retryDelay time.Duration, now time.Time,
) (RenewalMutation, error) {
	current := claim.Subscription
	if !entitlementMatchesSubscription(entitlement, current) {
		return RenewalMutation{}, ErrInvalidRenewal
	}
	if current.CancelAtPeriodEnd {
		return s.terminalRenewal(claim, entitlement, SubscriptionCanceled, RenewalCanceled, now)
	}
	if current.Status == SubscriptionPastDue && !current.GraceUntil.After(now) {
		return s.terminalRenewal(claim, entitlement, SubscriptionExpired, RenewalExpired, now)
	}
	return s.financialRenewal(claim, entitlement, retryDelay, now)
}

func (s *Service) terminalRenewal(
	claim *RenewalClaim, entitlement *EntitlementSnapshot, status SubscriptionStatus,
	outcome RenewalOutcome, now time.Time,
) (RenewalMutation, error) {
	next := cloneSubscription(claim.Subscription)
	next.Status, next.CanceledAt = status, now
	next.CancelAtPeriodEnd, next.RenewalNextAttemptAt = false, time.Time{}
	advanceSubscription(next, now)
	projection := renewalEntitlement(entitlement, next, now)
	branch, err := s.renewalBranch(claim.Subscription.Revision, next, projection, EventSubscriptionStatusChanged, now)
	if err != nil {
		return RenewalMutation{}, err
	}
	return newRenewalMutation(claim, now, branch, outcome), nil
}

func (s *Service) financialRenewal(
	claim *RenewalClaim, entitlement *EntitlementSnapshot, retryDelay time.Duration, now time.Time,
) (RenewalMutation, error) {
	current := claim.Subscription
	renewed := renewedSubscription(current, now)
	renewedEntitlement := renewalEntitlement(entitlement, renewed, now)
	success, err := s.renewalBranch(current.Revision, renewed, renewedEntitlement, EventSubscriptionRenewed, now)
	if err != nil {
		return RenewalMutation{}, err
	}
	mutation := newRenewalMutation(claim, now, success, RenewalRenewed)
	if current.Renewal.Price.MinorUnits == 0 {
		return mutation, nil
	}
	return s.addDebitOutcomes(mutation, current, entitlement, retryDelay, now)
}

func newRenewalMutation(
	claim *RenewalClaim, now time.Time, success *SubscriptionMutation, outcome RenewalOutcome,
) RenewalMutation {
	return RenewalMutation{
		Owner: claim.Owner, ClaimUntil: claim.LeaseUntil, AttemptedAt: now,
		ExpectedRevision:  claim.Subscription.Revision,
		ExpectedPeriodEnd: claim.Subscription.CurrentPeriodEnd,
		Success:           success, SuccessOutcome: outcome,
	}
}

func renewedSubscription(current *Subscription, now time.Time) *Subscription {
	next := cloneSubscription(current)
	start := laterTime(now, current.CurrentPeriodEnd)
	next.CurrentPeriodStart = start
	next.CurrentPeriodEnd = periodEnd(start, current.Renewal.Interval)
	next.Status, next.GraceUntil = SubscriptionActive, time.Time{}
	next.RenewalNextAttemptAt = next.CurrentPeriodEnd
	advanceSubscription(next, now)
	return next
}

func (s *Service) addDebitOutcomes(
	mutation RenewalMutation, current *Subscription, entitlement *EntitlementSnapshot,
	retryDelay time.Duration, now time.Time,
) (RenewalMutation, error) {
	debit, event, err := s.renewalDebit(current, now)
	if err != nil {
		return RenewalMutation{}, err
	}
	mutation.Success.Events = append(mutation.Success.Events, event)
	failed, outcome := failedRenewalSubscription(current, retryDelay, now)
	failedEntitlement := renewalEntitlement(entitlement, failed, now)
	branch, err := s.renewalBranch(current.Revision, failed, failedEntitlement, EventSubscriptionRenewalFailed, now)
	if err != nil {
		return RenewalMutation{}, err
	}
	branch.Events[0].Payload["reason"] = "insufficient_funds"
	branch.Events[0].PayloadDigest = digestPayload(branch.Events[0].Payload)
	mutation.Debit, mutation.Insufficient = debit, branch
	mutation.InsufficientOutcome = outcome
	return mutation, nil
}

func (s *Service) renewalDebit(current *Subscription, now time.Time) (*LedgerEntry, *OutboxEvent, error) {
	id, err := s.newID("led")
	if err != nil {
		return nil, nil, err
	}
	period := current.CurrentPeriodEnd.UTC().Format(time.RFC3339Nano)
	entry := &LedgerEntry{
		ID: id, TenantID: current.TenantID, Currency: current.Renewal.Price.Currency,
		Kind: LedgerSubscriptionCharge, AmountMinor: -current.Renewal.Price.MinorUnits,
		IdempotencyKey: "renewal:" + current.ID + ":" + period,
		Reference:      current.ID + ":" + period, OccurredAt: now, CreatedAt: now,
	}
	event, err := s.walletEvent(entry, now)
	return entry, event, err
}

func failedRenewalSubscription(
	current *Subscription, retryDelay time.Duration, now time.Time,
) (*Subscription, RenewalOutcome) {
	next := cloneSubscription(current)
	if next.GraceUntil.IsZero() {
		base := laterTime(now, next.CurrentPeriodEnd)
		next.GraceUntil = base.AddDate(0, 0, next.Renewal.GracePeriodDays)
	}
	outcome := RenewalPastDue
	next.Status = SubscriptionPastDue
	next.RenewalNextAttemptAt = earlierTime(now.Add(retryDelay), next.GraceUntil)
	if !next.GraceUntil.After(now) {
		next.Status, next.CanceledAt = SubscriptionExpired, now
		next.RenewalNextAttemptAt, outcome = time.Time{}, RenewalExpired
	}
	advanceSubscription(next, now)
	return next, outcome
}

func (s *Service) renewalBranch(
	expected uint64, subscription *Subscription, entitlement *EntitlementSnapshot,
	eventType EventType, now time.Time,
) (*SubscriptionMutation, error) {
	events, err := s.subscriptionEvents(subscription, entitlement, eventType, now)
	if err != nil {
		return nil, err
	}
	return &SubscriptionMutation{
		ExpectedRevision: expected, Subscription: subscription, Entitlement: entitlement, Events: events,
	}, nil
}

func renewalEntitlement(
	current *EntitlementSnapshot, subscription *Subscription, now time.Time,
) *EntitlementSnapshot {
	next := cloneEntitlement(current)
	next.Revision, next.Active = subscription.Revision, grantsAccess(subscription.Status)
	next.EffectiveAt, next.GeneratedAt = now, now
	next.ExpiresAt = subscription.CurrentPeriodEnd
	if subscription.Status == SubscriptionPastDue && subscription.GraceUntil.After(next.ExpiresAt) {
		next.ExpiresAt = subscription.GraceUntil
	}
	if !next.Active {
		next.ExpiresAt = now
	}
	return next
}

func earlierTime(left, right time.Time) time.Time {
	if right.IsZero() || left.Before(right) {
		return left
	}
	return right
}
