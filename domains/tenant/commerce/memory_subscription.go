package commerce

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"time"
)

func (s *MemoryStore) ApplySubscription(ctx context.Context, mutation SubscriptionMutation) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateSubscriptionMutation(mutation); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.subscriptionReplayLocked(mutation) {
		return nil
	}
	if err := s.validateSubscriptionRevisionLocked(mutation); err != nil {
		return err
	}
	if err := s.validateTenantSubscriptionLocked(mutation); err != nil {
		return err
	}
	events, err := s.prepareOutboxLocked(mutation.Events)
	if err != nil {
		return err
	}
	s.commitSubscriptionLocked(mutation)
	s.commitOutboxLocked(events)
	return nil
}

func (s *MemoryStore) subscriptionReplayLocked(mutation SubscriptionMutation) bool {
	current, ok := s.subscriptions[mutation.Subscription.ID]
	if !ok || !reflect.DeepEqual(current, mutation.Subscription) {
		return false
	}
	for _, event := range mutation.Events {
		if !s.outboxReplayLocked(event) {
			return false
		}
	}
	return true
}

func (s *MemoryStore) validateSubscriptionRevisionLocked(mutation SubscriptionMutation) error {
	current, exists := s.subscriptions[mutation.Subscription.ID]
	if !exists {
		if mutation.ExpectedRevision != 0 || mutation.Subscription.Revision != 1 {
			return ErrRevisionConflict
		}
		return nil
	}
	if current.Revision != mutation.ExpectedRevision {
		return ErrRevisionConflict
	}
	if mutation.Subscription.Revision != current.Revision+1 {
		return ErrRevisionConflict
	}
	return nil
}

func (s *MemoryStore) validateTenantSubscriptionLocked(mutation SubscriptionMutation) error {
	currentID, exists := s.currentSubscription[mutation.Subscription.TenantID]
	if !exists || currentID == mutation.Subscription.ID {
		return nil
	}
	current := s.subscriptions[currentID]
	if current == nil || terminalStatus(current.Status) {
		return nil
	}
	return ErrTenantSubscribed
}

func (s *MemoryStore) commitSubscriptionLocked(mutation SubscriptionMutation) {
	subscription := cloneSubscription(mutation.Subscription)
	_, exists := s.subscriptions[subscription.ID]
	s.subscriptions[subscription.ID] = subscription
	s.entitlements[subscription.TenantID] = cloneEntitlement(mutation.Entitlement)
	s.currentSubscription[subscription.TenantID] = subscription.ID
	delete(s.renewalClaims, subscription.ID)
	if !exists {
		s.tenantSubscriptions[subscription.TenantID] = append(
			s.tenantSubscriptions[subscription.TenantID], subscription.ID,
		)
	}
}

func (s *MemoryStore) ClaimDueRenewals(
	ctx context.Context, owner string, now time.Time, lease time.Duration, limit int,
) ([]*RenewalClaim, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == "" || now.IsZero() || lease <= 0 || limit <= 0 {
		return nil, ErrInvalidRenewal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	eligible := s.eligibleRenewalsLocked(now)
	if limit < len(eligible) {
		eligible = eligible[:limit]
	}
	claims := make([]*RenewalClaim, 0, len(eligible))
	for _, subscription := range eligible {
		until := now.Add(lease)
		s.renewalClaims[subscription.ID] = renewalLease{owner: owner, until: until}
		claims = append(claims, &RenewalClaim{
			Subscription: cloneSubscription(subscription), Owner: owner, LeaseUntil: until,
		})
	}
	return claims, nil
}

func (s *MemoryStore) eligibleRenewalsLocked(now time.Time) []*Subscription {
	eligible := make([]*Subscription, 0)
	for _, subscription := range s.subscriptions {
		claim := s.renewalClaims[subscription.ID]
		if renewalDue(subscription, now) && !claim.until.After(now) {
			eligible = append(eligible, subscription)
		}
	}
	sort.Slice(eligible, func(left, right int) bool {
		if eligible[left].RenewalNextAttemptAt.Equal(eligible[right].RenewalNextAttemptAt) {
			return eligible[left].ID < eligible[right].ID
		}
		return eligible[left].RenewalNextAttemptAt.Before(eligible[right].RenewalNextAttemptAt)
	})
	return eligible
}

func renewalDue(subscription *Subscription, now time.Time) bool {
	statusDue := subscription.Status == SubscriptionActive ||
		subscription.Status == SubscriptionTrialing || subscription.Status == SubscriptionPastDue
	return statusDue && subscription.Renewal.Interval != IntervalNone &&
		!subscription.CurrentPeriodEnd.After(now) && !subscription.RenewalNextAttemptAt.After(now)
}

func (s *MemoryStore) InspectRenewalBacklog(
	ctx context.Context, now time.Time,
) (RenewalBacklog, error) {
	if err := ctx.Err(); err != nil {
		return RenewalBacklog{}, err
	}
	if now.IsZero() {
		return RenewalBacklog{}, ErrInvalidRenewal
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	backlog := RenewalBacklog{}
	for _, subscription := range s.subscriptions {
		if !renewalDue(subscription, now) {
			continue
		}
		backlog.DueCount++
		dueAt := laterTime(subscription.CurrentPeriodEnd, subscription.RenewalNextAttemptAt)
		if backlog.OldestDueAt.IsZero() || dueAt.Before(backlog.OldestDueAt) {
			backlog.OldestDueAt = dueAt
		}
	}
	return backlog, nil
}

func (s *MemoryStore) ApplyRenewal(
	ctx context.Context, mutation RenewalMutation,
) (*RenewalResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := mutation.Validate(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, wallet, err := s.validateRenewalLocked(mutation)
	if err != nil {
		return nil, err
	}
	if mutation.Debit == nil {
		return s.commitRenewalLocked(mutation.Success, mutation.SuccessOutcome, nil, wallet)
	}
	if wallet.Status == WalletFrozen {
		return nil, ErrWalletFrozen
	}
	balance, balanceErr := nextBalance(wallet.BalanceMinor, mutation.Debit.AmountMinor)
	if errors.Is(balanceErr, ErrInsufficientFunds) {
		return s.commitRenewalLocked(mutation.Insufficient, mutation.InsufficientOutcome, nil, wallet)
	}
	if balanceErr != nil {
		return nil, balanceErr
	}
	entry, nextWallet := nextWalletState(mutation.Debit, wallet, balance)
	_ = current
	return s.commitRenewalLocked(mutation.Success, mutation.SuccessOutcome, entry, nextWallet)
}

func (s *MemoryStore) validateRenewalLocked(
	mutation RenewalMutation,
) (*Subscription, *Wallet, error) {
	current := s.subscriptions[mutation.Success.Subscription.ID]
	if current == nil {
		return nil, nil, ErrSubscriptionNotFound
	}
	lease, claimed := s.renewalClaims[current.ID]
	if !claimed || lease.owner != mutation.Owner || !lease.until.Equal(mutation.ClaimUntil) ||
		!lease.until.After(mutation.AttemptedAt) || !lease.until.After(s.now()) {
		return nil, nil, ErrRenewalClaimLost
	}
	if current.Revision != mutation.ExpectedRevision ||
		!current.CurrentPeriodEnd.Equal(mutation.ExpectedPeriodEnd) ||
		!sameRenewalIdentity(current, mutation.Success.Subscription) {
		return nil, nil, ErrRevisionConflict
	}
	key := walletKey{tenantID: current.TenantID, currency: current.Renewal.Price.Currency}
	wallet := s.wallets[key]
	if wallet == nil {
		wallet = &Wallet{TenantID: key.tenantID, Currency: key.currency, Status: WalletActive}
	}
	return current, cloneWallet(wallet), nil
}

func sameRenewalIdentity(current, next *Subscription) bool {
	return current.ID == next.ID && current.TenantID == next.TenantID &&
		current.Plan == next.Plan && current.Renewal == next.Renewal &&
		current.CreatedAt.Equal(next.CreatedAt)
}

func (s *MemoryStore) commitRenewalLocked(
	branch *SubscriptionMutation, outcome RenewalOutcome,
	entry *LedgerEntry, wallet *Wallet,
) (*RenewalResult, error) {
	events := cloneOutboxEvents(branch.Events)
	if entry != nil {
		for _, event := range events {
			if event.AggregateType == "wallet" {
				event.AggregateVersion = wallet.Version
			}
		}
	}
	prepared, err := s.prepareOutboxLocked(events)
	if err != nil {
		return nil, err
	}
	s.commitSubscriptionLocked(*branch)
	if entry != nil {
		s.commitRenewalWalletLocked(entry, wallet)
	}
	s.commitOutboxLocked(prepared)
	return &RenewalResult{
		Outcome: outcome, Subscription: cloneSubscription(branch.Subscription),
		Entitlement: cloneEntitlement(branch.Entitlement), LedgerEntry: cloneLedgerEntry(entry),
		Wallet: cloneWallet(wallet),
	}, nil
}

func (s *MemoryStore) commitRenewalWalletLocked(entry *LedgerEntry, wallet *Wallet) {
	key := walletKey{tenantID: entry.TenantID, currency: entry.Currency}
	s.wallets[key] = cloneWallet(wallet)
	s.entries[key] = append(s.entries[key], cloneLedgerEntry(entry))
	s.ledgerKeys[ledgerIdempotencyKey(entry)] = cloneLedgerEntry(entry)
	s.ledgerByID[entry.ID] = cloneLedgerEntry(entry)
}

func (s *MemoryStore) GetSubscription(ctx context.Context, id string) (*Subscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	subscription, ok := s.subscriptions[id]
	if !ok {
		return nil, ErrSubscriptionNotFound
	}
	return cloneSubscription(subscription), nil
}

func (s *MemoryStore) ListSubscriptionsByTenant(
	ctx context.Context, tenantID string,
) ([]*Subscription, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Subscription, 0, len(s.tenantSubscriptions[tenantID]))
	for _, id := range s.tenantSubscriptions[tenantID] {
		result = append(result, cloneSubscription(s.subscriptions[id]))
	}
	sort.Slice(result, func(left, right int) bool {
		return result[left].CreatedAt.Before(result[right].CreatedAt)
	})
	return result, nil
}

func (s *MemoryStore) CurrentEntitlement(
	ctx context.Context, tenantID string,
) (*EntitlementSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entitlement, ok := s.entitlements[tenantID]
	if !ok {
		return nil, ErrEntitlementNotFound
	}
	return cloneEntitlement(entitlement), nil
}
