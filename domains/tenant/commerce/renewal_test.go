package commerce_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

type renewalClock struct{ nanos atomic.Int64 }

type catalogGuardStore struct {
	commerce.Store
	rejectGetPlan atomic.Bool
	getPlanCalls  atomic.Int64
}

func (store *catalogGuardStore) GetPlan(
	ctx context.Context, id string, version uint64,
) (*commerce.Plan, error) {
	store.getPlanCalls.Add(1)
	if store.rejectGetPlan.Load() {
		return nil, errors.New("catalog lookup forbidden during renewal")
	}
	return store.Store.GetPlan(ctx, id, version)
}

func newRenewalClock(now time.Time) *renewalClock {
	clock := &renewalClock{}
	clock.Set(now)
	return clock
}

func (clock *renewalClock) Set(now time.Time) { clock.nanos.Store(now.UnixNano()) }

func (clock *renewalClock) Now() time.Time {
	return time.Unix(0, clock.nanos.Load()).UTC()
}

func newRenewalService(
	t *testing.T, store commerce.Store, clock *renewalClock,
) *commerce.Service {
	t.Helper()
	var sequence atomic.Uint64
	service, err := commerce.NewService(store,
		commerce.WithClock(clock.Now),
		commerce.WithIDGenerator(func(prefix string) (string, error) {
			return fmt.Sprintf("%s_renewal_%d", prefix, sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func seedRenewal(
	t *testing.T, service *commerce.Service, tenantID string, balance int64,
) *commerce.Subscription {
	t.Helper()
	publishTestPlan(t, service, "full", 1)
	subscription, _ := createTestSubscription(t, service, "sub-"+tenantID, tenantID, "full", 1)
	if subscription.Renewal.Price.MinorUnits != 4900 ||
		subscription.Renewal.Interval != commerce.IntervalMonth {
		t.Fatalf("renewal terms not snapshotted: %+v", subscription.Renewal)
	}
	if balance > 0 {
		_, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
			TenantID: tenantID, Currency: "USD", Kind: commerce.LedgerTopUp,
			AmountMinor: balance, IdempotencyKey: "seed:" + tenantID,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return subscription
}

func renewalCommand(owner string) commerce.SettleRenewalsCommand {
	return commerce.SettleRenewalsCommand{
		Owner: owner, Lease: 2 * time.Minute, RetryDelay: time.Hour, Limit: 50,
	}
}

func TestConcurrentRenewalWorkersDebitAndAdvanceOnce(t *testing.T) {
	clock := newRenewalClock(testNow)
	store := commerce.NewMemoryStore(commerce.WithMemoryStoreClock(clock.Now))
	service := newRenewalService(t, store, clock)
	subscription := seedRenewal(t, service, "tenant-funded", 10_000)
	clock.Set(subscription.CurrentPeriodEnd)

	var settled atomic.Int64
	var wait sync.WaitGroup
	errorsChannel := make(chan error, 32)
	for worker := range 32 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results, err := service.SettleDueSubscriptions(
				context.Background(), renewalCommand(fmt.Sprintf("worker-%d", worker)),
			)
			settled.Add(int64(len(results)))
			errorsChannel <- err
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
	if settled.Load() != 1 {
		t.Fatalf("settlements = %d, want 1", settled.Load())
	}
	assertFundedRenewal(t, store, subscription)
}

func TestAutomaticRenewalDoesNotReadCatalog(t *testing.T) {
	clock := newRenewalClock(testNow)
	store := &catalogGuardStore{Store: commerce.NewMemoryStore(commerce.WithMemoryStoreClock(clock.Now))}
	service := newRenewalService(t, store, clock)
	subscription := seedRenewal(t, service, "tenant-snapshot", 5_000)
	store.getPlanCalls.Store(0)
	store.rejectGetPlan.Store(true)
	clock.Set(subscription.CurrentPeriodEnd)

	result := settleOne(t, service, "worker-snapshot")
	if result.Outcome != commerce.RenewalRenewed || result.Wallet.BalanceMinor != 100 {
		t.Fatalf("snapshot renewal = %+v", result)
	}
	if calls := store.getPlanCalls.Load(); calls != 0 {
		t.Fatalf("automatic renewal performed %d catalog lookups", calls)
	}
}

func TestRenewalBacklogIncludesLeasedDueSubscriptions(t *testing.T) {
	clock := newRenewalClock(testNow)
	store := commerce.NewMemoryStore(commerce.WithMemoryStoreClock(clock.Now))
	service := newRenewalService(t, store, clock)
	subscription := seedRenewal(t, service, "tenant-backlog", 5_000)
	now := subscription.CurrentPeriodEnd.Add(5 * time.Minute)
	clock.Set(now)

	backlog, err := service.InspectRenewalBacklog(context.Background(), now)
	if err != nil || backlog.DueCount != 1 || !backlog.OldestDueAt.Equal(subscription.CurrentPeriodEnd) {
		t.Fatalf("renewal backlog = %+v err=%v", backlog, err)
	}
	claims, err := store.ClaimDueRenewals(context.Background(), "worker", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("renewal claims = %+v err=%v", claims, err)
	}
	backlog, err = service.InspectRenewalBacklog(context.Background(), now)
	if err != nil || backlog.DueCount != 1 {
		t.Fatalf("leased renewal disappeared from backlog: %+v err=%v", backlog, err)
	}
}

func TestTrialEndsBeforeFirstPaidRenewalPeriod(t *testing.T) {
	clock := newRenewalClock(testNow)
	store := commerce.NewMemoryStore(commerce.WithMemoryStoreClock(clock.Now))
	service := newRenewalService(t, store, clock)
	publishTestPlan(t, service, "trial-plan", 1)
	if _, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-trial", Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 5_000, IdempotencyKey: "trial-funds",
	}); err != nil {
		t.Fatal(err)
	}
	trialEnd := testNow.AddDate(0, 0, 14)
	subscription, entitlement, err := service.CreateSubscription(context.Background(), commerce.CreateSubscriptionCommand{
		ID: "sub-trial", TenantID: "tenant-trial", Plan: commerce.PlanRef{ID: "trial-plan", Version: 1},
		TrialEnd: trialEnd,
	})
	if err != nil || subscription.Status != commerce.SubscriptionTrialing ||
		!subscription.CurrentPeriodEnd.Equal(trialEnd) || !entitlement.ExpiresAt.Equal(trialEnd) {
		t.Fatalf("trial projection = %+v entitlement=%+v err=%v", subscription, entitlement, err)
	}
	clock.Set(trialEnd)
	result := settleOne(t, service, "worker-trial")
	if result.Outcome != commerce.RenewalRenewed || result.Subscription.Status != commerce.SubscriptionActive ||
		!result.Subscription.CurrentPeriodStart.Equal(trialEnd) ||
		!result.Subscription.CurrentPeriodEnd.Equal(trialEnd.AddDate(0, 1, 0)) ||
		result.Wallet.BalanceMinor != 100 {
		t.Fatalf("trial settlement = %+v", result)
	}
}

func assertFundedRenewal(
	t *testing.T, store *commerce.MemoryStore, original *commerce.Subscription,
) {
	t.Helper()
	stored, err := store.GetSubscription(context.Background(), original.ID)
	if err != nil || stored.Revision != 2 || stored.Status != commerce.SubscriptionActive ||
		!stored.CurrentPeriodStart.Equal(original.CurrentPeriodEnd) {
		t.Fatalf("renewal not advanced once: %+v %v", stored, err)
	}
	wallet, _ := store.GetWallet(context.Background(), original.TenantID, "USD")
	entries, _ := store.ListLedgerEntries(context.Background(), original.TenantID, "USD", 10)
	if wallet.BalanceMinor != 5100 || wallet.Version != 2 || len(entries) != 2 ||
		entries[0].Kind != commerce.LedgerSubscriptionCharge {
		t.Fatalf("renewal debit mismatch: wallet=%+v entries=%+v", wallet, entries)
	}
}

func TestInsufficientRenewalKeepsFixedGraceThenExpires(t *testing.T) {
	clock := newRenewalClock(testNow)
	store := commerce.NewMemoryStore(commerce.WithMemoryStoreClock(clock.Now))
	service := newRenewalService(t, store, clock)
	subscription := seedRenewal(t, service, "tenant-empty", 0)
	due := subscription.CurrentPeriodEnd
	clock.Set(due)

	first := settleOne(t, service, "worker-a")
	if first.Outcome != commerce.RenewalPastDue ||
		first.Subscription.Status != commerce.SubscriptionPastDue {
		t.Fatalf("insufficient settlement = %+v", first)
	}
	grace := first.Subscription.GraceUntil
	if !grace.Equal(due.AddDate(0, 0, 7)) {
		t.Fatalf("grace = %v", grace)
	}
	clock.Set(first.Subscription.RenewalNextAttemptAt)
	second := settleOne(t, service, "worker-b")
	if second.Outcome != commerce.RenewalPastDue || !second.Subscription.GraceUntil.Equal(grace) {
		t.Fatalf("retry extended grace: %+v", second.Subscription)
	}
	clock.Set(grace)
	expired := settleOne(t, service, "worker-c")
	if expired.Outcome != commerce.RenewalExpired || expired.Subscription.Status != commerce.SubscriptionExpired ||
		expired.Entitlement.Active {
		t.Fatalf("grace-end policy mismatch: %+v", expired)
	}
	entries, _ := store.ListLedgerEntries(context.Background(), subscription.TenantID, "USD", 10)
	if len(entries) != 0 {
		t.Fatalf("insufficient renewal wrote ledger: %+v", entries)
	}
	assertRenewalFailureFacts(t, store, due)
}

func settleOne(t *testing.T, service *commerce.Service, owner string) *commerce.RenewalResult {
	t.Helper()
	results, err := service.SettleDueSubscriptions(context.Background(), renewalCommand(owner))
	if err != nil || len(results) != 1 {
		t.Fatalf("settlement result=%+v err=%v", results, err)
	}
	return results[0]
}

func assertRenewalFailureFacts(t *testing.T, store *commerce.MemoryStore, now time.Time) {
	t.Helper()
	events, err := store.ClaimOutbox(context.Background(), "audit", now.AddDate(0, 0, 8), time.Minute, 100)
	if err != nil {
		t.Fatal(err)
	}
	failures := 0
	for _, event := range events {
		if event.Type == commerce.EventSubscriptionRenewalFailed {
			failures++
			if event.Payload["reason"] != "insufficient_funds" {
				t.Fatalf("renewal failure reason = %+v", event.Payload)
			}
		}
	}
	if failures != 2 {
		t.Fatalf("renewal failure facts = %d, want 2", failures)
	}
}

func TestRenewalRetrySucceedsAfterTopUp(t *testing.T) {
	clock := newRenewalClock(testNow)
	store := commerce.NewMemoryStore(commerce.WithMemoryStoreClock(clock.Now))
	service := newRenewalService(t, store, clock)
	subscription := seedRenewal(t, service, "tenant-retry", 0)
	clock.Set(subscription.CurrentPeriodEnd)
	pastDue := settleOne(t, service, "worker-a")

	clock.Set(pastDue.Subscription.RenewalNextAttemptAt.Add(-time.Minute))
	_, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: subscription.TenantID, Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 5_000, IdempotencyKey: "retry-funds",
	})
	if err != nil {
		t.Fatal(err)
	}
	clock.Set(pastDue.Subscription.RenewalNextAttemptAt)
	renewed := settleOne(t, service, "worker-b")
	if renewed.Outcome != commerce.RenewalRenewed || renewed.Subscription.Revision != 3 ||
		!renewed.Subscription.GraceUntil.IsZero() || renewed.Wallet.BalanceMinor != 100 {
		t.Fatalf("funded retry failed: %+v", renewed)
	}
}

func TestExpiredRenewalClaimCannotCommit(t *testing.T) {
	serviceClock := newRenewalClock(testNow)
	storeClock := newRenewalClock(testNow)
	store := commerce.NewMemoryStore(commerce.WithMemoryStoreClock(storeClock.Now))
	service := newRenewalService(t, store, serviceClock)
	subscription := seedRenewal(t, service, "tenant-stale", 5_000)
	due := subscription.CurrentPeriodEnd
	serviceClock.Set(due)
	storeClock.Set(due)
	claims, err := store.ClaimDueRenewals(context.Background(), "old", due, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("initial claim=%+v err=%v", claims, err)
	}
	storeClock.Set(due.Add(2 * time.Minute))
	if _, err := service.SettleRenewalClaim(context.Background(), claims[0], time.Hour); !errors.Is(err, commerce.ErrRenewalClaimLost) {
		t.Fatalf("expired claim error = %v", err)
	}
	serviceClock.Set(due.Add(2 * time.Minute))
	renewed := settleOne(t, service, "new")
	if renewed.Outcome != commerce.RenewalRenewed || renewed.Wallet.BalanceMinor != 100 {
		t.Fatalf("reclaimed settlement failed: %+v", renewed)
	}
}
