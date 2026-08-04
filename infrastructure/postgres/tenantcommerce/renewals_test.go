package tenantcommerce

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

type postgresRenewalClock struct{ nanos atomic.Int64 }

func postgresRenewalStart() time.Time {
	return time.Now().UTC().Add(-28 * 24 * time.Hour)
}

func (clock *postgresRenewalClock) set(now time.Time) { clock.nanos.Store(now.UnixNano()) }

func (clock *postgresRenewalClock) now() time.Time {
	return time.Unix(0, clock.nanos.Load()).UTC()
}

func integrationRenewalService(
	t *testing.T, store commerce.Store, clock *postgresRenewalClock,
) *commerce.Service {
	t.Helper()
	var sequence atomic.Uint64
	service, err := commerce.NewService(store,
		commerce.WithClock(clock.now),
		commerce.WithIDGenerator(func(prefix string) (string, error) {
			return fmt.Sprintf("%s_pg_renewal_%d", prefix, sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func seedPostgresRenewal(
	t *testing.T, service *commerce.Service, tenantID string, balance int64,
) *commerce.Subscription {
	t.Helper()
	publishIntegrationPlan(t, service)
	subscription, _, err := service.CreateSubscription(context.Background(), commerce.CreateSubscriptionCommand{
		ID: "sub-" + tenantID, TenantID: tenantID, Plan: commerce.PlanRef{ID: "full", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if balance > 0 {
		_, _, err = service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
			TenantID: tenantID, Currency: "USD", Kind: commerce.LedgerTopUp,
			AmountMinor: balance, IdempotencyKey: "seed:" + tenantID,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return subscription
}

func postgresRenewalCommand(owner string) commerce.SettleRenewalsCommand {
	return commerce.SettleRenewalsCommand{
		Owner: owner, Lease: 2 * time.Minute, RetryDelay: time.Hour, Limit: 50,
	}
}

func TestPostgresConcurrentRenewalWorkersDebitOnce(t *testing.T) {
	store := integrationStore(t)
	clock := &postgresRenewalClock{}
	clock.set(postgresRenewalStart())
	service := integrationRenewalService(t, store, clock)
	subscription := seedPostgresRenewal(t, service, "tenant-renewal-funded", 10_000)
	clock.set(subscription.CurrentPeriodEnd)

	var settled atomic.Int64
	errorsChannel := make(chan error, 16)
	var wait sync.WaitGroup
	for worker := range 16 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results, err := service.SettleDueSubscriptions(
				context.Background(), postgresRenewalCommand(fmt.Sprintf("worker-%d", worker)),
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
	assertPostgresRenewalDebit(t, store, subscription)
}

func TestPostgresRenewalBacklogReportsGlobalDueAge(t *testing.T) {
	store := integrationStore(t)
	clock := &postgresRenewalClock{}
	clock.set(postgresRenewalStart())
	service := integrationRenewalService(t, store, clock)
	subscription := seedPostgresRenewal(t, service, "tenant-renewal-backlog", 5_000)
	now := subscription.CurrentPeriodEnd.Add(5 * time.Minute)

	backlog, err := store.InspectRenewalBacklog(context.Background(), now)
	if err != nil || backlog.DueCount != 1 || !backlog.OldestDueAt.Equal(subscription.CurrentPeriodEnd) {
		t.Fatalf("postgres renewal backlog = %+v err=%v", backlog, err)
	}
	claims, err := store.ClaimDueRenewals(context.Background(), "worker", now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("postgres renewal claims = %+v err=%v", claims, err)
	}
	backlog, err = store.InspectRenewalBacklog(context.Background(), now)
	if err != nil || backlog.DueCount != 1 {
		t.Fatalf("leased postgres renewal disappeared from backlog: %+v err=%v", backlog, err)
	}
}

func assertPostgresRenewalDebit(t *testing.T, store *Store, original *commerce.Subscription) {
	t.Helper()
	stored, err := store.GetSubscription(context.Background(), original.ID)
	if err != nil || stored.Revision != 2 || stored.Status != commerce.SubscriptionActive {
		t.Fatalf("stored renewal = %+v err=%v", stored, err)
	}
	wallet, err := store.GetWallet(context.Background(), original.TenantID, "USD")
	entries, listErr := store.ListLedgerEntries(context.Background(), original.TenantID, "USD", 10)
	if err != nil || listErr != nil || wallet.BalanceMinor != 5100 || wallet.Version != 2 ||
		len(entries) != 2 || entries[0].Kind != commerce.LedgerSubscriptionCharge {
		t.Fatalf("wallet=%+v entries=%+v err=%v/%v", wallet, entries, err, listErr)
	}
	assertPostgresRenewalSuccessEvents(t, store, original.CurrentPeriodEnd)
}

func assertPostgresRenewalSuccessEvents(t *testing.T, store *Store, now time.Time) {
	t.Helper()
	events, err := store.ClaimOutbox(context.Background(), "audit", now, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	wanted := map[commerce.EventType]bool{
		commerce.EventSubscriptionRenewed: false, commerce.EventWalletDebitPosted: false,
	}
	for _, event := range events {
		if _, exists := wanted[event.Type]; exists {
			wanted[event.Type] = true
		}
	}
	if !wanted[commerce.EventSubscriptionRenewed] || !wanted[commerce.EventWalletDebitPosted] {
		t.Fatalf("renewal success events missing: wanted=%+v events=%+v", wanted, events)
	}
}

func TestPostgresInsufficientRenewalIsAtomicAndAudited(t *testing.T) {
	store := integrationStore(t)
	clock := &postgresRenewalClock{}
	clock.set(postgresRenewalStart())
	service := integrationRenewalService(t, store, clock)
	subscription := seedPostgresRenewal(t, service, "tenant-renewal-empty", 0)
	clock.set(subscription.CurrentPeriodEnd)

	results, err := service.SettleDueSubscriptions(
		context.Background(), postgresRenewalCommand("worker-empty"),
	)
	if err != nil || len(results) != 1 || results[0].Outcome != commerce.RenewalPastDue {
		t.Fatalf("insufficient results=%+v err=%v", results, err)
	}
	stored, err := store.GetSubscription(context.Background(), subscription.ID)
	entries, listErr := store.ListLedgerEntries(context.Background(), subscription.TenantID, "USD", 10)
	if err != nil || listErr != nil || stored.Status != commerce.SubscriptionPastDue ||
		stored.Revision != 2 || len(entries) != 0 {
		t.Fatalf("stored=%+v entries=%+v err=%v/%v", stored, entries, err, listErr)
	}
	assertPostgresRenewalFailureEvent(t, store, clock.now())
}

func assertPostgresRenewalFailureEvent(t *testing.T, store *Store, now time.Time) {
	t.Helper()
	events, err := store.ClaimOutbox(context.Background(), "audit", now, time.Minute, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Type == commerce.EventSubscriptionRenewalFailed &&
			event.Payload["reason"] == "insufficient_funds" {
			return
		}
	}
	t.Fatalf("renewal failure event missing: %+v", events)
}

func TestPostgresExpiredRenewalClaimCannotCommit(t *testing.T) {
	store := integrationStore(t)
	clock := &postgresRenewalClock{}
	clock.set(postgresRenewalStart())
	service := integrationRenewalService(t, store, clock)
	subscription := seedPostgresRenewal(t, service, "tenant-renewal-stale", 5_000)
	due := time.Now().UTC()
	_, err := store.db.ExecContext(context.Background(), `UPDATE tenant_commerce_subscriptions
SET current_period_start_ns=$2, current_period_end_ns=$3, renewal_next_attempt_at_ns=$3
WHERE id=$1`, subscription.ID, timeNano(due.AddDate(0, -1, 0)), timeNano(due))
	if err != nil {
		t.Fatal(err)
	}
	clock.set(due)
	claims, err := store.ClaimDueRenewals(context.Background(), "old", due, 100*time.Millisecond, 1)
	if err != nil || len(claims) != 1 {
		t.Fatalf("claim=%+v err=%v", claims, err)
	}
	time.Sleep(150 * time.Millisecond)
	if _, err := service.SettleRenewalClaim(context.Background(), claims[0], time.Hour); !errors.Is(err, commerce.ErrRenewalClaimLost) {
		t.Fatalf("expired claim error = %v", err)
	}
	clock.set(due.Add(2 * time.Minute))
	results, err := service.SettleDueSubscriptions(context.Background(), postgresRenewalCommand("new"))
	if err != nil || len(results) != 1 || results[0].Wallet.BalanceMinor != 100 {
		t.Fatalf("reclaimed results=%+v err=%v", results, err)
	}
}
