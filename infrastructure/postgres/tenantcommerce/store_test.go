package tenantcommerce

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/platform/migrate"
)

var (
	integrationNow          = time.Date(2026, time.August, 4, 12, 0, 0, 123, time.UTC)
	migrationSchemaSequence atomic.Uint64
)

func TestSchemaDeclaresDurabilityBoundaries(t *testing.T) {
	baseline := []string{
		"UNIQUE (tenant_id, currency, idempotency_key)",
		"PRIMARY KEY (provider, id)",
		"idx_tenant_commerce_one_live_subscription",
		"status TEXT NOT NULL CHECK (status IN ('active', 'frozen'))",
		"UNIQUE (tenant_id, idempotency_key)",
	}
	for _, fragment := range baseline {
		if !strings.Contains(schema, fragment) {
			t.Errorf("commerce migration missing %q", fragment)
		}
	}
	renewal := []string{
		"ADD COLUMN billing_interval", "ADD COLUMN renewal_price_minor",
		"ADD COLUMN renewal_next_attempt_at_ns", "ADD COLUMN renewal_lease_owner",
		"idx_tenant_commerce_renewal_claim", "'subscription'",
	}
	for _, fragment := range renewal {
		if !strings.Contains(renewalSchema, fragment) {
			t.Errorf("renewal migration missing %q", fragment)
		}
	}
	for _, fragment := range []string{"tenant_commerce_quota_outbox", "projection_revision", "ON CONFLICT (event_id) DO NOTHING"} {
		if !strings.Contains(quotaProjectionOutboxSchema, fragment) {
			t.Errorf("quota projection migration missing %q", fragment)
		}
	}
	for _, fragment := range []string{"chargeback_reversal", "chargeback_reversed"} {
		if !strings.Contains(chargebackReversalSchema, fragment) {
			t.Errorf("chargeback reversal migration missing %q", fragment)
		}
	}
	if MaxVersion() != 4 {
		t.Fatalf("MaxVersion() = %d, want 4", MaxVersion())
	}
}

func TestPostgresMigratesVersion3ChargebackConstraints(t *testing.T) {
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping tenant commerce migration test")
	}
	adminDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = adminDB.Close() }()
	schemaName := fmt.Sprintf("tenant_commerce_upgrade_%d", migrationSchemaSequence.Add(1))
	if _, err := adminDB.ExecContext(context.Background(), "CREATE SCHEMA "+schemaName); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = adminDB.ExecContext(context.Background(), "DROP SCHEMA "+schemaName+" CASCADE")
	})

	separator := "?"
	if strings.Contains(dsn, "?") {
		separator = "&"
	}
	db, err := sql.Open("pgx", dsn+separator+"search_path="+schemaName)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	legacy := strings.ReplaceAll(schema, "'refund', 'chargeback_reversal', 'adjustment'", "'refund', 'adjustment'")
	legacy = strings.ReplaceAll(legacy, "'chargeback', 'chargeback_reversed'", "'chargeback'")
	version3 := append([]migrate.Migration(nil), migrations[:3]...)
	version3[0].SQL = legacy
	dialect := postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	if err := postgresbackend.Run(context.Background(), db, "tenant_commerce", version3, dialect); err != nil {
		t.Fatal(err)
	}
	if _, err := NewWithDB(db, dialect); err != nil {
		t.Fatal(err)
	}
	assertConstraintContains(t, db, "tenant_commerce_ledger_kind_check", "chargeback_reversal")
	assertConstraintContains(t, db, "tenant_commerce_payment_events_type_check", "chargeback_reversed")
}

func assertConstraintContains(t *testing.T, db *sql.DB, name, expected string) {
	t.Helper()
	var definition string
	err := db.QueryRowContext(context.Background(),
		`SELECT pg_get_constraintdef(oid) FROM pg_constraint WHERE conname=$1`, name).Scan(&definition)
	if err != nil || !strings.Contains(definition, expected) {
		t.Fatalf("constraint %q = %q, want %q: %v", name, definition, expected, err)
	}
}

func integrationStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set; skipping tenant commerce integration test")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	dialect := postgresbackend.Dialect(os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	store, err := NewWithDB(db, dialect)
	if err != nil {
		t.Fatal(err)
	}
	truncateCommerce(t, db)
	return store
}

func truncateCommerce(t *testing.T, db *sql.DB) {
	t.Helper()
	_, err := db.ExecContext(context.Background(), `TRUNCATE
tenant_commerce_payment_events, tenant_commerce_outbox, tenant_commerce_ledger,
tenant_commerce_entitlements, tenant_commerce_payment_orders,
tenant_commerce_subscriptions, tenant_commerce_wallets, tenant_commerce_plans CASCADE`)
	if err != nil {
		t.Fatalf("truncate commerce tables: %v", err)
	}
}

func integrationService(t *testing.T, store commerce.Store) *commerce.Service {
	t.Helper()
	var sequence atomic.Uint64
	service, err := commerce.NewService(store,
		commerce.WithClock(func() time.Time { return integrationNow }),
		commerce.WithIDGenerator(func(prefix string) (string, error) {
			return fmt.Sprintf("%s_pg_%d", prefix, sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func publishIntegrationPlan(t *testing.T, service *commerce.Service) {
	t.Helper()
	err := service.PublishPlan(context.Background(), &commerce.Plan{
		ID: "full", Version: 1, Name: "Full", Status: commerce.PlanActive,
		Interval: commerce.IntervalMonth, Price: commerce.Money{Currency: "USD", MinorUnits: 4900},
		GracePeriodDays: 7,
		Features:        map[commerce.FeatureKey]bool{commerce.FeatureCoreSSO: true},
		Limits:          map[commerce.LimitKey]commerce.LimitGrant{commerce.LimitUsers: {Soft: 90, Hard: 100}},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSubscriptionAndOutboxAreAtomic(t *testing.T) {
	store := integrationStore(t)
	service := integrationService(t, store)
	publishIntegrationPlan(t, service)
	subscription, entitlement, err := service.CreateSubscription(context.Background(), commerce.CreateSubscriptionCommand{
		ID: "sub-pg-1", TenantID: "tenant-pg-1", Plan: commerce.PlanRef{ID: "full", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if subscription.Revision != 1 || !entitlement.FeatureEnabled(commerce.FeatureCoreSSO, integrationNow) {
		t.Fatalf("unexpected subscription projection: %+v %+v", subscription, entitlement)
	}
	stored, err := store.CurrentEntitlement(context.Background(), "tenant-pg-1")
	if err != nil || stored.Revision != subscription.Revision {
		t.Fatalf("entitlement round trip failed: %+v %v", stored, err)
	}
	events, err := store.ClaimOutbox(context.Background(), "relay-a", integrationNow, time.Minute, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("business mutation did not atomically publish two facts: %d %v", len(events), err)
	}
	if err := store.CompleteOutbox(context.Background(), events[0].ID, "relay-b", integrationNow); !errors.Is(err, commerce.ErrOutboxLeaseLost) {
		t.Fatalf("wrong lease owner accepted: %v", err)
	}
	quotaEvents, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "quota", integrationNow, time.Minute, 10)
	if err != nil || len(quotaEvents) != 1 || quotaEvents[0].AggregateVersion != subscription.Revision {
		t.Fatalf("independent quota outbox = %+v %v", quotaEvents, err)
	}
}

func TestPostgresQuotaProjectionDeliveryRetriesUntilComplete(t *testing.T) {
	store := integrationStore(t)
	service := integrationService(t, store)
	publishIntegrationPlan(t, service)
	_, entitlement, err := service.CreateSubscription(context.Background(), commerce.CreateSubscriptionCommand{
		ID: "sub-quota-retry", TenantID: "tenant-quota-retry",
		Plan: commerce.PlanRef{ID: "full", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimQuotaProjectionDeliveries(
		context.Background(), "quota-a", integrationNow, time.Minute, 1,
	)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("initial quota claim = %+v, %v", claimed, err)
	}
	event := claimed[0]
	if err := store.CompleteQuotaProjectionDelivery(context.Background(), event.ID,
		"quota-b", entitlement.Revision, integrationNow); !errors.Is(err, commerce.ErrOutboxLeaseLost) {
		t.Fatalf("wrong quota lease owner accepted: %v", err)
	}
	retryAt := integrationNow.Add(time.Minute)
	if err := store.FailQuotaProjectionDelivery(context.Background(), event.ID,
		"quota-a", "dependency unavailable", integrationNow, retryAt); err != nil {
		t.Fatal(err)
	}
	if err := store.QuotaProjectionDeliveryReady(context.Background(),
		integrationNow.Add(2*time.Minute), time.Minute); !errors.Is(err, commerce.ErrQuotaProjectionLag) {
		t.Fatalf("lagged readiness = %v", err)
	}
	retried, err := store.ClaimQuotaProjectionDeliveries(
		context.Background(), "quota-b", retryAt, time.Minute, 1,
	)
	if err != nil || len(retried) != 1 || retried[0].Attempts != 2 {
		t.Fatalf("quota retry = %+v, %v", retried, err)
	}
	if err := store.CompleteQuotaProjectionDelivery(context.Background(), event.ID,
		"quota-b", entitlement.Revision, retryAt); err != nil {
		t.Fatal(err)
	}
	if err := store.QuotaProjectionDeliveryReady(context.Background(),
		integrationNow.Add(2*time.Minute), time.Minute); err != nil {
		t.Fatalf("recovered readiness = %v", err)
	}
	assertQuotaProjectionDelivery(t, store.db, event.ID, entitlement.Revision, 2)
}

func TestPostgresQuotaProjectionSerializesTenantRevisions(t *testing.T) {
	store := integrationStore(t)
	service := integrationService(t, store)
	publishIntegrationPlan(t, service)
	subscription, _, err := service.CreateSubscription(context.Background(), commerce.CreateSubscriptionCommand{
		ID: "sub-quota-serial", TenantID: "tenant-quota-serial",
		Plan: commerce.PlanRef{ID: "full", Version: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.TransitionSubscription(context.Background(), commerce.TransitionSubscriptionCommand{
		SubscriptionID: subscription.ID, To: commerce.SubscriptionPastDue, ExpectedRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}
	first, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "quota-a", integrationNow, time.Minute, 10)
	if err != nil || len(first) != 1 || first[0].AggregateVersion != 1 {
		t.Fatalf("first claim=%+v error=%v", first, err)
	}
	blocked, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "quota-b", integrationNow, time.Minute, 10)
	if err != nil || len(blocked) != 0 {
		t.Fatalf("newer revision bypassed predecessor: %+v %v", blocked, err)
	}
	if err := store.CompleteQuotaProjectionDelivery(context.Background(), first[0].ID, "quota-a", 2, integrationNow); err != nil {
		t.Fatal(err)
	}
	second, err := store.ClaimQuotaProjectionDeliveries(context.Background(), "quota-b", integrationNow, time.Minute, 10)
	if err != nil || len(second) != 1 || second[0].AggregateVersion != 2 {
		t.Fatalf("second claim=%+v error=%v", second, err)
	}
}

func assertQuotaProjectionDelivery(
	t *testing.T, db *sql.DB, eventID string, revision uint64, attempts int,
) {
	t.Helper()
	var status string
	var deliveredRevision uint64
	var storedAttempts int
	err := db.QueryRowContext(context.Background(), `SELECT status, delivered_revision, attempts
FROM tenant_commerce_quota_outbox WHERE event_id=$1`, eventID).Scan(
		&status, &deliveredRevision, &storedAttempts,
	)
	if err != nil || status != "delivered" || deliveredRevision != revision || storedAttempts != attempts {
		t.Fatalf("quota delivery state = %q rev=%d attempts=%d err=%v",
			status, deliveredRevision, storedAttempts, err)
	}
}

func TestPostgresPaymentLedgerAndFrozenWallet(t *testing.T) {
	store := integrationStore(t)
	service := integrationService(t, store)
	order, err := service.CreateTopUpOrder(context.Background(), commerce.CreateTopUpCommand{
		ID: "pay-pg-1", TenantID: "tenant-pg-1", Provider: "testpay",
		ProviderOrderID: "provider-order-1", Currency: "USD", AmountMinor: 1000, IdempotencyKey: "checkout-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	captured := paymentEvent(order, "capture-1", commerce.PaymentCaptured, 1000)
	if _, _, _, err := service.ApplyPaymentEvent(context.Background(), captured); err != nil {
		t.Fatal(err)
	}
	postUsage(t, service, -800, "usage-1")
	chargeback := paymentEvent(order, "chargeback-1", commerce.PaymentChargeback, 1000)
	if _, _, wallet, err := service.ApplyPaymentEvent(context.Background(), chargeback); err != nil {
		t.Fatal(err)
	} else if wallet.BalanceMinor != -800 || wallet.Status != commerce.WalletFrozen {
		t.Fatalf("refund did not freeze negative wallet: %+v", wallet)
	}
	assertFrozenDebit(t, service)
	reversed := paymentEvent(order, "chargeback-reversed-1", commerce.PaymentChargebackReversed, 1000)
	if restored, entry, wallet, err := service.ApplyPaymentEvent(context.Background(), reversed); err != nil {
		t.Fatal(err)
	} else if restored.Status != commerce.PaymentSucceeded || entry.Kind != commerce.LedgerChargebackReversal ||
		wallet.BalanceMinor != 200 || wallet.Status != commerce.WalletActive {
		t.Fatalf("chargeback reversal did not restore wallet: order=%+v entry=%+v wallet=%+v", restored, entry, wallet)
	}
	assertPaymentReconciliation(t, store)
	if _, _, wallet, err := service.ApplyPaymentEvent(context.Background(), reversed); err != nil || wallet.BalanceMinor != 200 {
		t.Fatalf("provider replay changed wallet: %+v %v", wallet, err)
	}
}

func paymentEvent(
	order *commerce.PaymentOrder, id string, eventType commerce.PaymentEventType, amount int64,
) *commerce.PaymentEvent {
	return &commerce.PaymentEvent{
		ID: id, Provider: order.Provider, ProviderOrderID: order.ProviderOrderID, OrderID: order.ID,
		Type: eventType, Currency: order.Currency, AmountMinor: amount, OccurredAt: integrationNow,
	}
}

func postUsage(t *testing.T, service *commerce.Service, amount int64, key string) {
	t.Helper()
	_, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-pg-1", Currency: "USD", Kind: commerce.LedgerUsage,
		AmountMinor: amount, IdempotencyKey: key, Reference: "usage",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func assertFrozenDebit(t *testing.T, service *commerce.Service) {
	t.Helper()
	_, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-pg-1", Currency: "USD", Kind: commerce.LedgerUsage,
		AmountMinor: -1, IdempotencyKey: "usage-frozen", Reference: "usage",
	})
	if !errors.Is(err, commerce.ErrWalletFrozen) {
		t.Fatalf("frozen wallet debit error = %v", err)
	}
}

func assertPaymentReconciliation(t *testing.T, store *Store) {
	t.Helper()
	report, err := store.ReconcilePayments(context.Background(), "tenant-pg-1")
	if err != nil || report.OrdersChecked != 1 || len(report.Issues) != 0 {
		t.Fatalf("payment reconciliation failed: %+v %v", report, err)
	}
	events, err := store.ListPaymentEvents(context.Background(), "pay-pg-1")
	if err != nil || len(events) != 3 || events[0].LedgerEntryID == "" ||
		events[1].LedgerEntryID == "" || events[2].LedgerEntryID == "" {
		t.Fatalf("payment event history incomplete: %+v %v", events, err)
	}
}

func TestPostgresOutboxClaimUsesCrossReplicaLease(t *testing.T) {
	store := integrationStore(t)
	service := integrationService(t, store)
	_, err := service.CreateTopUpOrder(context.Background(), commerce.CreateTopUpCommand{
		ID: "pay-lease", TenantID: "tenant-lease", Provider: "testpay",
		Currency: "USD", AmountMinor: 100, IdempotencyKey: "lease-order",
	})
	if err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	counts := make(chan int, 2)
	for _, owner := range []string{"relay-a", "relay-b"} {
		wait.Add(1)
		go func() {
			defer wait.Done()
			events, claimErr := store.ClaimOutbox(context.Background(), owner, integrationNow, time.Minute, 1)
			if claimErr != nil {
				counts <- -1
				return
			}
			counts <- len(events)
		}()
	}
	wait.Wait()
	close(counts)
	total := 0
	for count := range counts {
		if count < 0 {
			t.Fatal("concurrent outbox claim failed")
		}
		total += count
	}
	if total != 1 {
		t.Fatalf("cross-replica claim count = %d, want 1", total)
	}
}

func TestPostgresOutboxRetryDeadLetterAndReplay(t *testing.T) {
	store := integrationStore(t)
	service := integrationService(t, store)
	_, err := service.CreateTopUpOrder(context.Background(), commerce.CreateTopUpCommand{
		ID: "pay-dead", TenantID: "tenant-dead", Provider: "testpay",
		Currency: "USD", AmountMinor: 100, IdempotencyKey: "dead-order",
	})
	if err != nil {
		t.Fatal(err)
	}
	claimed, err := store.ClaimOutbox(context.Background(), "relay-a", integrationNow, time.Minute, 1)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim failed: %+v %v", claimed, err)
	}
	if err := store.FailOutbox(context.Background(), claimed[0].ID, "relay-a", "unavailable",
		integrationNow, integrationNow.Add(time.Minute), 1); err != nil {
		t.Fatal(err)
	}
	dead, err := store.ListDeadOutbox(context.Background(), 10)
	if err != nil || len(dead) != 1 || dead[0].Status != commerce.OutboxDead {
		t.Fatalf("dead letter missing: %+v %v", dead, err)
	}
	replayAt := integrationNow.Add(2 * time.Minute)
	if err := store.ReplayOutbox(context.Background(), dead[0].ID, replayAt); err != nil {
		t.Fatal(err)
	}
	replayed, err := store.ClaimOutbox(context.Background(), "relay-b", replayAt, time.Minute, 1)
	if err != nil || len(replayed) != 1 || replayed[0].Attempts != 1 {
		t.Fatalf("dead letter replay failed: %+v %v", replayed, err)
	}
}

func TestPostgresConcurrentPaymentReplayPostsOnce(t *testing.T) {
	store := integrationStore(t)
	service := integrationService(t, store)
	order := createConcurrentTopUp(t, store, service)
	event := paymentEvent(order, "capture-concurrent", commerce.PaymentCaptured, 500)
	runConcurrent(t, 24, func() error {
		_, _, _, err := service.ApplyPaymentEvent(context.Background(), event)
		return err
	})
	wallet, err := store.GetWallet(context.Background(), order.TenantID, order.Currency)
	if err != nil || wallet.BalanceMinor != 500 || wallet.Version != 1 {
		t.Fatalf("concurrent capture changed wallet more than once: %+v %v", wallet, err)
	}
	entries, err := store.ListLedgerEntries(context.Background(), order.TenantID, order.Currency, 100)
	if err != nil || len(entries) != 1 {
		t.Fatalf("concurrent capture wrote %d ledger entries: %v", len(entries), err)
	}
}

func createConcurrentTopUp(t *testing.T, store *Store, service *commerce.Service) *commerce.PaymentOrder {
	t.Helper()
	command := commerce.CreateTopUpCommand{
		ID: "pay-concurrent", TenantID: "tenant-concurrent", Provider: "testpay",
		ProviderOrderID: "provider-concurrent", Currency: "USD", AmountMinor: 500,
		IdempotencyKey: "checkout-concurrent",
	}
	runConcurrent(t, 24, func() error {
		_, err := service.CreateTopUpOrder(context.Background(), command)
		return err
	})
	orders, err := store.ListPaymentOrdersByTenant(context.Background(), command.TenantID)
	if err != nil || len(orders) != 1 {
		t.Fatalf("concurrent create wrote %d orders: %v", len(orders), err)
	}
	return orders[0]
}

func runConcurrent(t *testing.T, workers int, operation func() error) {
	t.Helper()
	errorsChannel := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			errorsChannel <- operation()
		}()
	}
	wait.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatal(err)
		}
	}
}
