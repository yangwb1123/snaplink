package commerce_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func createTopUp(t *testing.T, service *commerce.Service, amount int64) *commerce.PaymentOrder {
	t.Helper()
	order, err := service.CreateTopUpOrder(context.Background(), commerce.CreateTopUpCommand{
		TenantID: "tenant-1", Provider: "provider-a", ProviderOrderID: "provider-order-1",
		Currency: "USD", AmountMinor: amount, IdempotencyKey: "checkout-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return order
}

func paymentEvent(id, orderID string, eventType commerce.PaymentEventType, amount int64) *commerce.PaymentEvent {
	return &commerce.PaymentEvent{
		ID: id, Provider: "provider-a", ProviderOrderID: "provider-order-1", OrderID: orderID,
		Type: eventType, Currency: "USD", AmountMinor: amount, OccurredAt: testNow,
	}
}

func TestTopUpOrderAndCapturedEventAreIdempotent(t *testing.T) {
	service, store := newTestService(t)
	order := createTopUp(t, service, 10_000)
	replayed := createTopUp(t, service, 10_000)
	if replayed.ID != order.ID {
		t.Fatalf("order idempotency created a duplicate: %q != %q", replayed.ID, order.ID)
	}

	applied, entry, wallet, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("event-1", order.ID, commerce.PaymentCaptured, 10_000),
	)
	if err != nil || applied.Status != commerce.PaymentSucceeded || entry.AmountMinor != 10_000 || wallet.BalanceMinor != 10_000 {
		t.Fatalf("capture failed: order=%+v entry=%+v wallet=%+v err=%v", applied, entry, wallet, err)
	}
	replayOrder, replayEntry, replayWallet, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("event-1", order.ID, commerce.PaymentCaptured, 10_000),
	)
	if err != nil || replayOrder.Revision != applied.Revision || replayEntry != nil || replayWallet.BalanceMinor != 10_000 {
		t.Fatalf("event replay changed money: %+v %+v %+v %v", replayOrder, replayEntry, replayWallet, err)
	}
	entries, _ := store.ListLedgerEntries(context.Background(), "tenant-1", "USD", 10)
	if len(entries) != 1 {
		t.Fatalf("capture replay wrote %d entries", len(entries))
	}
}

func TestPaymentEventConflictAndStateConflict(t *testing.T) {
	service, _ := newTestService(t)
	order := createTopUp(t, service, 1_000)
	if _, _, _, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("event-1", order.ID, commerce.PaymentCaptured, 1_000),
	); err != nil {
		t.Fatal(err)
	}
	changed := paymentEvent("event-1", order.ID, commerce.PaymentCaptured, 999)
	if _, _, _, err := service.ApplyPaymentEvent(context.Background(), changed); !errors.Is(err, commerce.ErrIdempotencyConflict) {
		t.Fatalf("same provider event with changed content should conflict: %v", err)
	}
	if _, _, _, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("event-2", order.ID, commerce.PaymentCaptured, 1_000),
	); !errors.Is(err, commerce.ErrPaymentStateConflict) {
		t.Fatalf("second capture should conflict: %v", err)
	}
}

func TestRefundFreezesNegativeWalletAndReconciles(t *testing.T) {
	service, store := newTestService(t)
	order := createTopUp(t, service, 1_000)
	if _, _, _, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("capture", order.ID, commerce.PaymentCaptured, 1_000),
	); err != nil {
		t.Fatal(err)
	}
	if _, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerUsage,
		AmountMinor: -900, IdempotencyKey: "usage-1", Reference: "invoice-1",
	}); err != nil {
		t.Fatal(err)
	}

	partial, _, wallet, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("refund-1", order.ID, commerce.PaymentRefundedEvent, 500),
	)
	if err != nil || partial.Status != commerce.PaymentPartiallyRefunded ||
		wallet.BalanceMinor != -400 || wallet.Status != commerce.WalletFrozen {
		t.Fatalf("refund did not freeze negative wallet: %+v %+v %v", partial, wallet, err)
	}
	if _, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerUsage,
		AmountMinor: -1, IdempotencyKey: "usage-2", Reference: "invoice-2",
	}); !errors.Is(err, commerce.ErrWalletFrozen) {
		t.Fatalf("frozen wallet allowed usage: %v", err)
	}
	if _, _, _, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("refund-2", order.ID, commerce.PaymentRefundedEvent, 500),
	); err != nil {
		t.Fatal(err)
	}
	report, err := store.ReconcilePayments(context.Background(), "tenant-1")
	if err != nil || report.OrdersChecked != 1 || len(report.Issues) != 0 {
		t.Fatalf("unexpected reconciliation: %+v %v", report, err)
	}
}

func TestChargebackReversalRestoresWalletAndOrder(t *testing.T) {
	service, store := newTestService(t)
	order := createTopUp(t, service, 1_000)
	if _, _, _, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("capture", order.ID, commerce.PaymentCaptured, 1_000),
	); err != nil {
		t.Fatal(err)
	}
	chargedBack, _, frozen, err := service.ApplyPaymentEvent(
		context.Background(), paymentEvent("chargeback", order.ID, commerce.PaymentChargeback, 1_000),
	)
	if err != nil || chargedBack.Status != commerce.PaymentRefunded || frozen.Status != commerce.WalletFrozen {
		t.Fatalf("chargeback state = %+v wallet=%+v err=%v", chargedBack, frozen, err)
	}
	restored, entry, wallet, err := service.ApplyPaymentEvent(context.Background(),
		paymentEvent("chargeback-reversed", order.ID, commerce.PaymentChargebackReversed, 1_000))
	if err != nil || restored.Status != commerce.PaymentSucceeded || restored.RefundedMinor != 0 ||
		entry.Kind != commerce.LedgerChargebackReversal || entry.AmountMinor != 1_000 ||
		wallet.BalanceMinor != 1_000 || wallet.Status != commerce.WalletActive {
		t.Fatalf("reversal state = %+v entry=%+v wallet=%+v err=%v", restored, entry, wallet, err)
	}
	report, err := store.ReconcilePayments(context.Background(), "tenant-1")
	if err != nil || len(report.Issues) != 0 {
		t.Fatalf("reversal reconciliation = %+v err=%v", report, err)
	}
}

func TestConcurrentProviderEventPostsOneLedgerEntry(t *testing.T) {
	service, store := newTestService(t)
	order := createTopUp(t, service, 2_000)
	const workers = 24
	var wait sync.WaitGroup
	errorsCh := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, _, err := service.ApplyPaymentEvent(
				context.Background(), paymentEvent("capture", order.ID, commerce.PaymentCaptured, 2_000),
			)
			errorsCh <- err
		}()
	}
	wait.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	wallet, _ := store.GetWallet(context.Background(), "tenant-1", "USD")
	entries, _ := store.ListLedgerEntries(context.Background(), "tenant-1", "USD", workers)
	if wallet.BalanceMinor != 2_000 || wallet.Version != 1 || len(entries) != 1 {
		t.Fatalf("concurrent webhook duplicated money: %+v entries=%d", wallet, len(entries))
	}
}
