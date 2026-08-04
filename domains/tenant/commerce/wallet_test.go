package commerce_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
)

func TestWalletLedgerBalanceAndIdempotency(t *testing.T) {
	service, store := newTestService(t)
	credit := commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 10_000, IdempotencyKey: "payment:1", Reference: "provider-charge-1",
	}
	first, wallet, err := service.PostLedgerEntry(context.Background(), credit)
	if err != nil || wallet.BalanceMinor != 10_000 || first.BalanceAfter != 10_000 {
		t.Fatalf("credit failed: entry=%+v wallet=%+v err=%v", first, wallet, err)
	}
	replay, wallet, err := service.PostLedgerEntry(context.Background(), credit)
	if err != nil || replay.ID != first.ID || wallet.BalanceMinor != 10_000 {
		t.Fatalf("idempotent replay changed balance: %+v %+v %v", replay, wallet, err)
	}

	_, wallet, err = service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerUsage,
		AmountMinor: -2_500, IdempotencyKey: "usage:1", Reference: "invoice-line-1",
	})
	if err != nil || wallet.BalanceMinor != 7_500 || wallet.Version != 2 {
		t.Fatalf("debit failed: %+v %v", wallet, err)
	}

	entries, err := store.ListLedgerEntries(context.Background(), "tenant-1", "USD", 10)
	if err != nil || len(entries) != 2 || entries[0].Kind != commerce.LedgerUsage {
		t.Fatalf("unexpected ledger: %+v %v", entries, err)
	}
}

func TestWalletRejectsConflictAndInsufficientFundsAtomically(t *testing.T) {
	service, store := newTestService(t)
	base := commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 1_000, IdempotencyKey: "payment:1", Reference: "charge-1",
	}
	if _, _, err := service.PostLedgerEntry(context.Background(), base); err != nil {
		t.Fatal(err)
	}
	conflict := base
	conflict.AmountMinor = 2_000
	if _, _, err := service.PostLedgerEntry(context.Background(), conflict); !errors.Is(err, commerce.ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
	_, _, err := service.PostLedgerEntry(context.Background(), commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerUsage,
		AmountMinor: -1_001, IdempotencyKey: "usage:too-large",
	})
	if !errors.Is(err, commerce.ErrInsufficientFunds) {
		t.Fatalf("expected insufficient funds, got %v", err)
	}
	wallet, _ := store.GetWallet(context.Background(), "tenant-1", "USD")
	entries, _ := store.ListLedgerEntries(context.Background(), "tenant-1", "USD", 10)
	if wallet.BalanceMinor != 1_000 || len(entries) != 1 {
		t.Fatalf("rejected mutations changed wallet: %+v entries=%d", wallet, len(entries))
	}
}

func TestConcurrentIdempotentTopUpPostsOnce(t *testing.T) {
	service, store := newTestService(t)
	command := commerce.PostLedgerCommand{
		TenantID: "tenant-1", Currency: "USD", Kind: commerce.LedgerTopUp,
		AmountMinor: 5_000, IdempotencyKey: "provider:event-1", Reference: "charge-1",
	}
	const workers = 32
	var wait sync.WaitGroup
	errorsCh := make(chan error, workers)
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, _, err := service.PostLedgerEntry(context.Background(), command)
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
	if wallet.BalanceMinor != 5_000 || wallet.Version != 1 || len(entries) != 1 {
		t.Fatalf("concurrent replay duplicated money: %+v entries=%d", wallet, len(entries))
	}
}
