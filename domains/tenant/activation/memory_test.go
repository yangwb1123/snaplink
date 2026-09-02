package activation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestMemoryStorePrepareClaimAndCurrent(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(WithClock(func() time.Time { return now }))
	if err := store.AddCode(context.Background(), Code{
		ID: "code-1", ProductID: "console", TenantID: "acme", Key: "paid-key",
	}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	if stored := store.codes["code-1"].code; stored.Key != "" || stored.InvitationCode != "" {
		store.mu.Unlock()
		t.Fatal("activation store retained a plaintext credential")
	}
	store.mu.Unlock()
	prepared, err := store.Prepare(context.Background(), PrepareInput{
		ClientID: "client", ProductID: "console", LicenseKey: "paid-key", TenantHint: "acme",
	})
	if err != nil || prepared.Ticket == "" {
		t.Fatalf("Prepare() = %#v, %v", prepared, err)
	}
	claimed, err := store.Claim(context.Background(), ClaimInput{
		Ticket: prepared.Ticket, ClientID: "client", ProductID: "console", Subject: "user-1",
	})
	if err != nil || claimed.TenantID != "acme" {
		t.Fatalf("Claim() = %#v, %v", claimed, err)
	}
	current, err := store.Current(context.Background(), CurrentInput{
		ClientID: "client", ProductID: "console", Subject: "user-1",
	})
	if err != nil || current.TenantID != "acme" {
		t.Fatalf("Current() = %#v, %v", current, err)
	}
	if _, err := store.Claim(context.Background(), ClaimInput{
		Ticket: prepared.Ticket, ClientID: "client", ProductID: "console", Subject: "user-1",
	}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("replayed ticket error = %v", err)
	}
}

func TestMemoryStoreSweepsExpiredTicketsBeforePrepare(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(WithClock(func() time.Time { return now }))
	if err := store.AddCode(context.Background(), Code{
		ID: "code-1", ProductID: "console", TenantID: "acme", Key: "paid-key",
	}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.tickets["expired"] = memoryTicket{expiresAt: now.Add(-time.Nanosecond)}
	store.tickets["boundary"] = memoryTicket{expiresAt: now}
	store.tickets["live"] = memoryTicket{expiresAt: now.Add(time.Nanosecond)}
	store.lastTicketSweep.Store(0)
	store.mu.Unlock()

	prepared, err := store.Prepare(context.Background(), PrepareInput{
		ClientID: "client", ProductID: "console", LicenseKey: "paid-key",
	})
	if err != nil || prepared.Ticket == "" {
		t.Fatalf("Prepare() = %#v, %v", prepared, err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if _, ok := store.tickets["expired"]; ok {
		t.Error("expired ticket remains")
	}
	for _, key := range []string{"boundary", "live", digest(prepared.Ticket)} {
		if _, ok := store.tickets[key]; !ok {
			t.Errorf("ticket %q missing after sweep", key)
		}
	}
	if _, ok := store.codes["code-1"]; !ok {
		t.Error("provisioned code was removed by ticket sweep")
	}
}

func TestMemoryStoreClaimAtTicketExpiryRemainsInvalid(t *testing.T) {
	now := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore(WithClock(func() time.Time { return now }))
	if err := store.AddCode(context.Background(), Code{
		ID: "code-1", ProductID: "console", TenantID: "acme", Key: "paid-key",
	}); err != nil {
		t.Fatal(err)
	}
	store.mu.Lock()
	store.tickets[digest("boundary-ticket")] = memoryTicket{
		codeID: "code-1", clientID: "client", productID: "console", expiresAt: now,
	}
	store.mu.Unlock()
	if _, err := store.Claim(context.Background(), ClaimInput{
		Ticket: "boundary-ticket", ClientID: "client", ProductID: "console", Subject: "user-1",
	}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("boundary claim error = %v", err)
	}
	store.mu.Lock()
	_, retained := store.tickets[digest("boundary-ticket")]
	store.mu.Unlock()
	if retained {
		t.Error("invalid boundary ticket was not consumed")
	}
}

func TestMemoryStoreConcurrentPrepareClaim(t *testing.T) {
	store := NewMemoryStore()
	if err := store.AddCode(context.Background(), Code{
		ID: "code-1", ProductID: "console", TenantID: "acme", Key: "paid-key", MaxClaims: 64,
	}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prepared, err := store.Prepare(context.Background(), PrepareInput{
				ClientID: "client", ProductID: "console", LicenseKey: "paid-key",
			})
			if err != nil {
				errs <- fmt.Errorf("prepare %d: %w", i, err)
				return
			}
			if _, err := store.Claim(context.Background(), ClaimInput{
				Ticket: prepared.Ticket, ClientID: "client", ProductID: "console",
				Subject: fmt.Sprintf("user-%d", i),
			}); err != nil {
				errs <- fmt.Errorf("claim %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestMemoryStoreRejectsUnknownAndSecondClaim(t *testing.T) {
	store := NewMemoryStore()
	if err := store.AddCode(context.Background(), Code{
		ID: "code-1", ProductID: "console", TenantID: "acme", Key: "paid-key",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Prepare(context.Background(), PrepareInput{
		ClientID: "client", ProductID: "console", LicenseKey: "wrong",
	}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("unknown key error = %v", err)
	}
	first, err := store.Prepare(context.Background(), PrepareInput{
		ClientID: "client", ProductID: "console", LicenseKey: "paid-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Claim(context.Background(), ClaimInput{
		Ticket: first.Ticket, ClientID: "client", ProductID: "console", Subject: "user-1",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Prepare(context.Background(), PrepareInput{
		ClientID: "client", ProductID: "console", LicenseKey: "paid-key",
	}); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("second claim preparation error = %v", err)
	}
}
