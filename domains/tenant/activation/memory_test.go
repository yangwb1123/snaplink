package activation

import (
	"context"
	"errors"
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
