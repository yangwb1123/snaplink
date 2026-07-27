package memorystorecredential

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core/corecredential"
)

func TestMemoryCredentialStatusStore_UpsertGet(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStatusStore()

	meta := corecredential.CredentialMeta{
		ID:        "webhook_hmac/v1",
		Type:      corecredential.CredentialTypeWebhookHMAC,
		Version:   1,
		Status:    corecredential.CredentialStatusActive,
		CreatedAt: time.Now(),
		Algorithm: "HMAC-SHA256",
	}
	if err := store.Upsert(ctx, meta); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, err := store.Get(ctx, meta.Type, meta.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != meta {
		t.Fatalf("Get returned %+v, want %+v", got, meta)
	}
}

func TestMemoryCredentialStatusStore_GetUnknown(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStatusStore()

	if _, err := store.Get(ctx, corecredential.CredentialTypeWebhookHMAC, "missing"); !errors.Is(err, corecredential.ErrCredentialNotFound) {
		t.Fatalf("Get(unknown) = %v, want ErrCredentialNotFound", err)
	}
}

func TestMemoryCredentialStatusStore_UpsertReplaces(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStatusStore()

	base := corecredential.CredentialMeta{
		ID: "webhook_hmac/v1", Type: corecredential.CredentialTypeWebhookHMAC,
		Version: 1, Status: corecredential.CredentialStatusActive,
	}
	if err := store.Upsert(ctx, base); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	base.Status = corecredential.CredentialStatusRetiring
	if err := store.Upsert(ctx, base); err != nil {
		t.Fatalf("Upsert (replace): %v", err)
	}
	got, err := store.Get(ctx, base.Type, base.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != corecredential.CredentialStatusRetiring {
		t.Fatalf("Status = %q, want retiring (Upsert should replace, not merge)", got.Status)
	}
}

func TestMemoryCredentialStatusStore_ListByTypeOrdersByVersion(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStatusStore()

	// Insert out of order to prove ListByType sorts rather than returning
	// map iteration order.
	v2 := corecredential.CredentialMeta{ID: "webhook_hmac/v2", Type: corecredential.CredentialTypeWebhookHMAC, Version: 2}
	v1 := corecredential.CredentialMeta{ID: "webhook_hmac/v1", Type: corecredential.CredentialTypeWebhookHMAC, Version: 1}
	v3 := corecredential.CredentialMeta{ID: "webhook_hmac/v3", Type: corecredential.CredentialTypeWebhookHMAC, Version: 3}
	for _, m := range []corecredential.CredentialMeta{v2, v1, v3} {
		if err := store.Upsert(ctx, m); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	list, err := store.ListByType(ctx, corecredential.CredentialTypeWebhookHMAC)
	if err != nil {
		t.Fatalf("ListByType: %v", err)
	}
	if len(list) != 3 {
		t.Fatalf("len(list) = %d, want 3", len(list))
	}
	for i, want := range []int{1, 2, 3} {
		if list[i].Version != want {
			t.Fatalf("list[%d].Version = %d, want %d (ascending order)", i, list[i].Version, want)
		}
	}
}

func TestMemoryCredentialStatusStore_ListByTypeUnknownReturnsEmpty(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStatusStore()

	list, err := store.ListByType(ctx, corecredential.CredentialTypeWebhookHMAC)
	if err != nil {
		t.Fatalf("ListByType: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("len(list) = %d, want 0 for an untracked type", len(list))
	}
}

func TestMemoryCredentialStatusStore_UpdateStatus(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStatusStore()

	meta := corecredential.CredentialMeta{ID: "webhook_hmac/v1", Type: corecredential.CredentialTypeWebhookHMAC, Version: 1, Status: corecredential.CredentialStatusActive}
	if err := store.Upsert(ctx, meta); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if err := store.UpdateStatus(ctx, meta.Type, meta.ID, corecredential.CredentialStatusRetired); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	got, err := store.Get(ctx, meta.Type, meta.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != corecredential.CredentialStatusRetired {
		t.Fatalf("Status = %q, want retired", got.Status)
	}
}

func TestMemoryCredentialStatusStore_UpdateStatusUnknown(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStatusStore()

	err := store.UpdateStatus(ctx, corecredential.CredentialTypeWebhookHMAC, "missing", corecredential.CredentialStatusRetired)
	if !errors.Is(err, corecredential.ErrCredentialNotFound) {
		t.Fatalf("UpdateStatus(unknown) = %v, want ErrCredentialNotFound", err)
	}
}
