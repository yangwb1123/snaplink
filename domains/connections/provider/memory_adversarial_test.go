package provider

import (
	"context"
	"sync"
	"testing"
)

func TestMemoryProviderStore_Adversarial_ConcurrentCreate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			p := &Provider{
				ID:          "p-" + itoa(n),
				TenantID:    "tenant-1",
				DisplayName: "Provider " + itoa(n),
				Type:        TypeOIDC,
				Enabled:     true,
			}
			_ = store.Create(ctx, p)
		}(i)
	}
	wg.Wait()

	all, err := store.ListByTenant(ctx, "tenant-1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(all) != goroutines {
		t.Errorf("expected %d providers, got %d", goroutines, len(all))
	}
}

func TestMemoryProviderStore_Adversarial_ConcurrentUpdate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	p := &Provider{
		ID:          "update-me",
		TenantID:    "tenant-2",
		DisplayName: "Original",
		Type:        TypeOIDC,
		Enabled:     true,
	}
	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	const goroutines = 10
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for range goroutines {
		go func() {
			defer wg.Done()
			_ = store.Update(ctx, p)
		}()
	}
	wg.Wait()

	got, err := store.Get(ctx, "update-me")
	if err != nil {
		t.Fatalf("Get after concurrent updates: %v", err)
	}
	if got == nil {
		t.Fatal("provider should still exist")
	}
}

func TestMemoryProviderStore_Adversarial_RaceDeleteDuringList(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	for i := range 10 {
		_ = store.Create(ctx, &Provider{
			ID: "p-" + itoa(i), TenantID: "tenant-race", Type: TypeOIDC, Enabled: true,
		})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for range 20 {
			_, _ = store.ListByTenant(ctx, "tenant-race")
		}
	}()

	go func() {
		defer wg.Done()
		for i := range 10 {
			_ = store.Delete(ctx, "p-"+itoa(i))
		}
	}()

	wg.Wait()

	remaining, _ := store.ListByTenant(ctx, "tenant-race")
	t.Logf("remaining providers after race: %d", len(remaining))
}

func TestMemoryProviderStore_Adversarial_GetNonExistent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	_, err := store.Get(ctx, "no-id")
	if err != ErrNoSuchProvider {
		t.Errorf("expected ErrNoSuchProvider, got %v", err)
	}
}

func TestMemoryProviderStore_Adversarial_DeleteNonExistent(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if err := store.Delete(ctx, "no-id"); err != nil {
		t.Errorf("Delete non-existent should succeed, got: %v", err)
	}
}

func TestMemoryProviderStore_Adversarial_ConcurrentDuplicateCreate(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	var wg sync.WaitGroup
	wg.Add(5)

	for range 5 {
		go func() {
			defer wg.Done()
			_ = store.Create(ctx, &Provider{
				ID: "dup", TenantID: "t", Type: TypeOIDC, Enabled: true,
			})
		}()
	}
	wg.Wait()

	// Only the first should have succeeded
	all, _ := store.ListByTenant(ctx, "t")
	if len(all) != 1 {
		t.Errorf("expected 1 provider after duplicate creates, got %d", len(all))
	}
}

func TestMemoryProviderStore_Adversarial_ListByIDs(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	for i := range 5 {
		_ = store.Create(ctx, &Provider{
			ID: "p-" + itoa(i), TenantID: "t", Type: TypeOIDC, Enabled: true,
		})
	}

	result, err := store.ListByIDs(ctx, []string{"p-0", "p-2", "p-4", "nonexistent"})
	if err != nil {
		t.Fatalf("ListByIDs: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 results, got %d", len(result))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
