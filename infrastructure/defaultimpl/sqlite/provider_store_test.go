package sqlite

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/domains/connections/provider"
)

func TestSQLiteProviderStore_CreateAndGet(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "provider.db") + "?_journal=WAL"
	store, err := NewProviderStore(dsn)
	if err != nil {
		t.Fatalf("NewProviderStore: %v", err)
	}

	p := &provider.Provider{
		ID:          "google-oidc",
		TenantID:    "tenant-1",
		Type:        provider.TypeOIDC,
		DisplayName: "Sign in with Google",
		Enabled:     true,
		Config:      map[string]string{"client_id": "google-client-id"},
	}

	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.Get(ctx, "google-oidc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DisplayName != "Sign in with Google" {
		t.Errorf("expected 'Sign in with Google', got %q", got.DisplayName)
	}
	if got.Config["client_id"] != "google-client-id" {
		t.Errorf("expected client_id 'google-client-id', got %q", got.Config["client_id"])
	}
}

func TestSQLiteProviderStore_CreateDuplicate(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "provider_dup.db") + "?_journal=WAL"
	store, err := NewProviderStore(dsn)
	if err != nil {
		t.Fatalf("NewProviderStore: %v", err)
	}

	_ = store.Create(ctx, &provider.Provider{
		ID: "dup", TenantID: "t", Type: provider.TypeOIDC, Enabled: true,
	})

	err = store.Create(ctx, &provider.Provider{
		ID: "dup", TenantID: "t", Type: provider.TypeOIDC, Enabled: true,
	})
	if err == nil {
		t.Error("expected error for duplicate provider")
	}
}

func TestSQLiteProviderStore_Update(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "provider_upd.db") + "?_journal=WAL"
	store, err := NewProviderStore(dsn)
	if err != nil {
		t.Fatalf("NewProviderStore: %v", err)
	}

	_ = store.Create(ctx, &provider.Provider{
		ID: "update-me", TenantID: "t", Type: provider.TypeOIDC,
		DisplayName: "Original", Enabled: true,
	})

	err = store.Update(ctx, &provider.Provider{
		ID: "update-me", TenantID: "t", Type: provider.TypeSAML,
		DisplayName: "Updated", Enabled: false,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := store.Get(ctx, "update-me")
	if got.DisplayName != "Updated" {
		t.Errorf("expected 'Updated', got %q", got.DisplayName)
	}
	if got.Type != provider.TypeSAML {
		t.Errorf("expected TypeSAML, got %v", got.Type)
	}
	if got.Enabled {
		t.Error("expected Enabled=false")
	}
}

func TestSQLiteProviderStore_Delete(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "provider_del.db") + "?_journal=WAL"
	store, err := NewProviderStore(dsn)
	if err != nil {
		t.Fatalf("NewProviderStore: %v", err)
	}

	_ = store.Create(ctx, &provider.Provider{
		ID: "delete-me", TenantID: "t", Type: provider.TypeOIDC, Enabled: true,
	})

	if err := store.Delete(ctx, "delete-me"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err = store.Get(ctx, "delete-me")
	if err == nil {
		t.Error("expected error after delete")
	}
}

func TestSQLiteProviderStore_ListByTenant(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "provider_list.db") + "?_journal=WAL"
	store, err := NewProviderStore(dsn)
	if err != nil {
		t.Fatalf("NewProviderStore: %v", err)
	}

	for i := 0; i < 3; i++ {
		_ = store.Create(ctx, &provider.Provider{
			ID: "p-" + itoa(i), TenantID: "tenant-a", Type: provider.TypeOIDC, Enabled: true,
		})
	}
	_ = store.Create(ctx, &provider.Provider{
		ID: "other", TenantID: "tenant-b", Type: provider.TypeSAML, Enabled: true,
	})

	tenants, err := store.ListByTenant(ctx, "tenant-a")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(tenants) != 3 {
		t.Errorf("expected 3 providers for tenant-a, got %d", len(tenants))
	}
}

func TestSQLiteProviderStore_ListByIDs(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "provider_ids.db") + "?_journal=WAL"
	store, err := NewProviderStore(dsn)
	if err != nil {
		t.Fatalf("NewProviderStore: %v", err)
	}

	for i := 0; i < 5; i++ {
		_ = store.Create(ctx, &provider.Provider{
			ID: "pid-" + itoa(i), TenantID: "t", Type: provider.TypeOIDC, Enabled: true,
		})
	}

	result, err := store.ListByIDs(ctx, []string{"pid-0", "pid-2", "pid-4", "nonexistent"})
	if err != nil {
		t.Fatalf("ListByIDs: %v", err)
	}
	if len(result) != 3 {
		t.Errorf("expected 3 results, got %d", len(result))
	}
}

func TestSQLiteProviderStore_GetNotFound(t *testing.T) {
	ctx := context.Background()
	dsn := "file:" + filepath.Join(t.TempDir(), "provider_nf.db") + "?_journal=WAL"
	store, err := NewProviderStore(dsn)
	if err != nil {
		t.Fatalf("NewProviderStore: %v", err)
	}

	_, err = store.Get(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent provider")
	}
}

