package provider

import (
	"context"
	"testing"
)

func TestMemoryStore_CreateAndGet(t *testing.T) {
	s := NewMemoryStore()
	p := &Provider{
		ID:          "google_oidc",
		Type:        TypeOIDC,
		DisplayName: "Google",
		Enabled:     true,
		Config:      map[string]string{"issuer": "https://accounts.google.com"},
	}

	if err := s.Create(context.Background(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := s.Get(context.Background(), "google_oidc")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DisplayName != "Google" {
		t.Errorf("DisplayName = %q, want %q", got.DisplayName, "Google")
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt is zero, should be set")
	}
}

func TestMemoryStore_CreateDuplicate(t *testing.T) {
	s := NewMemoryStore()
	p := &Provider{ID: "dup", Type: TypeOIDC, DisplayName: "First"}
	if err := s.Create(context.Background(), p); err != nil {
		t.Fatalf("first Create: %v", err)
	}
	if err := s.Create(context.Background(), p); err != ErrProviderExists {
		t.Errorf("second Create: got %v, want ErrProviderExists", err)
	}
}

func TestMemoryStore_GetNotFound(t *testing.T) {
	s := NewMemoryStore()
	_, err := s.Get(context.Background(), "nonexistent")
	if err != ErrNoSuchProvider {
		t.Errorf("Get: got %v, want ErrNoSuchProvider", err)
	}
}

func TestMemoryStore_Update(t *testing.T) {
	s := NewMemoryStore()
	p := &Provider{ID: "github", Type: TypeOIDC, DisplayName: "GitHub"}
	if err := s.Create(context.Background(), p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	p.DisplayName = "GitHub (Updated)"
	if err := s.Update(context.Background(), p); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, _ := s.Get(context.Background(), "github")
	if got.DisplayName != "GitHub (Updated)" {
		t.Errorf("after update DisplayName = %q, want %q", got.DisplayName, "GitHub (Updated)")
	}
}

func TestMemoryStore_UpdateNotFound(t *testing.T) {
	s := NewMemoryStore()
	err := s.Update(context.Background(), &Provider{ID: "missing", Type: TypeOIDC})
	if err != ErrNoSuchProvider {
		t.Errorf("Update: got %v, want ErrNoSuchProvider", err)
	}
}

func TestMemoryStore_Delete(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Create(context.Background(), &Provider{ID: "del", Type: TypeOIDC})
	if err := s.Delete(context.Background(), "del"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := s.Get(context.Background(), "del")
	if err != ErrNoSuchProvider {
		t.Error("expected ErrNoSuchProvider after delete")
	}
}

func TestMemoryStore_DeleteIdempotent(t *testing.T) {
	s := NewMemoryStore()
	if err := s.Delete(context.Background(), "never_existed"); err != nil {
		t.Errorf("delete absent: got %v, want nil", err)
	}
}

func TestMemoryStore_ListByTenant(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Create(context.Background(), &Provider{ID: "global", Type: TypeOIDC, DisplayName: "Global"})
	_ = s.Create(context.Background(), &Provider{ID: "t1_a", Type: TypeOIDC, DisplayName: "T1-A", TenantID: "tenant1"})
	_ = s.Create(context.Background(), &Provider{ID: "t1_b", Type: TypeOIDC, DisplayName: "T1-B", TenantID: "tenant1"})
	_ = s.Create(context.Background(), &Provider{ID: "t2_a", Type: TypeOIDC, DisplayName: "T2-A", TenantID: "tenant2"})

	got, err := s.ListByTenant(context.Background(), "tenant1")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 providers for tenant1, got %d", len(got))
	}
}

func TestMemoryStore_ListByTenant_Empty(t *testing.T) {
	s := NewMemoryStore()
	got, err := s.ListByTenant(context.Background(), "empty_tenant")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty list, got %d", len(got))
	}
}

func TestMemoryStore_ListGlobal(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Create(context.Background(), &Provider{ID: "g1", Type: TypeOIDC, DisplayName: "G1"})
	_ = s.Create(context.Background(), &Provider{ID: "g2", Type: TypeOIDC, DisplayName: "G2"})
	_ = s.Create(context.Background(), &Provider{ID: "t1", Type: TypeOIDC, TenantID: "t1"})

	got, err := s.ListGlobal(context.Background())
	if err != nil {
		t.Fatalf("ListGlobal: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 global providers, got %d", len(got))
	}
}

func TestMemoryStore_ListByIDs(t *testing.T) {
	s := NewMemoryStore()
	_ = s.Create(context.Background(), &Provider{ID: "a", Type: TypeOIDC})
	_ = s.Create(context.Background(), &Provider{ID: "b", Type: TypeOIDC})
	_ = s.Create(context.Background(), &Provider{ID: "c", Type: TypeOIDC})

	got, err := s.ListByIDs(context.Background(), []string{"a", "c", "nonexistent"})
	if err != nil {
		t.Fatalf("ListByIDs: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("expected 2 providers, got %d", len(got))
	}
}

func TestMemoryStore_CloneIsIndependent(t *testing.T) {
	s := NewMemoryStore()
	p := &Provider{ID: "clone_test", Type: TypeOIDC, Config: map[string]string{"key": "val"}}
	_ = s.Create(context.Background(), p)

	got, _ := s.Get(context.Background(), "clone_test")
	got.DisplayName = "modified"
	got.Config["key"] = "hacked"

	got2, _ := s.Get(context.Background(), "clone_test")
	if got2.DisplayName == "modified" {
		t.Error("Clone did not protect original from mutation")
	}
	if got2.Config["key"] == "hacked" {
		t.Error("Config map was shared, not deep-copied")
	}
}

func TestMemoryStore_Concurrency(t *testing.T) {
	s := NewMemoryStore()
	done := make(chan struct{}, 2)
	go func() {
		for i := 0; i < 100; i++ {
			_ = s.Create(context.Background(), &Provider{ID: "p", Type: TypeOIDC})
			_, _ = s.Get(context.Background(), "p")
			_ = s.Delete(context.Background(), "p")
		}
		done <- struct{}{}
	}()
	go func() {
		for i := 0; i < 100; i++ {
			_, _ = s.ListByTenant(context.Background(), "t")
			_, _ = s.ListGlobal(context.Background())
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}
