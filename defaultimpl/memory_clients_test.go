package defaultimpl_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func TestClientTenantID_RoundTripThroughStore(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	in := &sso.Client{ID: "web-app", TenantID: "t-acme", Active: true}
	if err := store.Add(ctx, in); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := store.Get(ctx, "web-app")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.TenantID != "t-acme" {
		t.Errorf("TenantID=%q want t-acme", got.TenantID)
	}
}

func TestClientTenantID_EmptyByDefault(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	_ = store.Add(ctx, &sso.Client{ID: "platform-admin", Active: true}) // no TenantID
	got, _ := store.Get(ctx, "platform-admin")
	if got.TenantID != "" {
		t.Errorf("TenantID=%q want empty", got.TenantID)
	}
}

func TestListByTenant_FiltersCorrectly(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	_ = store.Add(ctx, &sso.Client{ID: "acme-portal", TenantID: "t-acme"})
	_ = store.Add(ctx, &sso.Client{ID: "acme-admin", TenantID: "t-acme"})
	_ = store.Add(ctx, &sso.Client{ID: "beta-portal", TenantID: "t-beta"})
	_ = store.Add(ctx, &sso.Client{ID: "platform", TenantID: ""})

	acmeOnly, err := store.ListByTenant(ctx, "t-acme")
	if err != nil {
		t.Fatalf("ListByTenant: %v", err)
	}
	if len(acmeOnly) != 2 {
		t.Errorf("acme len=%d, want 2: %+v", len(acmeOnly), acmeOnly)
	}
	for _, c := range acmeOnly {
		if c.TenantID != "t-acme" {
			t.Errorf("leaked client from other tenant: %+v", c)
		}
	}
}

func TestListByTenant_EmptyTenantIDReturnsNoTenantBucket(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	_ = store.Add(ctx, &sso.Client{ID: "acme-portal", TenantID: "t-acme"})
	_ = store.Add(ctx, &sso.Client{ID: "platform-1", TenantID: ""})
	_ = store.Add(ctx, &sso.Client{ID: "platform-2", TenantID: ""})

	platformOnly, _ := store.ListByTenant(ctx, "")
	if len(platformOnly) != 2 {
		t.Errorf("platform-bucket len=%d, want 2: %+v", len(platformOnly), platformOnly)
	}
}

func TestListByTenant_UnknownTenantReturnsEmpty(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	out, err := store.ListByTenant(context.Background(), "ghost-tenant")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %+v, want empty", out)
	}
}
