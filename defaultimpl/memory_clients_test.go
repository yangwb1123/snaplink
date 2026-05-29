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

func TestMemoryStats_OrderIndependentHash(t *testing.T) {
	ctx := context.Background()
	// Two stores with the SAME logical client set added in DIFFERENT
	// orders must produce the same fingerprint — map iteration order
	// must not leak into the digest.
	a := defaultimpl.NewMemoryClientStore()
	_ = a.Add(ctx, &sso.Client{ID: "c-1", AllowedScopes: []string{"read", "write"}})
	_ = a.Add(ctx, &sso.Client{ID: "c-2", AllowedScopes: []string{"profile"}})
	_ = a.Add(ctx, &sso.Client{ID: "c-3", RequirePAR: true})

	b := defaultimpl.NewMemoryClientStore()
	_ = b.Add(ctx, &sso.Client{ID: "c-3", RequirePAR: true})
	_ = b.Add(ctx, &sso.Client{ID: "c-2", AllowedScopes: []string{"profile"}})
	// Scope order within a client must also be irrelevant (set membership).
	_ = b.Add(ctx, &sso.Client{ID: "c-1", AllowedScopes: []string{"write", "read"}})

	countA, hashA, err := a.Stats(ctx)
	if err != nil {
		t.Fatalf("a.Stats: %v", err)
	}
	countB, hashB, err := b.Stats(ctx)
	if err != nil {
		t.Fatalf("b.Stats: %v", err)
	}
	if countA != 3 || countB != 3 {
		t.Errorf("count: a=%d b=%d want 3", countA, countB)
	}
	if hashA != hashB {
		t.Errorf("hash differs across insert order: a=%s b=%s", hashA, hashB)
	}
}

func TestMemoryStats_ScopeChangeFlipsHash(t *testing.T) {
	ctx := context.Background()
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(ctx, &sso.Client{ID: "c-1", AllowedScopes: []string{"read"}})
	_, before, _ := store.Stats(ctx)

	// Adding a scope changes the discovery doc -> must flip the hash.
	_ = store.Update(ctx, &sso.Client{ID: "c-1", AllowedScopes: []string{"read", "admin"}})
	_, after, _ := store.Stats(ctx)
	if before == after {
		t.Errorf("scope change did not flip hash: %s", after)
	}

	// A change that does NOT affect the discovery doc (secret rotation)
	// must NOT flip the hash.
	stable := after
	if _, err := store.RotateSecret(ctx, "c-1"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	_, afterRotate, _ := store.Stats(ctx)
	if afterRotate != stable {
		t.Errorf("secret rotation flipped discovery hash: %s -> %s", stable, afterRotate)
	}
}

func TestMemoryStats_NewClientFlipsHash(t *testing.T) {
	ctx := context.Background()
	store := defaultimpl.NewMemoryClientStore()
	_ = store.Add(ctx, &sso.Client{ID: "c-1", AllowedScopes: []string{"read"}})
	c1, h1, _ := store.Stats(ctx)

	_ = store.Add(ctx, &sso.Client{ID: "c-2", AllowedScopes: []string{"read"}})
	c2, h2, _ := store.Stats(ctx)

	if c1 != 1 || c2 != 2 {
		t.Errorf("count: c1=%d c2=%d want 1,2", c1, c2)
	}
	if h1 == h2 {
		t.Errorf("adding a client did not flip hash: %s", h2)
	}

	// Deleting back to the original set restores the original hash —
	// the digest is a pure function of the discovery-relevant content.
	_ = store.Delete(ctx, "c-2")
	c3, h3, _ := store.Stats(ctx)
	if c3 != 1 || h3 != h1 {
		t.Errorf("delete did not restore original fingerprint: count=%d hash=%s want 1,%s", c3, h3, h1)
	}
}

func TestMemoryStats_EmptyStoreStable(t *testing.T) {
	ctx := context.Background()
	a := defaultimpl.NewMemoryClientStore()
	b := defaultimpl.NewMemoryClientStore()
	ca, ha, err := a.Stats(ctx)
	if err != nil {
		t.Fatalf("a.Stats: %v", err)
	}
	cb, hb, _ := b.Stats(ctx)
	if ca != 0 || cb != 0 {
		t.Errorf("empty count: a=%d b=%d want 0", ca, cb)
	}
	if ha != hb {
		t.Errorf("empty-store hash unstable: a=%s b=%s", ha, hb)
	}
}
