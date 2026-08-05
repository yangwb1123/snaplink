package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func newClient(id string) *sso.Client {
	return &sso.Client{
		ID:                      id,
		Secret:                  "s3cr3t-" + id,
		Active:                  true,
		RegistrationAccessToken: "rat-" + id,
		TenantID:                "acme",
		LoginPageURI:            "https://login.example/authorize",
	}
}

func TestRedisClientStore_AddGetRoundTrip(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()

	if err := cs.Add(ctx, newClient("c1")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := cs.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "c1" || got.TenantID != "acme" || !got.Active || got.LoginPageURI == "" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
	// Secret must be hashed at rest, not the plaintext.
	if got.Secret == "s3cr3t-c1" {
		t.Errorf("secret stored in plaintext: %q", got.Secret)
	}
	if !isBcryptHash(got.Secret) || !isBcryptHash(got.RegistrationAccessToken) {
		t.Errorf("secret/regtoken not bcrypt-hashed at rest")
	}
	// ValidateSecret accepts the original plaintext against the hash.
	if err := cs.ValidateSecret(ctx, "c1", "s3cr3t-c1"); err != nil {
		t.Errorf("ValidateSecret(correct): %v", err)
	}
	if err := cs.ValidateSecret(ctx, "c1", "wrong"); err == nil {
		t.Errorf("ValidateSecret(wrong) must fail")
	}
}

func TestRedisClientStore_GetUnknown(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	if _, err := cs.Get(context.Background(), "nope"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("Get unknown = %v, want ErrNoSuchClient", err)
	}
}

func TestRedisClientStore_AddDuplicate(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()
	if err := cs.Add(ctx, newClient("dup")); err != nil {
		t.Fatalf("first Add: %v", err)
	}
	if err := cs.Add(ctx, newClient("dup")); !errors.Is(err, sso.ErrClientExists) {
		t.Errorf("duplicate Add = %v, want ErrClientExists", err)
	}
}

func TestRedisClientStore_UpdateMissingAndPresent(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()

	if err := cs.Update(ctx, newClient("ghost")); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("Update missing = %v, want ErrNoSuchClient", err)
	}

	_ = cs.Add(ctx, newClient("c2"))
	upd := newClient("c2")
	upd.Active = false
	if err := cs.Update(ctx, upd); err != nil {
		t.Fatalf("Update present: %v", err)
	}
	got, _ := cs.Get(ctx, "c2")
	if got.Active {
		t.Errorf("Update did not persist Active=false")
	}
	// An inactive client fails ValidateSecret even with the right secret.
	if err := cs.ValidateSecret(ctx, "c2", "s3cr3t-c2"); err == nil {
		t.Errorf("ValidateSecret on inactive client must fail")
	}
}

func TestRedisClientStore_DeleteIdempotent(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()
	_ = cs.Add(ctx, newClient("c3"))
	if err := cs.Delete(ctx, "c3"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.Get(ctx, "c3"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("client present after delete")
	}
	// Second delete of a missing id is a no-op (nil).
	if err := cs.Delete(ctx, "c3"); err != nil {
		t.Errorf("idempotent Delete = %v, want nil", err)
	}
}

func TestRedisClientStore_List(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		_ = cs.Add(ctx, newClient(id))
	}
	got, err := cs.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("List len = %d, want 3", len(got))
	}
	// Deleting one removes it from the index too.
	_ = cs.Delete(ctx, "b")
	got, _ = cs.List(ctx)
	if len(got) != 2 {
		t.Errorf("List after delete = %d, want 2", len(got))
	}
}

func TestRedisClientStore_RotateSecret(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()
	_ = cs.Add(ctx, newClient("c4"))

	newSecret, err := cs.RotateSecret(ctx, "c4")
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if newSecret == "" {
		t.Fatal("RotateSecret returned empty secret")
	}
	// New plaintext validates; the old one no longer does.
	if err := cs.ValidateSecret(ctx, "c4", newSecret); err != nil {
		t.Errorf("ValidateSecret(rotated): %v", err)
	}
	if err := cs.ValidateSecret(ctx, "c4", "s3cr3t-c4"); err == nil {
		t.Errorf("old secret must stop working after rotation")
	}
	// Rotating a missing client surfaces ErrNoSuchClient.
	if _, err := cs.RotateSecret(ctx, "missing"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("RotateSecret missing = %v, want ErrNoSuchClient", err)
	}
}

func TestRedisClientStore_RotateSecretOverlapPersists(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()
	if err := cs.Add(ctx, newClient("overlap")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	newSecret, err := cs.RotateSecretWithOverlap(ctx, "overlap", time.Hour)
	if err != nil {
		t.Fatalf("RotateSecretWithOverlap: %v", err)
	}
	if err := cs.ValidateSecret(ctx, "overlap", newSecret); err != nil {
		t.Fatalf("new secret inside overlap: %v", err)
	}
	if err := cs.ValidateSecret(ctx, "overlap", "s3cr3t-overlap"); err != nil {
		t.Fatalf("old secret inside overlap: %v", err)
	}
	client, err := cs.Get(ctx, "overlap")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if client.PreviousSecret == "s3cr3t-overlap" || !client.SecretOverlapUntil.After(time.Now()) || client.SecretRotatedAt.IsZero() {
		t.Fatalf("overlap metadata not persisted safely: %+v", client)
	}
	client.SecretOverlapUntil = time.Now().Add(-time.Second)
	if err := cs.Update(ctx, client); err != nil {
		t.Fatalf("expire overlap: %v", err)
	}
	if err := cs.ValidateSecret(ctx, "overlap", "s3cr3t-overlap"); err == nil {
		t.Fatal("old secret after overlap must be rejected")
	}
	due, err := cs.ListDueForRotation(ctx, time.Now().Add(time.Hour))
	if err != nil || len(due) != 1 || due[0] != "overlap" {
		t.Fatalf("persisted rotation timestamp not listable: due=%v err=%v", due, err)
	}
}

func TestRedisClientStore_SecretExpiryPersistsAndIsEnforced(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()
	expires := time.Now().UTC().Add(-time.Minute)
	client := newClient("expired")
	client.SecretExpiresAt = expires
	if err := cs.Add(ctx, client); err != nil {
		t.Fatalf("Add: %v", err)
	}
	stored, err := cs.Get(ctx, "expired")
	if err != nil || stored.SecretExpiresAt.UnixNano() != expires.UnixNano() {
		t.Fatalf("expiry did not round-trip: client=%+v err=%v", stored, err)
	}
	if err := cs.ValidateSecret(ctx, "expired", "s3cr3t-expired"); err == nil {
		t.Fatal("expired client secret must be rejected")
	}
}

func TestRedisClientStore_DCRRATOverlapPersists(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()
	client := newClient("rat-overlap")
	client.PreviousRegistrationAccessToken = "previous-rat"
	client.RegistrationAccessTokenOverlapUntil = time.Now().UTC().Add(time.Hour)
	if err := cs.Add(ctx, client); err != nil {
		t.Fatalf("Add: %v", err)
	}
	stored, err := cs.Get(ctx, "rat-overlap")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if stored.PreviousRegistrationAccessToken == "previous-rat" ||
		stored.PreviousRegistrationAccessToken == "" ||
		stored.RegistrationAccessTokenOverlapUntil.IsZero() {
		t.Fatalf("RAT overlap did not persist safely: %+v", stored)
	}
}

// TestRedisClientStore_TenantIndexAndStats proves the TenantScopedClientStore
// + ClientStoreStats extensions: the per-tenant SET index tracks writes and
// tenant moves, and Stats returns a canonical fingerprint that flips on a
// discovery-relevant change and stays stable otherwise.
func TestRedisClientStore_TenantIndexAndStats(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	ctx := context.Background()

	if err := cs.Add(ctx, &sso.Client{ID: "t1-a", Secret: "s1", Active: true, TenantID: "t1"}); err != nil {
		t.Fatalf("Add t1-a: %v", err)
	}
	if err := cs.Add(ctx, &sso.Client{ID: "t1-b", Secret: "s2", Active: true, TenantID: "t1"}); err != nil {
		t.Fatalf("Add t1-b: %v", err)
	}
	if err := cs.Add(ctx, &sso.Client{ID: "t2-a", Secret: "s3", Active: true, TenantID: "t2"}); err != nil {
		t.Fatalf("Add t2-a: %v", err)
	}
	if err := cs.Add(ctx, &sso.Client{ID: "none-a", Secret: "s4", Active: true}); err != nil {
		t.Fatalf("Add none-a: %v", err)
	}

	t1, err := cs.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("ListByTenant t1: %v", err)
	}
	if len(t1) != 2 {
		t.Fatalf("t1 clients = %d, want 2 (no cross-tenant leakage)", len(t1))
	}
	t2, err := cs.ListByTenant(ctx, "t2")
	if err != nil {
		t.Fatalf("ListByTenant t2: %v", err)
	}
	if len(t2) != 1 || t2[0].ID != "t2-a" {
		t.Fatalf("t2 clients = %+v, want exactly t2-a", t2)
	}
	none, err := cs.ListByTenant(ctx, "")
	if err != nil {
		t.Fatalf("ListByTenant empty: %v", err)
	}
	if len(none) != 1 || none[0].ID != "none-a" {
		t.Fatalf("tenant-less clients = %+v, want exactly none-a", none)
	}

	// Stats: count + fingerprint; a scope edit flips the hash, a secret
	// rotation does not (discovery-relevant fields only).
	count, hash1, err := cs.Stats(ctx)
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if count != 4 {
		t.Fatalf("Stats count = %d, want 4", count)
	}
	if _, err := cs.RotateSecret(ctx, "t1-a"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	_, hashAfterRotation, err := cs.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hashAfterRotation != hash1 {
		t.Errorf("secret rotation flipped the discovery fingerprint")
	}
	if err := cs.Update(ctx, &sso.Client{ID: "t1-a", Secret: "", Active: true, TenantID: "t1", AllowedScopes: []string{"openid", "profile"}}); err != nil {
		t.Fatalf("Update t1-a: %v", err)
	}
	_, hashAfterScope, err := cs.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hashAfterScope == hash1 {
		t.Errorf("scope edit did not flip the discovery fingerprint")
	}

	// Tenant move: Update with a different tenant relocates the index.
	if err := cs.Update(ctx, &sso.Client{ID: "t2-a", Secret: "", Active: true, TenantID: "t1"}); err != nil {
		t.Fatalf("Update t2-a tenant move: %v", err)
	}
	t1, err = cs.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(t1) != 3 {
		t.Fatalf("t1 clients after move = %d, want 3", len(t1))
	}
	t2, err = cs.ListByTenant(ctx, "t2")
	if err != nil {
		t.Fatal(err)
	}
	if len(t2) != 0 {
		t.Fatalf("t2 clients after move = %d, want 0", len(t2))
	}

	// Delete unindexes the tenant set.
	if err := cs.Delete(ctx, "t1-a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	t1, err = cs.ListByTenant(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(t1) != 2 {
		t.Fatalf("t1 clients after delete = %d, want 2", len(t1))
	}
}

// TestRedisClientStore_ImplementsTenantScopedExtensions pins the interface
// guards: the server's tenant-revocation leg and discovery cache must see
// the Redis backend as tenant-scoped + statted.
func TestRedisClientStore_ImplementsTenantScopedExtensions(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	var _ sso.TenantScopedClientStore = cs
	var _ interface {
		Stats(context.Context) (int, string, error)
	} = cs
}
