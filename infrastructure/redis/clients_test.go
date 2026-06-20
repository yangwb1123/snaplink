package redis

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

func newClient(id string) *sso.Client {
	return &sso.Client{
		ID:                      id,
		Secret:                  "s3cr3t-" + id,
		Active:                  true,
		RegistrationAccessToken: "rat-" + id,
		TenantID:                "acme",
	}
}

func TestRedisClientStore_AddGetRoundTrip(t *testing.T) {
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
	if got.ID != "c1" || got.TenantID != "acme" || !got.Active {
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
	_, rdb := newTestClient(t)
	cs := NewClientStore(rdb)
	if _, err := cs.Get(context.Background(), "nope"); !errors.Is(err, sso.ErrNoSuchClient) {
		t.Errorf("Get unknown = %v, want ErrNoSuchClient", err)
	}
}

func TestRedisClientStore_AddDuplicate(t *testing.T) {
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
