package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
)

// TestMemoryClientStore_AddBaselinesSecretRotatedAt mirrors the SQLite
// coverage: Add stamps a fresh SecretRotatedAt for a confidential client,
// leaving a secretless (public/federation) client's timestamp at zero.
func TestMemoryClientStore_AddBaselinesSecretRotatedAt(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	if err := store.Add(ctx, &sso.Client{ID: "confidential", Secret: "shh", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.Add(ctx, &sso.Client{ID: "public", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := store.Get(ctx, "confidential")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SecretRotatedAt.IsZero() {
		t.Error("confidential client's SecretRotatedAt must be baselined at Add time")
	}
	pub, err := store.Get(ctx, "public")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !pub.SecretRotatedAt.IsZero() {
		t.Errorf("secretless client's SecretRotatedAt = %v; want zero", pub.SecretRotatedAt)
	}
}

// TestMemoryClientStore_RotateSecretUpdatesSecretRotatedAt proves
// RotateSecret refreshes the timestamp, converging a due client to not-due.
func TestMemoryClientStore_RotateSecretUpdatesSecretRotatedAt(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	if err := store.Add(ctx, &sso.Client{ID: "r", Secret: "old", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	before, err := store.Get(ctx, "r")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	beforeAt := before.SecretRotatedAt
	if _, err := store.RotateSecret(ctx, "r"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	after, err := store.Get(ctx, "r")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !after.SecretRotatedAt.After(beforeAt) && !after.SecretRotatedAt.Equal(beforeAt) {
		t.Errorf("SecretRotatedAt after rotation = %v; want >= %v", after.SecretRotatedAt, beforeAt)
	}
}

func TestMemoryClientStore_RotateSecretOverlapLifecycle(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	if err := store.Add(ctx, &sso.Client{ID: "overlap", Secret: "old", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	newSecret, err := store.RotateSecretWithOverlap(ctx, "overlap", time.Hour)
	if err != nil {
		t.Fatalf("RotateSecretWithOverlap: %v", err)
	}
	if err := store.ValidateSecret(ctx, "overlap", newSecret); err != nil {
		t.Fatalf("new secret inside overlap: %v", err)
	}
	if err := store.ValidateSecret(ctx, "overlap", "old"); err != nil {
		t.Fatalf("old secret inside overlap: %v", err)
	}
	client, err := store.Get(ctx, "overlap")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if client.PreviousSecret == "old" || !client.SecretOverlapUntil.After(time.Now()) {
		t.Fatalf("overlap metadata not stored safely: %+v", client)
	}
	client.SecretOverlapUntil = time.Now().Add(-time.Second)
	if err := store.Update(ctx, client); err != nil {
		t.Fatalf("expire overlap: %v", err)
	}
	if err := store.ValidateSecret(ctx, "overlap", "old"); err == nil {
		t.Fatal("old secret after overlap must be rejected")
	}
}

func TestMemoryClientStore_SecretExpiryEnforced(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	if err := store.Add(ctx, &sso.Client{ID: "expired", Secret: "secret", Active: true, SecretExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := store.ValidateSecret(ctx, "expired", "secret"); err == nil {
		t.Fatal("expired client secret must be rejected")
	}
	if err := store.Add(ctx, &sso.Client{ID: "default-expiry", Secret: "secret", Active: true}); err != nil {
		t.Fatalf("Add default expiry: %v", err)
	}
	client, err := store.Get(ctx, "default-expiry")
	if err != nil || time.Until(client.SecretExpiresAt) < 89*24*time.Hour {
		t.Fatalf("new secret did not receive default lifetime: client=%+v err=%v", client, err)
	}
}

// TestMemoryClientStore_ListDueForRotation proves the due-listing contract:
// active + secret-bearing + rotated at-or-before the cutoff. Zero
// SecretRotatedAt (AddSeed — the YAML-seed loading path — never stamps it,
// see core.Client.SecretRotatedAt) is NEVER due, matching sqlite.
func TestMemoryClientStore_ListDueForRotation(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	now := time.Now()

	mustAddMemory(t, store, &sso.Client{ID: "stale", Secret: "s", Active: true})
	mustAddMemory(t, store, &sso.Client{ID: "fresh", Secret: "s", Active: true})
	mustAddMemory(t, store, &sso.Client{ID: "inactive", Secret: "s", Active: false})
	mustAddMemory(t, store, &sso.Client{ID: "public", Active: true})
	// AddSeed never stamps SecretRotatedAt — the YAML-seeded-client shape.
	store.AddSeed(&sso.Client{ID: "seeded", Secret: "s", Active: true})

	var cs sso.ClientStore = store
	lister, ok := cs.(clientrotation.ClientRotationLister)
	if !ok {
		t.Fatal("MemoryClientStore must implement clientrotation.ClientRotationLister")
	}

	none, err := lister.ListDueForRotation(ctx, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("ListDueForRotation: %v", err)
	}
	if len(none) != 0 {
		t.Errorf("cutoff before every rotation: due = %v; want none", none)
	}

	due, err := lister.ListDueForRotation(ctx, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("ListDueForRotation: %v", err)
	}
	if len(due) != 2 {
		t.Fatalf("due = %v; want exactly 2 (stale, fresh) — inactive/public/seeded excluded", due)
	}
	seen := map[string]bool{}
	for _, id := range due {
		seen[id] = true
	}
	if !seen["stale"] || !seen["fresh"] {
		t.Errorf("due = %v; want [stale fresh] in some order", due)
	}
}

func mustAddMemory(t *testing.T, store *defaultimpl.MemoryClientStore, c *sso.Client) {
	t.Helper()
	if err := store.Add(context.Background(), c); err != nil {
		t.Fatalf("Add(%s): %v", c.ID, err)
	}
}
