package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/security/clientrotation"
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
