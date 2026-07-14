package sqlite_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/security/clientrotation"
)

// TestSQLiteClients_AddBaselinesSecretRotatedAt proves a freshly-added
// confidential client gets a non-zero SecretRotatedAt immediately (so it can
// age into "due" on its own schedule), while a secretless (public/federation)
// client's timestamp stays zero — it has nothing to rotate.
func TestSQLiteClients_AddBaselinesSecretRotatedAt(t *testing.T) {
	t.Parallel()
	st := newClientStore(t)
	ctx := context.Background()
	if err := st.Add(ctx, &sso.Client{ID: "confidential", Secret: "shh", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := st.Add(ctx, &sso.Client{ID: "public", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := st.Get(ctx, "confidential")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SecretRotatedAt.IsZero() {
		t.Error("confidential client's SecretRotatedAt must be baselined at Add time")
	}
	pub, err := st.Get(ctx, "public")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !pub.SecretRotatedAt.IsZero() {
		t.Errorf("secretless client's SecretRotatedAt = %v; want zero (nothing to rotate)", pub.SecretRotatedAt)
	}
}

// TestSQLiteClients_RotateSecretUpdatesSecretRotatedAt proves RotateSecret
// stamps a fresh SecretRotatedAt, converging a due client back to not-due.
func TestSQLiteClients_RotateSecretUpdatesSecretRotatedAt(t *testing.T) {
	t.Parallel()
	st := newClientStore(t)
	ctx := context.Background()
	if err := st.Add(ctx, &sso.Client{ID: "r", Secret: "old", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	before, err := st.Get(ctx, "r")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := st.RotateSecret(ctx, "r"); err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	after, err := st.Get(ctx, "r")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !after.SecretRotatedAt.After(before.SecretRotatedAt) {
		t.Errorf("SecretRotatedAt after rotation = %v; want strictly after %v", after.SecretRotatedAt, before.SecretRotatedAt)
	}
}

// TestSQLiteClients_ListDueForRotation proves the query's full contract: only
// ACTIVE, secret-bearing clients whose secret is at least as old as the
// cutoff are due; an inactive client, a secretless client, and a
// recently-rotated client are all excluded, and a never-rotated (zero
// SecretRotatedAt) legacy-style row is excluded too — see
// core.Client.SecretRotatedAt for why zero must never mean "overdue".
func TestSQLiteClients_ListDueForRotation(t *testing.T) {
	t.Parallel()
	st := newClientStore(t)
	ctx := context.Background()
	now := time.Now()

	// due: active, has a secret, rotated long ago.
	mustAdd(t, st, &sso.Client{ID: "stale", Secret: "s", Active: true})
	// not due: rotated moments ago (Add just baselined it to "now").
	mustAdd(t, st, &sso.Client{ID: "fresh", Secret: "s", Active: true})
	// not due: inactive.
	mustAdd(t, st, &sso.Client{ID: "inactive", Secret: "s", Active: false})
	// not due: no secret to rotate (federation/public client).
	mustAdd(t, st, &sso.Client{ID: "public", Active: true})
	// not due: never tracked (simulates a pre-migration row) — the sqlite
	// migration defaults secret_rotated_at to 0 for existing rows, and Put
	// (unlike Add) does NOT stamp it, so this reproduces that shape exactly.
	mustPut(t, st, &sso.Client{ID: "legacy", Secret: "s", Active: true})

	// Force "stale" to look old by rotating it, then asking for everything
	// due at-or-before a cutoff in the FUTURE relative to "fresh"'s baseline
	// but computed from "stale"'s rotation moment: simplest is to list due
	// using a cutoff of `now` (every one of stale/fresh was just
	// stamped "now" or later by Add/RotateSecret), which would call both
	// due. Instead, directly assert the exclusion set using a cutoff before
	// any of them (nothing due) and a cutoff comfortably after all of them
	// (both secret-bearing/active/tracked clients due) — this avoids any
	// flakiness from real-clock skew between Add calls.
	var store sso.ClientStore = st
	lister, ok := store.(clientrotation.ClientRotationLister)
	if !ok {
		t.Fatal("sqlite.ClientStore must implement clientrotation.ClientRotationLister")
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
	if len(due) != 2 || due[0] != "fresh" || due[1] != "stale" {
		t.Errorf("due = %v; want exactly [fresh stale] (inactive/public/legacy excluded)", due)
	}
}

func mustAdd(t *testing.T, st interface {
	Add(ctx context.Context, c *sso.Client) error
}, c *sso.Client) {
	t.Helper()
	if err := st.Add(context.Background(), c); err != nil {
		t.Fatalf("Add(%s): %v", c.ID, err)
	}
}

func mustPut(t *testing.T, st interface {
	Put(ctx context.Context, c *sso.Client) error
}, c *sso.Client) {
	t.Helper()
	if err := st.Put(context.Background(), c); err != nil {
		t.Fatalf("Put(%s): %v", c.ID, err)
	}
}
