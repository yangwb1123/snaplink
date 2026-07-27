package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
)

// TestPostgresClients_AddBaselinesSecretRotatedAt proves a freshly-added
// confidential client gets a non-zero SecretRotatedAt immediately (so it can
// age into "due" on its own schedule), while a secretless (public/federation)
// client's timestamp stays zero — it has nothing to rotate. Regression guard
// for the missing secret_rotated_at column (this backend previously had no
// column, write, or read for it at all).
func TestPostgresClients_AddBaselinesSecretRotatedAt(t *testing.T) {
	t.Parallel()
	st := freshClientStore(t)
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

// TestPostgresClients_RotateSecretUpdatesSecretRotatedAt proves RotateSecret
// stamps a fresh SecretRotatedAt, converging a due client back to not-due.
func TestPostgresClients_RotateSecretUpdatesSecretRotatedAt(t *testing.T) {
	t.Parallel()
	st := freshClientStore(t)
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

// TestPostgresClients_ListDueForRotation proves the query's full contract:
// only ACTIVE, secret-bearing clients whose secret is at least as old as the
// cutoff are due; an inactive client, a secretless client, and a
// recently-rotated client are all excluded, and a never-rotated (zero
// SecretRotatedAt) legacy-style row is excluded too. This backend previously
// didn't implement clientrotation.ClientRotationLister at all, so scheduled
// rotation silently never listed anything against a Postgres ClientStore.
func TestPostgresClients_ListDueForRotation(t *testing.T) {
	t.Parallel()
	st := freshClientStore(t)
	ctx := context.Background()
	now := time.Now()

	mustAddClient(t, st, &sso.Client{ID: "stale", Secret: "s", Active: true})
	mustAddClient(t, st, &sso.Client{ID: "fresh", Secret: "s", Active: true})
	mustAddClient(t, st, &sso.Client{ID: "inactive", Secret: "s", Active: false})
	mustAddClient(t, st, &sso.Client{ID: "public", Active: true})
	// Simulates a pre-migration row: Put (unlike Add) does NOT stamp
	// secret_rotated_at, so it stays at the migration's DEFAULT 0.
	if err := st.Put(ctx, &sso.Client{ID: "legacy", Secret: "s", Active: true}); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var store sso.ClientStore = st
	lister, ok := store.(clientrotation.ClientRotationLister)
	if !ok {
		t.Fatal("postgres.ClientStore must implement clientrotation.ClientRotationLister")
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

func mustAddClient(t *testing.T, st *ClientStore, c *sso.Client) {
	t.Helper()
	if err := st.Add(context.Background(), c); err != nil {
		t.Fatalf("Add(%s): %v", c.ID, err)
	}
}

// TestPostgresClients_TrustScoreRoundTrips proves ClientTrustScore /
// ClientTrustSetAt (platform/lifecycle/clienttrust) survive an Update and a
// re-Get — this backend previously had no columns for either field, so a
// score set by the trust scorer was silently lost the moment it was re-read.
func TestPostgresClients_TrustScoreRoundTrips(t *testing.T) {
	t.Parallel()
	st := freshClientStore(t)
	ctx := context.Background()
	if err := st.Add(ctx, &sso.Client{ID: "t1", Secret: "x", Active: true}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := st.Get(ctx, "t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientTrustScore != 0 || !got.ClientTrustSetAt.IsZero() {
		t.Fatalf("never-scored client must read as ClientTrustScore=0/ClientTrustSetAt=zero, got %+v", got)
	}
	now := time.Now().UTC()
	got.ClientTrustScore = 0.42
	got.ClientTrustSetAt = now
	if err := st.Update(ctx, got); err != nil {
		t.Fatalf("Update: %v", err)
	}
	after, err := st.Get(ctx, "t1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if after.ClientTrustScore != 0.42 {
		t.Errorf("ClientTrustScore = %v, want 0.42", after.ClientTrustScore)
	}
	if after.ClientTrustSetAt.UnixNano() != now.UnixNano() {
		t.Errorf("ClientTrustSetAt = %v, want %v", after.ClientTrustSetAt, now)
	}
}
