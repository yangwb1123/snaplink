package clientrotation_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/lifecycle/rotation"
	"github.com/yangwb1123/snaplink/shared/core/corecredential"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
)

// TestClientSecretRotator_RotateOnlyRotatesDueClients is the core proof
// requested for this feature: given a REAL ClientStore (no mocks —
// defaultimpl.MemoryClientStore) holding one client past-due and one
// not-due, a Rotate() sweep changes ONLY the past-due client's secret.
func TestClientSecretRotator_RotateOnlyRotatesDueClients(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	mustAdd(t, store, &sso.Client{ID: "stale", Secret: "stale-secret", Active: true})
	mustAdd(t, store, &sso.Client{ID: "fresh", Secret: "fresh-secret", Active: true})

	// Backdate "stale" past the rotator's interval; leave "fresh" as just
	// added (not due).
	backdate(t, store, "stale", -48*time.Hour)

	rotator := clientrotation.NewClientSecretRotator(store, 24*time.Hour, nil)
	meta, err := rotator.Rotate(ctx)
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if meta.Type != corecredential.CredentialTypeOAuthClientSecret {
		t.Errorf("meta.Type = %q; want %q", meta.Type, corecredential.CredentialTypeOAuthClientSecret)
	}
	if meta.Version != 1 {
		t.Errorf("meta.Version = %d; want 1 (first sweep)", meta.Version)
	}

	stale, err := store.Get(ctx, "stale")
	if err != nil {
		t.Fatalf("Get(stale): %v", err)
	}
	if err := store.ValidateSecret(ctx, "stale", "stale-secret"); err == nil {
		t.Error("stale client's OLD secret must no longer validate after rotation")
	}
	if stale.SecretRotatedAt.Before(time.Now().Add(-time.Minute)) {
		t.Errorf("stale client's SecretRotatedAt = %v; want refreshed to ~now by this sweep", stale.SecretRotatedAt)
	}

	if err := store.ValidateSecret(ctx, "fresh", "fresh-secret"); err != nil {
		t.Error("fresh client's secret must be UNCHANGED — it was not due")
	}
}

// TestClientSecretRotator_RotateNoDueClientsIsNoop proves an empty sweep
// (nothing due) still succeeds and produces a sweep-event meta with rotated
// count implicitly zero (no error, no client touched).
func TestClientSecretRotator_RotateNoDueClientsIsNoop(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	mustAdd(t, store, &sso.Client{ID: "fresh", Secret: "s", Active: true})

	rotator := clientrotation.NewClientSecretRotator(store, 24*time.Hour, nil)
	meta, err := rotator.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if meta.Version != 1 {
		t.Errorf("meta.Version = %d; want 1", meta.Version)
	}
	if err := store.ValidateSecret(context.Background(), "fresh", "s"); err != nil {
		t.Error("untouched client's secret must still validate")
	}
}

// TestClientSecretRotator_SecondSweepIncrementsVersion proves repeated
// sweeps advance the synthetic sweep version (governance inventory shows
// "when did the fleet last get swept").
func TestClientSecretRotator_SecondSweepIncrementsVersion(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	rotator := clientrotation.NewClientSecretRotator(store, time.Hour, nil)
	first, err := rotator.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate 1: %v", err)
	}
	second, err := rotator.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate 2: %v", err)
	}
	if second.Version != first.Version+1 {
		t.Errorf("second sweep version = %d; want %d", second.Version, first.Version+1)
	}
}

// TestClientSecretRotator_OverlapWindowIsZero proves callers can still opt
// into immediate cutover by omitting the overlap argument.
func TestClientSecretRotator_OverlapWindowIsZero(t *testing.T) {
	t.Parallel()
	rotator := clientrotation.NewClientSecretRotator(defaultimpl.NewMemoryClientStore(), time.Hour, nil)
	if got := rotator.OverlapWindow(); got != 0 {
		t.Errorf("OverlapWindow() = %v; want 0 (explicit immediate cutover)", got)
	}
}

func TestClientSecretRotator_ConfiguredOverlapKeepsOldSecretValid(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	ctx := context.Background()
	mustAdd(t, store, &sso.Client{ID: "stale-overlap", Secret: "old", Active: true})
	backdate(t, store, "stale-overlap", -2*time.Hour)
	rotator := clientrotation.NewClientSecretRotator(store, time.Hour, nil, 2*time.Hour)
	if rotator.OverlapWindow() != 2*time.Hour {
		t.Fatalf("OverlapWindow = %v, want 2h", rotator.OverlapWindow())
	}
	if _, err := rotator.Rotate(ctx); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if err := store.ValidateSecret(ctx, "stale-overlap", "old"); err != nil {
		t.Fatalf("scheduled rotation discarded old secret before overlap elapsed: %v", err)
	}
}

// TestClientSecretRotator_PartialFailureRotatesTheRest proves one client's
// rotation failure doesn't block the rest of the fleet, and that the
// scheduler-facing contract reports failure (for backoff-retry) even though
// most of the sweep succeeded.
func TestClientSecretRotator_PartialFailureRotatesTheRest(t *testing.T) {
	t.Parallel()
	store := &failingRotateStore{MemoryClientStore: defaultimpl.NewMemoryClientStore(), failID: "bad"}
	mustAddFailing(t, store, &sso.Client{ID: "bad", Secret: "s", Active: true})
	mustAddFailing(t, store, &sso.Client{ID: "good", Secret: "s", Active: true})

	rotator := clientrotation.NewClientSecretRotator(store, time.Hour, nil)
	// Backdate both so they're due against a 1h interval.
	backdateFailing(t, store, "bad", -2*time.Hour)
	backdateFailing(t, store, "good", -2*time.Hour)

	if _, err := rotator.Rotate(context.Background()); err == nil {
		t.Fatal("expected sweep-level error when one client fails to rotate")
	}
	if err := store.ValidateSecret(context.Background(), "good", "s"); err == nil {
		t.Error("the succeeding client's secret should have rotated (old value must no longer validate)")
	}
}

// TestClientSecretRotator_NoListerSupportIsGracefulNoop proves a ClientStore
// that doesn't implement ClientRotationLister degrades gracefully (matches
// the RefreshTokenExpiryLister optional-extension idiom) rather than
// panicking or erroring — cmd's build-time validation is what stops this
// combination from reaching production.
func TestClientSecretRotator_NoListerSupportIsGracefulNoop(t *testing.T) {
	t.Parallel()
	rotator := clientrotation.NewClientSecretRotator(listerlessStore{}, time.Hour, nil)
	meta, err := rotator.Rotate(context.Background())
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if meta.Type != corecredential.CredentialTypeOAuthClientSecret {
		t.Errorf("meta.Type = %q", meta.Type)
	}
}

// TestClientSecretRotator_RegistersOntoRotationRegistry proves this rotator
// satisfies corecredential.CredentialRotator well enough to register with
// the SAME rotation.Registry framework the webhook rotator uses.
func TestClientSecretRotator_RegistersOntoRotationRegistry(t *testing.T) {
	t.Parallel()
	store := defaultimpl.NewMemoryClientStore()
	rotator := clientrotation.NewClientSecretRotator(store, time.Hour, nil)
	reg := rotation.NewRegistry()
	if err := reg.Register(rotator, time.Hour); err != nil {
		t.Fatalf("Register: %v", err)
	}
	inv := reg.Inventory()
	if len(inv) != 1 || inv[0].Type != corecredential.CredentialTypeOAuthClientSecret {
		t.Fatalf("inventory = %+v; want one oauth_client_secret entry", inv)
	}
}

func mustAdd(t *testing.T, store *defaultimpl.MemoryClientStore, c *sso.Client) {
	t.Helper()
	if err := store.Add(context.Background(), c); err != nil {
		t.Fatalf("Add(%s): %v", c.ID, err)
	}
}

// backdate reaches around the public ClientStore interface (which has no
// setter for SecretRotatedAt) via RotateSecret + a direct Get/mutate isn't
// possible either since Add/RotateSecret always stamp "now". Instead this
// helper rotates the client (stamping "now") then relies on the store
// returning the SAME pointer it stores internally isn't guaranteed, so
// backdate goes through Update — the one write path that does NOT stamp
// SecretRotatedAt (see clientrotation package doc), letting a test set it
// directly.
func backdate(t *testing.T, store *defaultimpl.MemoryClientStore, id string, delta time.Duration) {
	t.Helper()
	c, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	backdated := *c
	backdated.SecretRotatedAt = time.Now().Add(delta)
	if err := store.Update(context.Background(), &backdated); err != nil {
		t.Fatalf("Update(%s): %v", id, err)
	}
}

// failingRotateStore wraps MemoryClientStore, failing RotateSecret for one
// configured client ID — a real store for every other operation, so the
// test proves per-client fault isolation without a mock framework.
type failingRotateStore struct {
	*defaultimpl.MemoryClientStore
	failID string
}

func (f *failingRotateStore) RotateSecret(ctx context.Context, clientID string) (string, error) {
	if clientID == f.failID {
		return "", errors.New("injected rotation failure")
	}
	return f.MemoryClientStore.RotateSecret(ctx, clientID)
}

func (f *failingRotateStore) ListDueForRotation(ctx context.Context, olderThan time.Time) ([]string, error) {
	var cs sso.ClientStore = f.MemoryClientStore
	lister := cs.(clientrotation.ClientRotationLister)
	return lister.ListDueForRotation(ctx, olderThan)
}

func mustAddFailing(t *testing.T, store *failingRotateStore, c *sso.Client) {
	t.Helper()
	if err := store.Add(context.Background(), c); err != nil {
		t.Fatalf("Add(%s): %v", c.ID, err)
	}
}

func backdateFailing(t *testing.T, store *failingRotateStore, id string, delta time.Duration) {
	t.Helper()
	c, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("Get(%s): %v", id, err)
	}
	backdated := *c
	backdated.SecretRotatedAt = time.Now().Add(delta)
	if err := store.Update(context.Background(), &backdated); err != nil {
		t.Fatalf("Update(%s): %v", id, err)
	}
}

// listerlessStore is a minimal sso.ClientStore that deliberately does NOT
// implement clientrotation.ClientRotationLister.
type listerlessStore struct{ sso.ClientStore }
