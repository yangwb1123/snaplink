package defaultmfa

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
)

func TestMemoryTOTPEnrollmentStore_Lifecycle(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryTOTPEnrollmentStore()
	secret := []byte("seedbytes12345678901")

	// Nothing enrolled yet: empty list, GetSecret errors (treated as no-TOTP).
	if fs, _ := store.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Fatalf("ListFactors before enroll = %d, want 0", len(fs))
	}
	if _, err := store.GetSecret(ctx, "u-alice"); err == nil {
		t.Error("GetSecret before enroll should error (no secret)")
	}

	// Enroll: factor is listed and the secret is readable by the verifier seam.
	if err := store.AddTOTPFactor(ctx, "u-alice", "f1", "iPhone", secret); err != nil {
		t.Fatalf("AddTOTPFactor: %v", err)
	}
	fs, _ := store.ListFactors(ctx, "u-alice")
	if len(fs) != 1 || fs[0].ID != "f1" || fs[0].Method != authenticators.MethodTOTP || fs[0].Label != "iPhone" {
		t.Fatalf("ListFactors after enroll = %+v", fs)
	}
	got, err := store.GetSecret(ctx, "u-alice")
	if err != nil || string(got) != string(secret) {
		t.Fatalf("GetSecret = %q, %v; want %q", got, err, secret)
	}

	// GetSecret returns a copy: mutating it must not corrupt stored state.
	got[0] ^= 0xff
	if again, _ := store.GetSecret(ctx, "u-alice"); string(again) != string(secret) {
		t.Error("GetSecret returned a non-copy; stored secret was mutated")
	}

	// Re-enroll REPLACES the prior factor + secret (one TOTP per user).
	secret2 := []byte("differentbytes098765")
	_ = store.AddTOTPFactor(ctx, "u-alice", "f2", "Tablet", secret2)
	if fs, _ := store.ListFactors(ctx, "u-alice"); len(fs) != 1 || fs[0].ID != "f2" {
		t.Fatalf("re-enroll did not replace: %+v", fs)
	}
	if got2, _ := store.GetSecret(ctx, "u-alice"); string(got2) != string(secret2) {
		t.Error("re-enroll did not replace the secret")
	}

	// Cross-factor isolation: a non-matching factorID is a no-op.
	_ = store.RemoveFactor(ctx, "u-alice", "wrong-id")
	if fs, _ := store.ListFactors(ctx, "u-alice"); len(fs) != 1 {
		t.Error("RemoveFactor with a wrong id should be a no-op")
	}

	// Removing the real factor clears both the factor and the secret.
	_ = store.RemoveFactor(ctx, "u-alice", "f2")
	if fs, _ := store.ListFactors(ctx, "u-alice"); len(fs) != 0 {
		t.Error("RemoveFactor did not remove the factor")
	}
	if _, err := store.GetSecret(ctx, "u-alice"); err == nil {
		t.Error("RemoveFactor did not clear the secret")
	}
}
