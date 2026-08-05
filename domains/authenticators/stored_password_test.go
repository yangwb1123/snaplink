package authenticators_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"golang.org/x/crypto/bcrypt"
)

func TestStoredPasswordVerifier(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := defaultimpl.NewMemoryPasswordCredentialStore()
	_ = store.SetPassword(ctx, "uid-alice", "correct-horse")

	// Resolver maps the login username to the stable user id.
	resolve := func(_ context.Context, username string) (string, error) {
		if username == "alice" {
			return "uid-alice", nil
		}
		return "", errors.New("unknown user")
	}
	v := authenticators.NewStoredPasswordVerifier(store, resolve)

	t.Run("correct password -> AuthResult", func(t *testing.T) {
		res, err := v.Verify(ctx, "alice", "correct-horse")
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if res.UserID != "uid-alice" || res.Provider != authenticators.MethodPassword {
			t.Errorf("AuthResult = %+v, want uid-alice / password", res)
		}
	})

	t.Run("wrong password -> auth failed", func(t *testing.T) {
		if _, err := v.Verify(ctx, "alice", "wrong"); !errors.Is(err, authenticators.ErrStoredPasswordAuthFailed) {
			t.Errorf("err = %v, want ErrStoredPasswordAuthFailed", err)
		}
	})

	t.Run("unknown username -> auth failed (same error)", func(t *testing.T) {
		if _, err := v.Verify(ctx, "mallory", "correct-horse"); !errors.Is(err, authenticators.ErrStoredPasswordAuthFailed) {
			t.Errorf("err = %v, want ErrStoredPasswordAuthFailed", err)
		}
	})

	t.Run("password changed in store takes effect", func(t *testing.T) {
		// Simulate POST /me/password updating the same store.
		_ = store.SetPassword(ctx, "uid-alice", "new-secret")
		if _, err := v.Verify(ctx, "alice", "correct-horse"); !errors.Is(err, authenticators.ErrStoredPasswordAuthFailed) {
			t.Errorf("old password should stop working after change, got %v", err)
		}
		if _, err := v.Verify(ctx, "alice", "new-secret"); err != nil {
			t.Errorf("new password should work after change: %v", err)
		}
	})
}

// TestStoredPasswordVerifier_ProgressiveRehashOnLogin proves the
// rehash-on-login upgrade: a hash imported below the policy target (e.g. an
// operator-seeded cost-4 hash) is verified successfully and then re-hashed
// in place at the policy cost, so the next login sees the upgraded hash.
func TestStoredPasswordVerifier_ProgressiveRehashOnLogin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := defaultimpl.NewMemoryPasswordCredentialStore()
	// Import a pre-computed LOW-cost bcrypt hash (the operator-seed shape).
	lowHash, err := bcrypt.GenerateFromPassword([]byte("legacy-pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("mint low-cost hash: %v", err)
	}
	if err := store.SetPasswordHash(ctx, "uid-legacy", string(lowHash)); err != nil {
		t.Fatalf("SetPasswordHash: %v", err)
	}
	resolve := func(_ context.Context, username string) (string, error) {
		return "uid-legacy", nil
	}
	v := authenticators.NewStoredPasswordVerifier(store, resolve)

	// Before login: the low-cost hash needs rehash.
	need, err := store.NeedsRehash(ctx, "uid-legacy")
	if err != nil || !need {
		t.Fatalf("NeedsRehash before login = (%v, %v), want (true, nil)", need, err)
	}

	if _, err := v.Verify(ctx, "legacy", "legacy-pass"); err != nil {
		t.Fatalf("verify legacy password: %v", err)
	}

	// After login: the hash has been upgraded to the policy cost.
	need, err = store.NeedsRehash(ctx, "uid-legacy")
	if err != nil {
		t.Fatalf("NeedsRehash after login: %v", err)
	}
	if need {
		t.Error("hash still below policy after login; rehash-on-login did not upgrade it")
	}
	// And the password still verifies.
	if verr := store.VerifyPassword(ctx, "uid-legacy", "legacy-pass"); verr != nil {
		t.Errorf("password no longer verifies after rehash: %v", verr)
	}
}
