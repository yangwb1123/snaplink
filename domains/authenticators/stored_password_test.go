package authenticators_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
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
