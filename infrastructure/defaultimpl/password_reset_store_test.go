package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
)

// passwordResetStoreSuite runs the shared contract against any
// core.PasswordResetStore so memory + sqlite stay behaviorally identical.
func passwordResetStoreSuite(t *testing.T, mk func(t *testing.T) core.PasswordResetStore) {
	ctx := context.Background()

	t.Run("issue then consume returns the token", func(t *testing.T) {
		s := mk(t)
		if err := s.Issue(ctx, &core.PasswordResetToken{Token: "tok-1", UserID: "u1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("issue: %v", err)
		}
		got, err := s.Consume(ctx, "tok-1")
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if got.UserID != "u1" {
			t.Errorf("token = %+v, want UserID u1", got)
		}
	})

	t.Run("consume missing returns ErrResetTokenNotFound", func(t *testing.T) {
		s := mk(t)
		if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrResetTokenNotFound) {
			t.Errorf("err = %v, want ErrResetTokenNotFound", err)
		}
	})

	t.Run("consume is single-use", func(t *testing.T) {
		s := mk(t)
		_ = s.Issue(ctx, &core.PasswordResetToken{Token: "tok-2", UserID: "u1", ExpiresAt: time.Now().Add(time.Minute)})
		if _, err := s.Consume(ctx, "tok-2"); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if _, err := s.Consume(ctx, "tok-2"); !errors.Is(err, core.ErrResetTokenNotFound) {
			t.Errorf("second consume err = %v, want ErrResetTokenNotFound", err)
		}
	})

	t.Run("expired token is not returned", func(t *testing.T) {
		s := mk(t)
		_ = s.Issue(ctx, &core.PasswordResetToken{Token: "tok-3", UserID: "u1", ExpiresAt: time.Now().Add(-time.Second)})
		if _, err := s.Consume(ctx, "tok-3"); !errors.Is(err, core.ErrResetTokenNotFound) {
			t.Errorf("expired consume err = %v, want ErrResetTokenNotFound", err)
		}
	})

	t.Run("token binds to its own user", func(t *testing.T) {
		s := mk(t)
		_ = s.Issue(ctx, &core.PasswordResetToken{Token: "tA", UserID: "alice", ExpiresAt: time.Now().Add(time.Minute)})
		_ = s.Issue(ctx, &core.PasswordResetToken{Token: "tB", UserID: "bob", ExpiresAt: time.Now().Add(time.Minute)})
		a, _ := s.Consume(ctx, "tA")
		if a == nil || a.UserID != "alice" {
			t.Errorf("tA = %+v, want alice", a)
		}
		b, _ := s.Consume(ctx, "tB")
		if b == nil || b.UserID != "bob" {
			t.Errorf("tB = %+v, want bob", b)
		}
	})
}

func TestMemoryPasswordResetStore(t *testing.T) {
	t.Parallel()
	passwordResetStoreSuite(t, func(t *testing.T) core.PasswordResetStore {
		return defaultimpl.NewMemoryPasswordResetStore()
	})
}
