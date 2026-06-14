package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
)

// emailChangeStoreSuite runs the shared contract against any
// core.EmailChangeStore so memory + sqlite stay behaviorally identical.
func emailChangeStoreSuite(t *testing.T, mk func(t *testing.T) core.EmailChangeStore) {
	ctx := context.Background()

	t.Run("issue then consume returns token + new email", func(t *testing.T) {
		s := mk(t)
		if err := s.Issue(ctx, &core.EmailChangeToken{Token: "t1", UserID: "u1", NewEmail: "new@example.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
			t.Fatalf("issue: %v", err)
		}
		got, err := s.Consume(ctx, "t1")
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		if got.UserID != "u1" || got.NewEmail != "new@example.com" {
			t.Errorf("token = %+v", got)
		}
	})

	t.Run("consume missing returns sentinel", func(t *testing.T) {
		s := mk(t)
		if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrEmailChangeTokenNotFound) {
			t.Errorf("err = %v, want ErrEmailChangeTokenNotFound", err)
		}
	})

	t.Run("consume is single-use", func(t *testing.T) {
		s := mk(t)
		_ = s.Issue(ctx, &core.EmailChangeToken{Token: "t2", UserID: "u1", NewEmail: "x@e.com", ExpiresAt: time.Now().Add(time.Minute)})
		if _, err := s.Consume(ctx, "t2"); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		if _, err := s.Consume(ctx, "t2"); !errors.Is(err, core.ErrEmailChangeTokenNotFound) {
			t.Errorf("second consume err = %v, want sentinel", err)
		}
	})

	t.Run("expired token is not returned", func(t *testing.T) {
		s := mk(t)
		_ = s.Issue(ctx, &core.EmailChangeToken{Token: "t3", UserID: "u1", NewEmail: "x@e.com", ExpiresAt: time.Now().Add(-time.Second)})
		if _, err := s.Consume(ctx, "t3"); !errors.Is(err, core.ErrEmailChangeTokenNotFound) {
			t.Errorf("expired err = %v, want sentinel", err)
		}
	})
}

func TestMemoryEmailChangeStore(t *testing.T) {
	emailChangeStoreSuite(t, func(t *testing.T) core.EmailChangeStore {
		return defaultimpl.NewMemoryEmailChangeStore()
	})
}
