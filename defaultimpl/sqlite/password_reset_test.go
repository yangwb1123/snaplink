package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	sqlitestores "github.com/snaplink/sso/defaultimpl/sqlite"
)

func newPasswordResetStore(t *testing.T) *sqlitestores.PasswordResetStore {
	t.Helper()
	dsn := "file:pwreset_" + t.Name() + "?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
	s, err := sqlitestores.NewPasswordResetStore(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLitePasswordResetStore_IssueConsumeSingleUse(t *testing.T) {
	s := newPasswordResetStore(t)
	ctx := context.Background()
	if err := s.Issue(ctx, &core.PasswordResetToken{Token: "t1", UserID: "u1", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "t1")
	if err != nil || got.UserID != "u1" {
		t.Fatalf("consume = %+v, %v; want UserID u1", got, err)
	}
	// Single-use.
	if _, err := s.Consume(ctx, "t1"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Errorf("second consume err = %v, want ErrResetTokenNotFound", err)
	}
}

func TestSQLitePasswordResetStore_MissingAndExpired(t *testing.T) {
	s := newPasswordResetStore(t)
	ctx := context.Background()
	if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Errorf("missing err = %v, want ErrResetTokenNotFound", err)
	}
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "exp", UserID: "u1", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.Consume(ctx, "exp"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Errorf("expired err = %v, want ErrResetTokenNotFound", err)
	}
}

func TestSQLitePasswordResetStore_RevokeByUser(t *testing.T) {
	s := newPasswordResetStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "a1", UserID: "alice", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "a2", UserID: "alice", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "b1", UserID: "bob", ExpiresAt: exp})

	n, err := s.RevokeByUser(ctx, "alice")
	if err != nil || n != 2 {
		t.Fatalf("RevokeByUser = %d, %v; want 2, nil", n, err)
	}
	if _, err := s.Consume(ctx, "a1"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Errorf("alice token a1 survived revoke: %v", err)
	}
	if _, err := s.Consume(ctx, "b1"); err != nil {
		t.Errorf("bob token wrongly revoked: %v", err)
	}
	// Idempotent.
	if n, _ := s.RevokeByUser(ctx, "alice"); n != 0 {
		t.Errorf("second RevokeByUser = %d, want 0", n)
	}
}

func TestSQLitePasswordResetStore_ListByUser(t *testing.T) {
	s := newPasswordResetStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "a1", UserID: "alice", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "a2", UserID: "alice", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.PasswordResetToken{Token: "b1", UserID: "bob", ExpiresAt: exp})

	got, err := s.ListByUser(ctx, "alice")
	if err != nil || len(got) != 2 {
		t.Fatalf("ListByUser = %d tokens, %v; want 2", len(got), err)
	}
	for _, tk := range got {
		if tk.UserID != "alice" {
			t.Errorf("token for wrong user: %+v", tk)
		}
	}
	if other, _ := s.ListByUser(ctx, "carol"); len(other) != 0 {
		t.Errorf("carol should have no tokens, got %d", len(other))
	}
}
