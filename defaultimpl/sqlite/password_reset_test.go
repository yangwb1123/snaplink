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
