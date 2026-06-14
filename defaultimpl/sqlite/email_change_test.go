package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	sqlitestores "github.com/snaplink/sso/defaultimpl/sqlite"
)

func newEmailChangeStore(t *testing.T) *sqlitestores.EmailChangeStore {
	t.Helper()
	dsn := "file:emchg_" + t.Name() + "?mode=memory&cache=shared&_pragma=busy_timeout(5000)"
	s, err := sqlitestores.NewEmailChangeStore(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteEmailChangeStore_IssueConsumeSingleUse(t *testing.T) {
	s := newEmailChangeStore(t)
	ctx := context.Background()
	if err := s.Issue(ctx, &core.EmailChangeToken{Token: "t1", UserID: "u1", NewEmail: "n@e.com", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "t1")
	if err != nil || got.NewEmail != "n@e.com" {
		t.Fatalf("consume = %+v, %v", got, err)
	}
	if _, err := s.Consume(ctx, "t1"); !errors.Is(err, core.ErrEmailChangeTokenNotFound) {
		t.Errorf("second consume err = %v, want sentinel", err)
	}
}

func TestSQLiteEmailChangeStore_MissingAndExpired(t *testing.T) {
	s := newEmailChangeStore(t)
	ctx := context.Background()
	if _, err := s.Consume(ctx, "nope"); !errors.Is(err, core.ErrEmailChangeTokenNotFound) {
		t.Errorf("missing err = %v, want sentinel", err)
	}
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "exp", UserID: "u1", NewEmail: "n@e.com", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.Consume(ctx, "exp"); !errors.Is(err, core.ErrEmailChangeTokenNotFound) {
		t.Errorf("expired err = %v, want sentinel", err)
	}
}
