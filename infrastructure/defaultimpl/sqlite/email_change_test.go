package sqlite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/shared/core"
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

func TestSQLiteEmailChangeStore_RevokeByUser(t *testing.T) {
	s := newEmailChangeStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "a1", UserID: "alice", NewEmail: "a@n.com", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "b1", UserID: "bob", NewEmail: "b@n.com", ExpiresAt: exp})

	n, err := s.RevokeByUser(ctx, "alice")
	if err != nil || n != 1 {
		t.Fatalf("RevokeByUser = %d, %v; want 1, nil", n, err)
	}
	if _, err := s.Consume(ctx, "a1"); !errors.Is(err, core.ErrEmailChangeTokenNotFound) {
		t.Errorf("alice token survived revoke: %v", err)
	}
	if _, err := s.Consume(ctx, "b1"); err != nil {
		t.Errorf("bob token wrongly revoked: %v", err)
	}
}

func TestSQLiteEmailChangeStore_ListByUser(t *testing.T) {
	s := newEmailChangeStore(t)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "a1", UserID: "alice", NewEmail: "a@n.com", ExpiresAt: exp})
	_ = s.Issue(ctx, &core.EmailChangeToken{Token: "b1", UserID: "bob", NewEmail: "b@n.com", ExpiresAt: exp})

	got, err := s.ListByUser(ctx, "alice")
	if err != nil || len(got) != 1 {
		t.Fatalf("ListByUser = %d, %v; want 1", len(got), err)
	}
	if got[0].NewEmail != "a@n.com" {
		t.Errorf("new_email = %q", got[0].NewEmail)
	}
}
