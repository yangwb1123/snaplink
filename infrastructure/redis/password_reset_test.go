package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

func TestPasswordResetIssueConsume(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewPasswordResetStore(rdb)
	ctx := context.Background()

	rt := &core.PasswordResetToken{
		Token:     "tok-abc",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := s.Issue(ctx, rt); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "tok-abc")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.Token != "tok-abc" || got.UserID != "user-1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestPasswordResetOracleLeak enumerates the indistinguishable failures — each
// must return exactly core.ErrResetTokenNotFound (single oracle-safe response).
func TestPasswordResetOracleLeak(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	s := NewPasswordResetStore(rdb)
	ctx := context.Background()

	// 1. Unknown / never-issued token.
	if _, err := s.Consume(ctx, "never"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Fatalf("unknown: want ErrResetTokenNotFound, got %v", err)
	}

	// 2. Already-consumed (single-use).
	if err := s.Issue(ctx, &core.PasswordResetToken{Token: "once", UserID: "u", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := s.Consume(ctx, "once"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Consume(ctx, "once"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Fatalf("second consume: want ErrResetTokenNotFound, got %v", err)
	}

	// 3. Expired (TTL elapses -> key evicted).
	if err := s.Issue(ctx, &core.PasswordResetToken{Token: "exp", UserID: "u", ExpiresAt: time.Now().Add(time.Second)}); err != nil {
		t.Fatalf("issue: %v", err)
	}
	mr.FastForward(2 * time.Second)
	if _, err := s.Consume(ctx, "exp"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Fatalf("expired: want ErrResetTokenNotFound, got %v", err)
	}
}

// TestPasswordResetIssueAlreadyExpired confirms an already-expired token is a
// no-op at Issue (non-positive TTL) and unconsumable afterward.
func TestPasswordResetIssueAlreadyExpired(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewPasswordResetStore(rdb)
	ctx := context.Background()

	if err := s.Issue(ctx, &core.PasswordResetToken{Token: "stale", UserID: "u", ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatalf("issue already-expired: %v", err)
	}
	if _, err := s.Consume(ctx, "stale"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Fatalf("stale consume: want ErrResetTokenNotFound, got %v", err)
	}
}

// TestPasswordResetSingleUseRace proves GETDEL gives exactly one winner under
// concurrent consumption of the same token.
func TestPasswordResetSingleUseRace(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewPasswordResetStore(rdb)
	ctx := context.Background()
	if err := s.Issue(ctx, &core.PasswordResetToken{Token: "race", UserID: "u", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	const n = 16
	results := make(chan error, n)
	for range n {
		go func() {
			_, err := s.Consume(ctx, "race")
			results <- err
		}()
	}
	wins := 0
	for range n {
		if err := <-results; err == nil {
			wins++
		} else if !errors.Is(err, core.ErrResetTokenNotFound) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("single-use violated: %d winners, want 1", wins)
	}
}

func TestPasswordResetRevokeAndListByUser(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewPasswordResetStore(rdb)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)

	// Two tokens for user-1, one for user-2.
	for _, tok := range []string{"r1", "r2"} {
		if err := s.Issue(ctx, &core.PasswordResetToken{Token: tok, UserID: "user-1", ExpiresAt: exp}); err != nil {
			t.Fatalf("issue %s: %v", tok, err)
		}
	}
	if err := s.Issue(ctx, &core.PasswordResetToken{Token: "r3", UserID: "user-2", ExpiresAt: exp}); err != nil {
		t.Fatalf("issue r3: %v", err)
	}

	got, err := s.ListByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("ListByUser(user-1) = %d tokens, want 2", len(got))
	}

	n, err := s.RevokeByUser(ctx, "user-1")
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeByUser(user-1) removed %d, want 2", n)
	}
	// Revoked tokens no longer consumable; the other user's token survives.
	if _, err := s.Consume(ctx, "r1"); !errors.Is(err, core.ErrResetTokenNotFound) {
		t.Fatalf("r1 should be revoked, got %v", err)
	}
	if _, err := s.Consume(ctx, "r3"); err != nil {
		t.Fatalf("r3 (other user) should survive, got %v", err)
	}
	// Idempotent: revoking again removes nothing.
	if n, _ := s.RevokeByUser(ctx, "user-1"); n != 0 {
		t.Fatalf("second revoke removed %d, want 0", n)
	}
}
