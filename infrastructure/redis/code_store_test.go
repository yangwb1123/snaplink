package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
)

func TestCodeStore_SaveVerifySingleUse(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()

	if err := s.Save(ctx, "phone:+15551234", "123456", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := s.Verify(ctx, "phone:+15551234", "123456"); err != nil {
		t.Fatalf("verify correct code: %v", err)
	}
	// Single-use: the correct code is consumed.
	if err := s.Verify(ctx, "phone:+15551234", "123456"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("re-verify should be ErrCodeInvalid, got %v", err)
	}
}

func TestCodeStore_WrongCodeIsRetryable(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()

	if err := s.Save(ctx, "email:a@b.c", "999000", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	// A wrong attempt fails but MUST NOT consume the code (typo retry).
	if err := s.Verify(ctx, "email:a@b.c", "111111"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("wrong code should be ErrCodeInvalid, got %v", err)
	}
	if err := s.Verify(ctx, "email:a@b.c", "999000"); err != nil {
		t.Fatalf("correct code after a typo should still verify, got %v", err)
	}
}

func TestCodeStore_UnknownAndExpired(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	s := NewCodeStore(rdb)
	ctx := context.Background()

	if err := s.Verify(ctx, "never", "000000"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("unknown key should be ErrCodeInvalid, got %v", err)
	}

	if err := s.Save(ctx, "k", "424242", time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	mr.FastForward(time.Minute + time.Second)
	if err := s.Verify(ctx, "k", "424242"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("expired code should be ErrCodeInvalid, got %v", err)
	}
}
