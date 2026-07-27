package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestTempTokenStore_IssueConsumeSingleUse(t *testing.T) {
	t.Parallel()
	_, rdb := newTestClient(t)
	s := NewTempTokenStore(rdb)
	ctx := context.Background()
	sub := &core.Subject{ID: "user-42", Provider: "password"}

	if err := s.Issue(ctx, "tt-1", sub, time.Minute); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "tt-1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got == nil || got.ID != "user-42" {
		t.Fatalf("subject mismatch: %+v", got)
	}
	// Single-use: second consume fails.
	if _, err := s.Consume(ctx, "tt-1"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("re-consume should be ErrCodeInvalid, got %v", err)
	}
}

func TestTempTokenStore_UnknownAndExpired(t *testing.T) {
	t.Parallel()
	mr, rdb := newTestClient(t)
	s := NewTempTokenStore(rdb)
	ctx := context.Background()

	if _, err := s.Consume(ctx, "never"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("unknown token should be ErrCodeInvalid, got %v", err)
	}
	if err := s.Issue(ctx, "tt-2", &core.Subject{ID: "u"}, time.Minute); err != nil {
		t.Fatalf("issue: %v", err)
	}
	mr.FastForward(time.Minute + time.Second)
	if _, err := s.Consume(ctx, "tt-2"); !errors.Is(err, authenticators.ErrCodeInvalid) {
		t.Fatalf("expired token should be ErrCodeInvalid, got %v", err)
	}
}
