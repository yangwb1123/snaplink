package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/shared/spi"
)

func TestMemoryMFAChallengeStore_PutConsume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryMFAChallengeStore()
	ch := &spi.MFAChallenge{
		ID:           "ch-1",
		SubjectID:    "u",
		ClientID:     "c",
		ExpiresAt:    time.Now().Add(time.Minute),
		RequestState: []byte(`{"resume":true}`),
	}
	if err := s.Put(ctx, ch); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// Defensive copy: mutating the caller's struct after Put must not
	// poison the stored entry.
	ch.SubjectID = "TAMPERED"

	got, err := s.Consume(ctx, "ch-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.SubjectID != "u" || got.ClientID != "c" {
		t.Errorf("consumed = %+v (stored entry aliased caller?)", got)
	}
}

func TestMemoryMFAChallengeStore_SingleUse(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryMFAChallengeStore()
	_ = s.Put(ctx, &spi.MFAChallenge{ID: "ch", ExpiresAt: time.Now().Add(time.Minute)})
	if _, err := s.Consume(ctx, "ch"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Consume(ctx, "ch"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("second consume = %v, want ErrMFAChallengeNotFound", err)
	}
}

func TestMemoryMFAChallengeStore_NotFoundShapes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryMFAChallengeStore()

	if err := s.Put(ctx, nil); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("Put(nil) = %v", err)
	}
	if err := s.Put(ctx, &spi.MFAChallenge{ID: ""}); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("Put(empty id) = %v", err)
	}
	if _, err := s.Consume(ctx, ""); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("Consume(empty) = %v", err)
	}
	if _, err := s.Consume(ctx, "unknown"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("Consume(unknown) = %v", err)
	}
}

func TestMemoryMFAChallengeStore_ExpiredCollapses(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := defaultimpl.NewMemoryMFAChallengeStore()
	_ = s.Put(ctx, &spi.MFAChallenge{ID: "ch", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.Consume(ctx, "ch"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("expired consume = %v, want ErrMFAChallengeNotFound", err)
	}
	// Even an expired entry is removed by the consume attempt (single-use).
	if _, err := s.Consume(ctx, "ch"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Errorf("re-consume of expired = %v", err)
	}
}
