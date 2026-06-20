package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/spi"
)

func newMFAChallenge(id string, ttl time.Duration) *spi.MFAChallenge {
	now := time.Now()
	return &spi.MFAChallenge{
		ID:           id,
		SubjectID:    "user-1",
		ClientID:     "client-1",
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		RequestState: []byte(`{"resume":"state"}`),
	}
}

func TestMFAChallengeStore_PutConsumeRoundTrip(t *testing.T) {
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewMFAChallengeStore(rdb)

	c := newMFAChallenge("chal-1", spi.DefaultMFAChallengeTTL)
	if err := s.Put(ctx, c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Consume(ctx, "chal-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.SubjectID != "user-1" || got.ClientID != "client-1" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if string(got.RequestState) != `{"resume":"state"}` {
		t.Fatalf("request_state not preserved: %q", got.RequestState)
	}
}

func TestMFAChallengeStore_SingleUse(t *testing.T) {
	_, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewMFAChallengeStore(rdb)

	if err := s.Put(ctx, newMFAChallenge("chal-su", spi.DefaultMFAChallengeTTL)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := s.Consume(ctx, "chal-su"); err != nil {
		t.Fatalf("first Consume must succeed: %v", err)
	}
	// Second Consume of the same challenge finds nothing (GETDEL already
	// removed it) — single-use, collapsed to the mfa_invalid sentinel.
	if _, err := s.Consume(ctx, "chal-su"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("replay Consume must be ErrMFAChallengeNotFound, got %v", err)
	}
}

func TestMFAChallengeStore_OracleLeak(t *testing.T) {
	mr, rdb := newTestClient(t)
	ctx := context.Background()
	s := NewMFAChallengeStore(rdb)

	// Unknown id.
	if _, err := s.Consume(ctx, "unknown"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("unknown id must be ErrMFAChallengeNotFound, got %v", err)
	}
	// Empty id.
	if _, err := s.Consume(ctx, ""); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("empty id must be ErrMFAChallengeNotFound, got %v", err)
	}
	// Expired id: same sentinel as unknown + consumed.
	if err := s.Put(ctx, newMFAChallenge("chal-exp", 30*time.Second)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	mr.FastForward(31 * time.Second)
	if _, err := s.Consume(ctx, "chal-exp"); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("expired id must collapse to ErrMFAChallengeNotFound, got %v", err)
	}
}

func TestMFAChallengeStore_PutRejectsEmptyID(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewMFAChallengeStore(rdb)
	c := newMFAChallenge("", spi.DefaultMFAChallengeTTL)
	if err := s.Put(context.Background(), c); !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("Put with empty ID must reject, got %v", err)
	}
}

func TestMFAChallengeStore_Ping(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewMFAChallengeStore(rdb)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping live: %v", err)
	}
	var nilStore *MFAChallengeStore
	if err := nilStore.Ping(context.Background()); err == nil {
		t.Fatal("Ping on a nil store must error, not panic")
	}
}
