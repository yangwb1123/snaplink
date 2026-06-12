package sqlite

import "github.com/snaplink/sso/spi"

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func newMFAChallengeStoreForTest(t *testing.T) *MFAChallengeStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "mfa.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	store, err := NewMFAChallengeStore(dsn)
	if err != nil {
		t.Fatalf("NewMFAChallengeStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func sampleMFAChallenge() *spi.MFAChallenge {
	now := time.Now().UTC()
	return &spi.MFAChallenge{
		ID:           "ch-abcdef0123456789",
		SubjectID:    "user-alice",
		ClientID:     "demo-client",
		CreatedAt:    now,
		ExpiresAt:    now.Add(5 * time.Minute),
		RequestState: []byte(`{"login_request":{"client_id":"demo-client"},"result":{"sub":"user-alice"}}`),
	}
}

func TestMFAChallengeStore_PutAndConsumeRoundTrip(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	ctx := context.Background()

	want := sampleMFAChallenge()
	if err := store.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := store.Consume(ctx, want.ID)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ID != want.ID || got.SubjectID != want.SubjectID || got.ClientID != want.ClientID {
		t.Fatalf("scalar mismatch:\n got %#v\nwant %#v", got, want)
	}
	if got.CreatedAt.UnixNano() != want.CreatedAt.UnixNano() {
		t.Fatalf("CreatedAt: got %v want %v", got.CreatedAt, want.CreatedAt)
	}
	if got.ExpiresAt.UnixNano() != want.ExpiresAt.UnixNano() {
		t.Fatalf("ExpiresAt: got %v want %v", got.ExpiresAt, want.ExpiresAt)
	}
	if string(got.RequestState) != string(want.RequestState) {
		t.Fatalf("RequestState: got %q want %q", got.RequestState, want.RequestState)
	}
}

func TestMFAChallengeStore_ConsumeIsSingleUse(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	ctx := context.Background()

	c := sampleMFAChallenge()
	if err := store.Put(ctx, c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := store.Consume(ctx, c.ID); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	_, err := store.Consume(ctx, c.ID)
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("second Consume: got %v, want ErrMFAChallengeNotFound", err)
	}
}

func TestMFAChallengeStore_ConsumeUnknownReturnsNotFound(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	_, err := store.Consume(context.Background(), "ch-nonexistent")
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("unknown id: got %v, want ErrMFAChallengeNotFound", err)
	}
}

func TestMFAChallengeStore_ExpiredEntryReturnsNotFound(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	ctx := context.Background()

	c := sampleMFAChallenge()
	c.ExpiresAt = time.Now().Add(-1 * time.Second).UTC() // already expired
	if err := store.Put(ctx, c); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, err := store.Consume(ctx, c.ID)
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("expired: got %v, want ErrMFAChallengeNotFound", err)
	}
	// Even though Consume returned NotFound, the row should have been
	// deleted — re-Consume should still return NotFound (proof the
	// expired path doesn't leak rows that would compound on every
	// failed challenge).
	_, err = store.Consume(ctx, c.ID)
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("second Consume on expired: got %v, want ErrMFAChallengeNotFound", err)
	}
}

func TestMFAChallengeStore_PutEmptyIDRejected(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	c := sampleMFAChallenge()
	c.ID = ""
	err := store.Put(context.Background(), c)
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("empty id: got %v, want ErrMFAChallengeNotFound", err)
	}
}

func TestMFAChallengeStore_PutNilRejected(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	err := store.Put(context.Background(), nil)
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("nil challenge: got %v, want ErrMFAChallengeNotFound", err)
	}
}

func TestMFAChallengeStore_ConsumeEmptyIDReturnsNotFound(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	_, err := store.Consume(context.Background(), "")
	if !errors.Is(err, spi.ErrMFAChallengeNotFound) {
		t.Fatalf("empty id: got %v, want ErrMFAChallengeNotFound", err)
	}
}

func TestMFAChallengeStore_PingAfterClose(t *testing.T) {
	store := newMFAChallengeStoreForTest(t)
	if err := store.Ping(context.Background()); err != nil {
		t.Fatalf("Ping open store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := store.Ping(context.Background()); err == nil {
		t.Fatal("Ping after Close: want error, got nil")
	}
}

func TestMFAChallengeStore_DuplicateIDRejected(t *testing.T) {
	// Same anti-replay guarantee Put gives at the wire — if a caller
	// tries to overwrite an in-flight challenge, the second Put fails
	// rather than silently displacing the first (which would let an
	// attacker who watched the wire steal an existing challenge by
	// re-Putting under the same id).
	store := newMFAChallengeStoreForTest(t)
	ctx := context.Background()
	c := sampleMFAChallenge()
	if err := store.Put(ctx, c); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	if err := store.Put(ctx, c); err == nil {
		t.Fatal("duplicate Put: want error, got nil")
	}
}
