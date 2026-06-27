package redis

import (
	"context"
	"testing"
	"time"
)

func TestRedisRefreshGraceStore_RememberThenLookupReplays(t *testing.T) {
	mr, rdb := newTestClient(t)
	s := NewRefreshGraceStore(rdb, time.Minute)
	now := time.Now()

	resp := map[string]any{"access_token": "AT", "refresh_token": "RT2", "token_type": "Bearer"}
	s.Remember("consumed-token", resp, now)

	got, ok := s.Lookup("consumed-token", now)
	if !ok {
		t.Fatal("expected grace hit after Remember (cluster-shared replay)")
	}
	if got["access_token"] != "AT" || got["refresh_token"] != "RT2" {
		t.Fatalf("successor mismatch: %v", got)
	}
	// Idempotent: a second double-submit within the window still replays.
	if _, ok := s.Lookup("consumed-token", now); !ok {
		t.Fatal("expected second within-window lookup to also replay")
	}

	// Post-window (key TTL expired) MUST fail closed so the caller proceeds to
	// family-reuse detection — BCP 4.13 preserved.
	mr.FastForward(time.Minute + time.Second)
	if _, ok := s.Lookup("consumed-token", now); ok {
		t.Fatal("expected miss after the grace window (fail-closed)")
	}
}

func TestRedisRefreshGraceStore_UnrememberedTokenMisses(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshGraceStore(rdb, time.Minute)
	if _, ok := s.Lookup("never-rotated", time.Now()); ok {
		t.Fatal("a token never remembered must miss (no replay -> reuse path)")
	}
}

func TestRedisRefreshGraceStore_WindowZeroIsNoop(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshGraceStore(rdb, 0)
	s.Remember("tok", map[string]any{"a": "b"}, time.Now())
	if _, ok := s.Lookup("tok", time.Now()); ok {
		t.Fatal("window<=0 must not remember anything")
	}
}

func TestRedisRefreshGraceStore_Ping(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewRefreshGraceStore(rdb, time.Minute)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("ping live store: %v", err)
	}
	var nilStore *RefreshGraceStore
	if err := nilStore.Ping(context.Background()); err == nil {
		t.Fatal("nil store Ping should error")
	}
}
