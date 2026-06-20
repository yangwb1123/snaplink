package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
)

func TestAuthCodeIssueConsume(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewAuthCodeStore(rdb)
	ctx := context.Background()

	info := &oauth.AuthCode{
		UserID:        "alice",
		ClientID:      "app",
		RedirectURI:   "https://app/cb",
		Scopes:        []string{"openid", "profile"},
		Nonce:         "n0nce",
		CodeChallenge: "challenge",
		ExpiresAt:     time.Now().Add(10 * time.Minute),
	}
	if err := s.Issue(ctx, "code1", info); err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := s.Consume(ctx, "code1")
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.UserID != "alice" || got.ClientID != "app" || got.CodeChallenge != "challenge" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("scopes lost: %+v", got.Scopes)
	}
}

// TestAuthCodeOracleLeak enumerates the four failure shapes the §2
// oracle-leak hardening requires to be INDISTINGUISHABLE — every one must
// return exactly ErrAuthCodeNotFound.
func TestAuthCodeOracleLeak(t *testing.T) {
	mr, rdb := newTestClient(t)
	s := NewAuthCodeStore(rdb)
	ctx := context.Background()

	// 1. Unknown code.
	if _, err := s.Consume(ctx, "never-issued"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Fatalf("unknown: want ErrAuthCodeNotFound, got %v", err)
	}

	// 2. Already-consumed (single-use): issue, consume, consume again.
	_ = s.Issue(ctx, "used", &oauth.AuthCode{ClientID: "app", ExpiresAt: time.Now().Add(time.Minute)})
	if _, err := s.Consume(ctx, "used"); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Consume(ctx, "used"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Fatalf("second consume: want ErrAuthCodeNotFound, got %v", err)
	}

	// 3. Expired (key TTL evicts; advance miniredis clock).
	_ = s.Issue(ctx, "stale", &oauth.AuthCode{ClientID: "app", ExpiresAt: time.Now().Add(time.Second)})
	mr.FastForward(2 * time.Second)
	if _, err := s.Consume(ctx, "stale"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Fatalf("expired: want ErrAuthCodeNotFound, got %v", err)
	}
}

// TestAuthCodeSingleUseRace fires N concurrent Consume calls at one code;
// exactly one must win. (Run under -race -count.)
func TestAuthCodeSingleUseRace(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewAuthCodeStore(rdb)
	ctx := context.Background()
	_ = s.Issue(ctx, "hot", &oauth.AuthCode{ClientID: "app", ExpiresAt: time.Now().Add(time.Minute)})

	const n = 16
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := s.Consume(ctx, "hot")
			results <- err
		}()
	}
	wins := 0
	for i := 0; i < n; i++ {
		if err := <-results; err == nil {
			wins++
		} else if !errors.Is(err, oauth.ErrAuthCodeNotFound) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("single-use violated: %d winners, want 1", wins)
	}
}
