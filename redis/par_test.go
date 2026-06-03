package redis

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/oauth"
)

func TestPARIssueConsume(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPARStore(rdb)
	ctx := context.Background()

	uri, err := s.Issue(ctx, &oauth.PARRequest{
		ClientID:     "app",
		ResponseType: "code",
		RedirectURI:  "https://app/cb",
		Scope:        []string{"openid"},
		State:        "xyz",
		ExpiresAt:    time.Now().Add(oauth.DefaultPARTTL),
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.HasPrefix(uri, oauth.PARURIPrefix) {
		t.Fatalf("bad request_uri prefix: %q", uri)
	}
	got, err := s.Consume(ctx, uri)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if got.ClientID != "app" || got.State != "xyz" || got.ResponseType != "code" {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}

// TestPAROracleLeak enumerates the §2 indistinguishable failures — each
// must return exactly ErrPARNotFound.
func TestPAROracleLeak(t *testing.T) {
	mr, rdb := newTestClient(t)
	s := NewPARStore(rdb)
	ctx := context.Background()

	// 1. Unknown / never-issued request_uri.
	if _, err := s.Consume(ctx, oauth.PARURIPrefix+"bogus"); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Fatalf("unknown: want ErrPARNotFound, got %v", err)
	}

	// 2. Already-consumed (single-use).
	uri, _ := s.Issue(ctx, &oauth.PARRequest{ClientID: "app", ExpiresAt: time.Now().Add(time.Minute)})
	if _, err := s.Consume(ctx, uri); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Consume(ctx, uri); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Fatalf("second consume: want ErrPARNotFound, got %v", err)
	}

	// 3. Expired.
	uri2, _ := s.Issue(ctx, &oauth.PARRequest{ClientID: "app", ExpiresAt: time.Now().Add(time.Second)})
	mr.FastForward(2 * time.Second)
	if _, err := s.Consume(ctx, uri2); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Fatalf("expired: want ErrPARNotFound, got %v", err)
	}
}

func TestPARSingleUseRace(t *testing.T) {
	_, rdb := newTestClient(t)
	s := NewPARStore(rdb)
	ctx := context.Background()
	uri, _ := s.Issue(ctx, &oauth.PARRequest{ClientID: "app", ExpiresAt: time.Now().Add(time.Minute)})

	const n = 16
	results := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := s.Consume(ctx, uri)
			results <- err
		}()
	}
	wins := 0
	for i := 0; i < n; i++ {
		if err := <-results; err == nil {
			wins++
		} else if !errors.Is(err, oauth.ErrPARNotFound) {
			t.Errorf("unexpected error: %v", err)
		}
	}
	if wins != 1 {
		t.Fatalf("single-use violated: %d winners, want 1", wins)
	}
}
