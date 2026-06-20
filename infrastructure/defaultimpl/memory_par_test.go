package defaultimpl_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/protocols/oauth"
)

func TestMemoryPARStore_IssueConsume(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryPARStore()

	req := &oauth.PARRequest{
		ClientID:     "client-a",
		ResponseType: "code",
		RedirectURI:  "https://rp.example/cb",
		Scope:        []string{"openid", "profile"},
		State:        "st",
		Nonce:        "nn",
		ExpiresAt:    time.Now().Add(time.Minute),
	}
	uri, err := s.Issue(ctx, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if !strings.HasPrefix(uri, oauth.PARURIPrefix) {
		t.Fatalf("request_uri = %q, want %q prefix", uri, oauth.PARURIPrefix)
	}

	// Defensive-copy check: mutating the caller's slice after Issue must
	// not be visible at Consume.
	req.Scope[0] = "TAMPERED"

	got, err := s.Consume(ctx, uri)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got.ClientID != "client-a" || got.State != "st" {
		t.Errorf("consumed = %+v", got)
	}
	if got.Scope[0] != "openid" {
		t.Errorf("stored scope aliased the caller's slice: %v", got.Scope)
	}
}

func TestMemoryPARStore_SingleUse(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryPARStore()
	uri, _ := s.Issue(ctx, &oauth.PARRequest{ClientID: "c", ExpiresAt: time.Now().Add(time.Minute)})
	if _, err := s.Consume(ctx, uri); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if _, err := s.Consume(ctx, uri); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Errorf("second consume = %v, want ErrPARNotFound", err)
	}
}

func TestMemoryPARStore_NilRequestRejected(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryPARStore()
	if _, err := s.Issue(ctx, nil); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Errorf("Issue(nil) = %v, want ErrPARNotFound", err)
	}
}

func TestMemoryPARStore_UnknownAndExpired(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryPARStore()
	if _, err := s.Consume(ctx, "urn:ietf:params:oauth:request_uri:nope"); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Errorf("unknown consume = %v", err)
	}
	uri, _ := s.Issue(ctx, &oauth.PARRequest{ClientID: "c", ExpiresAt: time.Now().Add(-time.Second)})
	if _, err := s.Consume(ctx, uri); !errors.Is(err, oauth.ErrPARNotFound) {
		t.Errorf("expired consume = %v, want ErrPARNotFound", err)
	}
}

func TestGeneratePARToken(t *testing.T) {
	a, err := defaultimpl.GeneratePARToken()
	if err != nil {
		t.Fatalf("GeneratePARToken: %v", err)
	}
	b, _ := defaultimpl.GeneratePARToken()
	if a == "" || a == b {
		t.Errorf("tokens not random/unique: %q %q", a, b)
	}
}
