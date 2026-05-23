package defaultimpl_test

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/defaultimpl"
)

func TestMemoryRefreshTokenStore_RoundTrip(t *testing.T) {
	s := defaultimpl.NewMemoryRefreshTokenStore()
	now := time.Now()
	in := &oauth.RefreshToken{
		UserID:     "u-1",
		ClientID:   "web",
		Provider:   "password",
		Scopes:     []string{"openid", "profile"},
		Attributes: map[string]string{"role": "admin"},
		IssuedAt:   now,
		ExpiresAt:  now.Add(time.Hour),
	}
	if err := s.Issue(context.Background(), "tok-1", in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := s.Consume(context.Background(), "tok-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if out.UserID != "u-1" || out.ClientID != "web" || out.Provider != "password" {
		t.Errorf("payload mismatch: %+v", out)
	}
	if len(out.Scopes) != 2 || out.Attributes["role"] != "admin" {
		t.Errorf("slice/map round-trip failed: %+v", out)
	}
	if !out.IssuedAt.Equal(now) || !out.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("timestamps lost: %+v", out)
	}
}

func TestMemoryRefreshTokenStore_SingleUseRotation(t *testing.T) {
	// Consumption deletes — replay is the canonical rotation-reuse
	// detection signal even before family-revocation is implemented.
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(context.Background(), "t", &oauth.RefreshToken{ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := s.Consume(context.Background(), "t"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := s.Consume(context.Background(), "t"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("second Consume err = %v, want oauth.ErrRefreshTokenNotFound", err)
	}
}

func TestMemoryRefreshTokenStore_RejectsEmptyArgs(t *testing.T) {
	s := defaultimpl.NewMemoryRefreshTokenStore()
	if err := s.Issue(context.Background(), "", &oauth.RefreshToken{}); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("empty token Issue err = %v", err)
	}
	if err := s.Issue(context.Background(), "t", nil); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("nil info Issue err = %v", err)
	}
}

func TestMemoryRefreshTokenStore_UnknownTokenReturnsSentinel(t *testing.T) {
	s := defaultimpl.NewMemoryRefreshTokenStore()
	if _, err := s.Consume(context.Background(), "ghost"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("err = %v, want oauth.ErrRefreshTokenNotFound", err)
	}
}

func TestMemoryRefreshTokenStore_ExpiredTokenIndistinguishableFromMissing(t *testing.T) {
	s := defaultimpl.NewMemoryRefreshTokenStore()
	_ = s.Issue(context.Background(), "stale", &oauth.RefreshToken{
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if _, err := s.Consume(context.Background(), "stale"); !errors.Is(err, oauth.ErrRefreshTokenNotFound) {
		t.Errorf("err = %v, want oauth.ErrRefreshTokenNotFound", err)
	}
}

func TestMemoryRefreshTokenStore_DoesNotAliasCallerSlices(t *testing.T) {
	// Caller-supplied Scopes / Attributes must be copied at Issue time so
	// later mutation of the caller's structures isn't visible at Consume.
	s := defaultimpl.NewMemoryRefreshTokenStore()
	scopes := []string{"a"}
	attrs := map[string]string{"k": "v"}
	_ = s.Issue(context.Background(), "t", &oauth.RefreshToken{
		Scopes:     scopes,
		Attributes: attrs,
		ExpiresAt:  time.Now().Add(time.Hour),
	})
	scopes[0] = "MUTATED"
	attrs["k"] = "MUTATED"

	out, _ := s.Consume(context.Background(), "t")
	if out.Scopes[0] != "a" {
		t.Errorf("scopes aliased caller — saw %q after caller mutation", out.Scopes[0])
	}
	if out.Attributes["k"] != "v" {
		t.Errorf("attributes aliased caller — saw %q after caller mutation", out.Attributes["k"])
	}
}

func TestMemoryRefreshTokenStore_Concurrent(t *testing.T) {
	// Many goroutines issuing + consuming distinct tokens must not race.
	s := defaultimpl.NewMemoryRefreshTokenStore()
	var wg sync.WaitGroup
	const n = 100
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			tok := "t-" + base64.RawURLEncoding.EncodeToString([]byte{byte(i)})
			_ = s.Issue(context.Background(), tok, &oauth.RefreshToken{
				UserID: "u", ExpiresAt: time.Now().Add(time.Hour),
			})
			out, err := s.Consume(context.Background(), tok)
			if err != nil || out == nil {
				t.Errorf("goroutine %d: err=%v out=%v", i, err, out)
			}
		}(i)
	}
	wg.Wait()
}

func TestGenerateRefreshToken_LengthAndAlphabet(t *testing.T) {
	tok, err := defaultimpl.GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken: %v", err)
	}
	// 32 bytes → base64url RawEncoding length = ceil(32*4/3) = 43.
	if len(tok) != 43 {
		t.Errorf("token length = %d, want 43", len(tok))
	}
	if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
		t.Errorf("not base64url: %v", err)
	}
}

func TestRefreshToken_IsExpired(t *testing.T) {
	past := &oauth.RefreshToken{ExpiresAt: time.Now().Add(-time.Hour)}
	future := &oauth.RefreshToken{ExpiresAt: time.Now().Add(time.Hour)}
	if !past.IsExpired() {
		t.Error("past timestamp should be expired")
	}
	if future.IsExpired() {
		t.Error("future timestamp should not be expired")
	}
}
