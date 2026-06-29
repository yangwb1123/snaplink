package defaultimpl_test

import "github.com/snaplink/sso/protocols/oauth"

import (
	"context"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
)

func TestMemoryAuthCodeStore_RoundTrip(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryAuthCodeStore()
	in := &oauth.AuthCode{
		UserID:      "u-1",
		ClientID:    "web",
		RedirectURI: "https://app/cb",
		Scopes:      []string{"openid", "profile"},
		Nonce:       "n1",
		Provider:    "password",
		Attributes:  map[string]string{"role": "admin"},
		ExpiresAt:   time.Now().Add(time.Minute),
	}
	if err := s.Issue(context.Background(), "code-1", in); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	out, err := s.Consume(context.Background(), "code-1")
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if out.UserID != "u-1" || out.ClientID != "web" || out.RedirectURI != "https://app/cb" {
		t.Errorf("payload mismatch: %+v", out)
	}
	if len(out.Scopes) != 2 || out.Attributes["role"] != "admin" {
		t.Errorf("slice/map round-trip failed: %+v", out)
	}
	if out.Nonce != "n1" || out.Provider != "password" {
		t.Errorf("string fields lost: %+v", out)
	}
}

func TestMemoryAuthCodeStore_SingleUse(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryAuthCodeStore()
	_ = s.Issue(context.Background(), "c", &oauth.AuthCode{ExpiresAt: time.Now().Add(time.Minute)})
	if _, err := s.Consume(context.Background(), "c"); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := s.Consume(context.Background(), "c"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("second Consume err = %v, want oauth.ErrAuthCodeNotFound", err)
	}
}

func TestMemoryAuthCodeStore_RejectsEmptyArgs(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryAuthCodeStore()
	if err := s.Issue(context.Background(), "", &oauth.AuthCode{}); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("empty code Issue err = %v", err)
	}
	if err := s.Issue(context.Background(), "c", nil); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("nil info Issue err = %v", err)
	}
}

func TestMemoryAuthCodeStore_UnknownCodeReturnsSentinel(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryAuthCodeStore()
	if _, err := s.Consume(context.Background(), "ghost"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("err = %v, want oauth.ErrAuthCodeNotFound", err)
	}
}

func TestMemoryAuthCodeStore_ExpiredCodeIndistinguishableFromMissing(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryAuthCodeStore()
	_ = s.Issue(context.Background(), "stale", &oauth.AuthCode{
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if _, err := s.Consume(context.Background(), "stale"); !errors.Is(err, oauth.ErrAuthCodeNotFound) {
		t.Errorf("err = %v, want oauth.ErrAuthCodeNotFound", err)
	}
}

func TestMemoryAuthCodeStore_DoesNotAliasCallerSlices(t *testing.T) {
	t.Parallel()
	// Caller-supplied Scopes / Attributes must be copied at Issue time so
	// later mutation of the caller's structures isn't visible at Consume.
	s := defaultimpl.NewMemoryAuthCodeStore()
	scopes := []string{"a"}
	attrs := map[string]string{"k": "v"}
	_ = s.Issue(context.Background(), "c", &oauth.AuthCode{
		Scopes:     scopes,
		Attributes: attrs,
		ExpiresAt:  time.Now().Add(time.Minute),
	})
	scopes[0] = "MUTATED"
	attrs["k"] = "MUTATED"

	out, _ := s.Consume(context.Background(), "c")
	if out.Scopes[0] != "a" {
		t.Errorf("scopes aliased caller — saw %q after caller mutation", out.Scopes[0])
	}
	if out.Attributes["k"] != "v" {
		t.Errorf("attributes aliased caller — saw %q after caller mutation", out.Attributes["k"])
	}
}

func TestMemoryAuthCodeStore_Concurrent(t *testing.T) {
	t.Parallel()
	// Many goroutines issuing + consuming distinct codes must not race.
	s := defaultimpl.NewMemoryAuthCodeStore()
	var wg sync.WaitGroup
	const n = 100
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			code := "c-" + base64.RawURLEncoding.EncodeToString([]byte{byte(i)})
			_ = s.Issue(context.Background(), code, &oauth.AuthCode{
				UserID: "u", ExpiresAt: time.Now().Add(time.Minute),
			})
			out, err := s.Consume(context.Background(), code)
			if err != nil || out == nil {
				t.Errorf("goroutine %d: err=%v out=%v", i, err, out)
			}
		}(i)
	}
	wg.Wait()
}

func TestGenerateAuthCode_LengthAndAlphabet(t *testing.T) {
	t.Parallel()
	c, err := defaultimpl.GenerateAuthCode()
	if err != nil {
		t.Fatalf("GenerateAuthCode: %v", err)
	}
	// 32 bytes → base64url RawEncoding length = ceil(32*4/3) = 43.
	if len(c) != 43 {
		t.Errorf("code length = %d, want 43", len(c))
	}
	if _, err := base64.RawURLEncoding.DecodeString(c); err != nil {
		t.Errorf("not base64url: %v", err)
	}
}

func TestAuthCode_IsExpired(t *testing.T) {
	t.Parallel()
	past := &oauth.AuthCode{ExpiresAt: time.Now().Add(-time.Hour)}
	future := &oauth.AuthCode{ExpiresAt: time.Now().Add(time.Hour)}
	if !past.IsExpired() {
		t.Error("past timestamp should be expired")
	}
	if future.IsExpired() {
		t.Error("future timestamp should not be expired")
	}
}
