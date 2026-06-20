package authenticators

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/interfaces/sso"
)

func TestTOTP_RFC6238Vectors(t *testing.T) {
	// RFC 6238 Appendix B test vectors. We re-derive the HMAC-SHA1
	// 6-digit truncations from the spec's sample key ("12345678901234567890")
	// at known times.
	secret := []byte("12345678901234567890")
	cases := []struct {
		ts   int64
		want string
	}{
		// SHA-1 column from RFC 6238 Table 1, 6-digit truncated.
		{59, "94287082"}, // 8-digit per spec
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		// Spec table is 8-digit; we hardcode 6-digit. Derive last 6 chars.
		got8 := hotp(secret, c.ts/30, 8)
		if got8 != c.want {
			t.Errorf("hotp(t=%d, 8d) = %q want %q", c.ts, got8, c.want)
		}
		// Confirm 6-digit matches the last 6 of the 8-digit value.
		got6 := hotp(secret, c.ts/30, 6)
		if got6 != c.want[2:] {
			t.Errorf("hotp(t=%d, 6d) = %q want %q (last 6 of %q)", c.ts, got6, c.want[2:], c.want)
		}
	}
}

func TestTOTPAuthenticator_HappyPath(t *testing.T) {
	store := NewMemoryTOTPStore()
	secret, err := GenerateTOTPSecret()
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	store.Set("alice", secret)
	auth := NewTOTPAuthenticator(store)

	// Compute the current code via the same primitive.
	code := hotp(secret, time.Now().Unix()/30, 6)
	res, err := auth.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"username": "alice", "code": code},
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if res.UserID != "alice" {
		t.Errorf("UserID = %q want alice", res.UserID)
	}
	if res.Provider != MethodTOTP {
		t.Errorf("Provider = %q want %q", res.Provider, MethodTOTP)
	}
	if len(res.AuthMethods) != 1 || res.AuthMethods[0] != AuthMethodOTP {
		t.Errorf("AuthMethods = %v want [%s]", res.AuthMethods, AuthMethodOTP)
	}
}

func TestTOTPAuthenticator_RejectsBadCode(t *testing.T) {
	store := NewMemoryTOTPStore()
	store.Set("alice", []byte("seedbytes12345678901"))
	auth := NewTOTPAuthenticator(store)

	_, err := auth.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"username": "alice", "code": "000000"},
	})
	if err == nil {
		t.Fatal("expected error on wrong code")
	}
}

func TestTOTPAuthenticator_RejectsUnenrolledUser(t *testing.T) {
	store := NewMemoryTOTPStore()
	auth := NewTOTPAuthenticator(store)

	_, err := auth.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"username": "ghost", "code": "123456"},
	})
	if err == nil {
		t.Fatal("expected error on unknown user")
	}
}

func TestTOTPAuthenticator_AcceptsCodeWithinSkewWindow(t *testing.T) {
	store := NewMemoryTOTPStore()
	secret, _ := GenerateTOTPSecret()
	store.Set("alice", secret)
	auth := NewTOTPAuthenticator(store, WithTOTPSkew(1))

	// Code from the previous step (30s ago) MUST still validate
	// under the default ±1 skew.
	prevStep := (time.Now().Unix() - 30) / 30
	code := hotp(secret, prevStep, 6)
	_, err := auth.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"username": "alice", "code": code},
	})
	if err != nil {
		t.Errorf("previous-step code should pass within skew window: %v", err)
	}
}

func TestTOTPAuthenticator_StrictSkewRejectsDrift(t *testing.T) {
	store := NewMemoryTOTPStore()
	secret, _ := GenerateTOTPSecret()
	store.Set("alice", secret)
	auth := NewTOTPAuthenticator(store, WithTOTPSkew(0))

	// Step 2 ago should NOT validate even under skew=0.
	prevStep := (time.Now().Unix() - 60) / 30
	code := hotp(secret, prevStep, 6)
	_, err := auth.Authenticate(context.Background(), &sso.AuthRequest{
		Credential: map[string]string{"username": "alice", "code": code},
	})
	if err == nil {
		t.Error("expected rejection — code outside skew window")
	}
}

func TestTOTPAuthenticator_VerifyCode(t *testing.T) {
	// VerifyCode is the enrollment-confirm path: it checks a code against a
	// caller-supplied secret WITHOUT consulting the store.
	secret, _ := GenerateTOTPSecret()
	auth := NewTOTPAuthenticator(NewMemoryTOTPStore())

	code := hotp(secret, time.Now().Unix()/30, 6)
	if !auth.VerifyCode(secret, code) {
		t.Error("VerifyCode rejected a valid current code")
	}
	if auth.VerifyCode(secret, "000000") {
		t.Error("VerifyCode accepted a wrong code")
	}
	// Surrounding whitespace is trimmed (UIs often pad the entry).
	if !auth.VerifyCode(secret, "  "+code+" ") {
		t.Error("VerifyCode should trim surrounding whitespace")
	}
}

func TestOTPAuthURL_RenderableShape(t *testing.T) {
	secret := []byte("12345678901234567890")
	url := OTPAuthURL("Acme Corp", "alice@example.com", secret)
	want := "otpauth://totp/"
	if got := url[:len(want)]; got != want {
		t.Errorf("URL prefix = %q want %q", got, want)
	}
	if !contains(url, "secret=") {
		t.Errorf("URL missing secret=: %s", url)
	}
	if !contains(url, "issuer=Acme+Corp") {
		t.Errorf("URL missing issuer=Acme+Corp: %s", url)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
