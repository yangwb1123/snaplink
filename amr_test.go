package sso

import (
	"github.com/snaplink/sso/internal/handler"
	"reflect"
	"testing"
)

func TestAMRForResult(t *testing.T) {
	// Authenticator-recorded methods win over the OAuth provider id.
	if got := handler.AmrForResult(&AuthResult{Provider: "password", AuthMethods: []string{"pwd"}}); !reflect.DeepEqual(got, []string{"pwd"}) {
		t.Errorf("handler.AmrForResult with AuthMethods = %v, want [pwd]", got)
	}
	// Multi-method passes through unchanged.
	if got := handler.AmrForResult(&AuthResult{Provider: "x", AuthMethods: []string{"pwd", "otp"}}); !reflect.DeepEqual(got, []string{"pwd", "otp"}) {
		t.Errorf("handler.AmrForResult multi = %v, want [pwd otp]", got)
	}
	// Fallback to the provider id only when the authenticator recorded nothing.
	if got := handler.AmrForResult(&AuthResult{Provider: "saml"}); !reflect.DeepEqual(got, []string{"saml"}) {
		t.Errorf("handler.AmrForResult fallback = %v, want [saml]", got)
	}
	// Returns a fresh copy — the caller must not be able to alias/mutate
	// result.AuthMethods through the return value.
	res := &AuthResult{AuthMethods: []string{"pwd"}}
	out := handler.AmrForResult(res)
	out[0] = "mutated"
	if res.AuthMethods[0] != "pwd" {
		t.Error("handler.AmrForResult aliased result.AuthMethods")
	}
}

func TestWithMFAMethod(t *testing.T) {
	// totp maps to the RFC 8176 "otp" value, plus the "mfa" marker.
	if got := handler.WithMFAMethod([]string{"pwd"}, "totp"); !reflect.DeepEqual(got, []string{"pwd", "otp", "mfa"}) {
		t.Errorf("handler.WithMFAMethod totp = %v, want [pwd otp mfa]", got)
	}
	// An unmapped method passes through verbatim.
	if got := handler.WithMFAMethod([]string{"pwd"}, "webauthn"); !reflect.DeepEqual(got, []string{"pwd", "webauthn", "mfa"}) {
		t.Errorf("handler.WithMFAMethod webauthn = %v, want [pwd webauthn mfa]", got)
	}
	// Dedup: re-presenting an existing factor doesn't duplicate it, and
	// "mfa" is never added twice.
	if got := handler.WithMFAMethod([]string{"otp", "mfa"}, "totp"); !reflect.DeepEqual(got, []string{"otp", "mfa"}) {
		t.Errorf("handler.WithMFAMethod dedup = %v, want [otp mfa]", got)
	}
	// Empty start: just the mapped factor + mfa.
	if got := handler.WithMFAMethod(nil, "totp"); !reflect.DeepEqual(got, []string{"otp", "mfa"}) {
		t.Errorf("handler.WithMFAMethod empty = %v, want [otp mfa]", got)
	}
}
