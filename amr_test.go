package sso

import (
	"reflect"
	"testing"
)

func TestAMRForResult(t *testing.T) {
	// Authenticator-recorded methods win over the OAuth provider id.
	if got := amrForResult(&AuthResult{Provider: "password", AuthMethods: []string{"pwd"}}); !reflect.DeepEqual(got, []string{"pwd"}) {
		t.Errorf("amrForResult with AuthMethods = %v, want [pwd]", got)
	}
	// Multi-method passes through unchanged.
	if got := amrForResult(&AuthResult{Provider: "x", AuthMethods: []string{"pwd", "otp"}}); !reflect.DeepEqual(got, []string{"pwd", "otp"}) {
		t.Errorf("amrForResult multi = %v, want [pwd otp]", got)
	}
	// Fallback to the provider id only when the authenticator recorded nothing.
	if got := amrForResult(&AuthResult{Provider: "saml"}); !reflect.DeepEqual(got, []string{"saml"}) {
		t.Errorf("amrForResult fallback = %v, want [saml]", got)
	}
	// Returns a fresh copy — the caller must not be able to alias/mutate
	// result.AuthMethods through the return value.
	res := &AuthResult{AuthMethods: []string{"pwd"}}
	out := amrForResult(res)
	out[0] = "mutated"
	if res.AuthMethods[0] != "pwd" {
		t.Error("amrForResult aliased result.AuthMethods")
	}
}

func TestWithMFAMethod(t *testing.T) {
	// totp maps to the RFC 8176 "otp" value, plus the "mfa" marker.
	if got := withMFAMethod([]string{"pwd"}, "totp"); !reflect.DeepEqual(got, []string{"pwd", "otp", "mfa"}) {
		t.Errorf("withMFAMethod totp = %v, want [pwd otp mfa]", got)
	}
	// An unmapped method passes through verbatim.
	if got := withMFAMethod([]string{"pwd"}, "webauthn"); !reflect.DeepEqual(got, []string{"pwd", "webauthn", "mfa"}) {
		t.Errorf("withMFAMethod webauthn = %v, want [pwd webauthn mfa]", got)
	}
	// Dedup: re-presenting an existing factor doesn't duplicate it, and
	// "mfa" is never added twice.
	if got := withMFAMethod([]string{"otp", "mfa"}, "totp"); !reflect.DeepEqual(got, []string{"otp", "mfa"}) {
		t.Errorf("withMFAMethod dedup = %v, want [otp mfa]", got)
	}
	// Empty start: just the mapped factor + mfa.
	if got := withMFAMethod(nil, "totp"); !reflect.DeepEqual(got, []string{"otp", "mfa"}) {
		t.Errorf("withMFAMethod empty = %v, want [otp mfa]", got)
	}
}
