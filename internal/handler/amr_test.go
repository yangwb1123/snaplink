package handler

import (
	"slices"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// TestAmrForResult locks the RFC 8176 amr derivation: recorded AuthMethods win
// (as a FRESH copy that never aliases the result slice), and the provider id is
// the single-element fallback only when nothing was recorded so amr is never
// absent.
func TestAmrForResult(t *testing.T) {
	t.Run("recorded methods win and are copied", func(t *testing.T) {
		methods := []string{"pwd", "otp"}
		res := &core.AuthResult{AuthMethods: methods, Provider: "password"}
		got := AmrForResult(res)
		if !slices.Equal(got, []string{"pwd", "otp"}) {
			t.Fatalf("got %v, want [pwd otp]", got)
		}
		// Mutating the returned slice must not corrupt the source: the contract
		// promises a fresh copy callers may freely mutate.
		got[0] = "TAMPERED"
		if methods[0] != "pwd" {
			t.Fatalf("returned slice aliased result.AuthMethods (source mutated to %q)", methods[0])
		}
	})

	t.Run("provider fallback when no methods recorded", func(t *testing.T) {
		res := &core.AuthResult{Provider: "google"}
		got := AmrForResult(res)
		if !slices.Equal(got, []string{"google"}) {
			t.Fatalf("got %v, want [google]", got)
		}
	})
}

// TestAmrOrProvider exercises the shared helper directly, including the
// empty-methods fallback used by the authorization_code replay path.
func TestAmrOrProvider(t *testing.T) {
	cases := []struct {
		name     string
		methods  []string
		provider string
		want     []string
	}{
		{"methods present", []string{"x509"}, "certificate", []string{"x509"}},
		{"nil methods fall back to provider", nil, "phone", []string{"phone"}},
		{"empty methods fall back to provider", []string{}, "email", []string{"email"}},
		{"multiple methods preserved in order", []string{"pwd", "otp", "mfa"}, "password", []string{"pwd", "otp", "mfa"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := AmrOrProvider(c.methods, c.provider); !slices.Equal(got, c.want) {
				t.Fatalf("AmrOrProvider(%v, %q) = %v, want %v", c.methods, c.provider, got, c.want)
			}
		})
	}
}

// TestWithMFAMethod locks the /auth/mfa second-leg amr fold: the verified
// factor's amr value plus the "mfa" marker, deduped and order-preserving, with
// the totp->otp mapping applied and unknown factors passing through.
func TestWithMFAMethod(t *testing.T) {
	cases := []struct {
		name     string
		existing []string
		method   string
		want     []string
	}{
		{"totp maps to otp and adds mfa", []string{"pwd"}, "totp", []string{"pwd", "otp", "mfa"}},
		{"unknown method passes through", []string{"pwd"}, "push", []string{"pwd", "push", "mfa"}},
		{"already-present factor not duplicated", []string{"pwd", "otp"}, "totp", []string{"pwd", "otp", "mfa"}},
		{"mfa marker not duplicated", []string{"pwd", "mfa"}, "totp", []string{"pwd", "mfa", "otp"}},
		{"empty method only adds mfa marker", []string{"pwd"}, "", []string{"pwd", "mfa"}},
		{"empty existing", nil, "webauthn", []string{"webauthn", "mfa"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WithMFAMethod(c.existing, c.method); !slices.Equal(got, c.want) {
				t.Fatalf("WithMFAMethod(%v, %q) = %v, want %v", c.existing, c.method, got, c.want)
			}
		})
	}
}

// TestWithMFAMethod_DoesNotMutateInput guards that the fold never writes back
// into the caller's slice (it builds a fresh copy first).
func TestWithMFAMethod_DoesNotMutateInput(t *testing.T) {
	existing := []string{"pwd"}
	_ = WithMFAMethod(existing, "totp")
	if !slices.Equal(existing, []string{"pwd"}) {
		t.Fatalf("input slice mutated to %v", existing)
	}
}
