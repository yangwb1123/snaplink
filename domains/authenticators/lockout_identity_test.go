package authenticators

import (
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// TestLockoutIdentity_ClosesFieldInjectionBypass proves the per-account lockout
// key cannot be spread across distinct keys for the SAME account under attack.
// Phone/email OTP authenticators authenticate on phone/email, but the generic
// LockoutKey field precedence picks an earlier field (username) — so an attacker
// could inject a varying username (ignored by the authenticator) to defeat
// lockout. LockoutKeyer returns ONLY the real, normalized identity.
func TestLockoutIdentity_ClosesFieldInjectionBypass(t *testing.T) {
	t.Parallel()
	var _ core.LockoutKeyer = (*PhoneAuthenticator)(nil)
	var _ core.LockoutKeyer = (*EmailAuthenticator)(nil)

	p := &PhoneAuthenticator{}
	// Injected, varying `username` the phone authenticator ignores must NOT
	// change the lockout identity — it stays the phone under attack.
	a := p.LockoutIdentity(map[string]string{"username": "decoy-1", "phone": "+15551234567"})
	b := p.LockoutIdentity(map[string]string{"username": "decoy-2", "phone": "+15551234567"})
	if a != b || a != "+15551234567" {
		t.Errorf("phone lockout identity must be the phone regardless of injected fields: got %q and %q", a, b)
	}

	e := &EmailAuthenticator{}
	// Case/whitespace variants of the same address must share one key.
	if got := e.LockoutIdentity(map[string]string{"email": "  Alice@Example.COM "}); got != "alice@example.com" {
		t.Errorf("email lockout identity = %q, want normalized alice@example.com", got)
	}
	if e.LockoutIdentity(map[string]string{"username": "x", "email": "bob@x.io"}) != "bob@x.io" {
		t.Error("email lockout identity must ignore an injected username")
	}
}
