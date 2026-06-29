package webauthn

import (
	"errors"
	"strings"
	"testing"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

// rawAAGUID16 is a fixed non-zero 16-byte AAGUID used across the tests.
// Canonical form: "ee882879-721c-4913-9775-3dfcce97072a".
var rawAAGUID16 = []byte{
	0xee, 0x88, 0x28, 0x79, 0x72, 0x1c, 0x49, 0x13,
	0x97, 0x75, 0x3d, 0xfc, 0xce, 0x97, 0x07, 0x2a,
}

const (
	aaguidCanonical = "ee882879-721c-4913-9775-3dfcce97072a"
	aaguidUpper     = "EE882879-721C-4913-9775-3DFCCE97072A"
	aaguidBareHex   = "ee882879721c491397753dfcce97072a"
)

var zeroAAGUID16 = make([]byte, 16)

func TestCanonicalAAGUID_FormsMatch(t *testing.T) {
	t.Parallel()
	// Canonical, uppercase, and bare-hex all canonicalize to the same
	// value — and that value matches the raw 16-byte rendering. A
	// canonicalization mismatch here would silently allow/deny the wrong
	// authenticator, so this is the load-bearing comparison.
	fromBytes, err := canonicalAAGUIDFromBytes(rawAAGUID16)
	if err != nil {
		t.Fatalf("canonicalAAGUIDFromBytes: %v", err)
	}
	if fromBytes != aaguidCanonical {
		t.Fatalf("raw bytes canonicalized to %q, want %q", fromBytes, aaguidCanonical)
	}
	for _, in := range []string{aaguidCanonical, aaguidUpper, aaguidBareHex, "  " + aaguidUpper + "  "} {
		got, err := CanonicalAAGUID(in)
		if err != nil {
			t.Fatalf("CanonicalAAGUID(%q): %v", in, err)
		}
		if got != aaguidCanonical {
			t.Fatalf("CanonicalAAGUID(%q) = %q, want %q", in, got, aaguidCanonical)
		}
		if got != fromBytes {
			t.Fatalf("string form %q (%q) != raw-byte form %q", in, got, fromBytes)
		}
	}
}

func TestCanonicalAAGUID_RejectsMalformed(t *testing.T) {
	t.Parallel()
	bad := []string{
		"",                                     // empty
		"not-a-uuid",                           // junk
		"ee882879721c491397753dfcce97072",      // 31 hex (too short)
		"ee882879721c491397753dfcce97072aa",    // 33 hex (too long)
		"ee882879-721c-4913-9775-3dfcce97072",  // hyphenated but short
		"ee882879x721c-4913-9775-3dfcce97072a", // hyphen in wrong spot
		"gg882879-721c-4913-9775-3dfcce97072a", // non-hex
		"ee8828797-21c-4913-9775-3dfcce97072a", // hyphens misplaced (len 36 but wrong positions)
	}
	for _, in := range bad {
		if _, err := CanonicalAAGUID(in); err == nil {
			t.Fatalf("CanonicalAAGUID(%q) = nil error, want rejection", in)
		}
	}
}

func TestNewAttestationPolicy_Validation(t *testing.T) {
	t.Parallel()
	// off mode ignores the list and is a no-op.
	p, err := NewAttestationPolicy(AttestationPolicyOff, nil)
	if err != nil {
		t.Fatalf("off policy: %v", err)
	}
	if p.Enabled() {
		t.Fatal("off policy must not be Enabled")
	}

	// allowlist/denylist require a non-empty list.
	if _, err := NewAttestationPolicy(AttestationPolicyAllowlist, nil); err == nil {
		t.Fatal("allowlist with empty list must error")
	}
	if _, err := NewAttestationPolicy(AttestationPolicyDenylist, []string{}); err == nil {
		t.Fatal("denylist with empty list must error")
	}

	// A malformed AAGUID in the list fails loud.
	if _, err := NewAttestationPolicy(AttestationPolicyAllowlist, []string{"not-a-uuid"}); err == nil {
		t.Fatal("malformed AAGUID must error at construction")
	}

	// Unknown mode rejected.
	if _, err := NewAttestationPolicy(AttestationPolicyMode("bogus"), []string{aaguidCanonical}); err == nil {
		t.Fatal("unknown mode must error")
	}
}

func TestAttestationPolicy_NilAndOffPermitAll(t *testing.T) {
	t.Parallel()
	var nilPolicy *AttestationPolicy
	if err := nilPolicy.Check(rawAAGUID16); err != nil {
		t.Fatalf("nil policy must permit, got %v", err)
	}
	if err := nilPolicy.Check(zeroAAGUID16); err != nil {
		t.Fatalf("nil policy must permit zero AAGUID, got %v", err)
	}
	off, _ := NewAttestationPolicy(AttestationPolicyOff, nil)
	if err := off.Check(rawAAGUID16); err != nil {
		t.Fatalf("off policy must permit, got %v", err)
	}
}

func TestAttestationPolicy_Allowlist(t *testing.T) {
	t.Parallel()
	// Config supplies the UPPERCASE form; the raw 16-byte AAGUID must
	// still match through canonicalization.
	p, err := NewAttestationPolicy(AttestationPolicyAllowlist, []string{aaguidUpper})
	if err != nil {
		t.Fatalf("NewAttestationPolicy: %v", err)
	}
	if err := p.Check(rawAAGUID16); err != nil {
		t.Fatalf("allowed AAGUID rejected: %v", err)
	}
	// A different AAGUID is rejected.
	other := append([]byte(nil), rawAAGUID16...)
	other[0] ^= 0xff
	if err := p.Check(other); !errors.Is(err, ErrAttestationDenied) {
		t.Fatalf("non-allowed AAGUID: got %v, want ErrAttestationDenied", err)
	}
	// Zero AAGUID is rejected under allowlist (not special-cased).
	if err := p.Check(zeroAAGUID16); !errors.Is(err, ErrAttestationDenied) {
		t.Fatalf("zero AAGUID under allowlist: got %v, want ErrAttestationDenied", err)
	}
}

func TestAttestationPolicy_AllowlistZeroExplicit(t *testing.T) {
	t.Parallel()
	// When the operator explicitly allowlists the zero AAGUID, it passes.
	p, err := NewAttestationPolicy(AttestationPolicyAllowlist, []string{ZeroAAGUID, aaguidCanonical})
	if err != nil {
		t.Fatalf("NewAttestationPolicy: %v", err)
	}
	if err := p.Check(zeroAAGUID16); err != nil {
		t.Fatalf("explicitly-allowlisted zero AAGUID rejected: %v", err)
	}
	if err := p.Check(rawAAGUID16); err != nil {
		t.Fatalf("allowed AAGUID rejected: %v", err)
	}
}

func TestAttestationPolicy_Denylist(t *testing.T) {
	t.Parallel()
	p, err := NewAttestationPolicy(AttestationPolicyDenylist, []string{aaguidCanonical})
	if err != nil {
		t.Fatalf("NewAttestationPolicy: %v", err)
	}
	// Denied AAGUID is rejected.
	if err := p.Check(rawAAGUID16); !errors.Is(err, ErrAttestationDenied) {
		t.Fatalf("denied AAGUID: got %v, want ErrAttestationDenied", err)
	}
	// Any other AAGUID is permitted, including the zero AAGUID.
	other := append([]byte(nil), rawAAGUID16...)
	other[15] ^= 0x01
	if err := p.Check(other); err != nil {
		t.Fatalf("non-denied AAGUID rejected: %v", err)
	}
	if err := p.Check(zeroAAGUID16); err != nil {
		t.Fatalf("zero AAGUID under denylist must pass: %v", err)
	}
}

func TestAttestationPolicy_UnparseableAAGUID(t *testing.T) {
	t.Parallel()
	// A non-16-byte AAGUID can't match the canonical set. Under allowlist
	// it must be denied (fail closed); under denylist it can't match a
	// denied entry, so it passes.
	short := []byte{0x01, 0x02, 0x03}
	allow, _ := NewAttestationPolicy(AttestationPolicyAllowlist, []string{aaguidCanonical})
	if err := allow.Check(short); !errors.Is(err, ErrAttestationDenied) {
		t.Fatalf("unparseable AAGUID under allowlist: got %v, want ErrAttestationDenied", err)
	}
	deny, _ := NewAttestationPolicy(AttestationPolicyDenylist, []string{aaguidCanonical})
	if err := deny.Check(short); err != nil {
		t.Fatalf("unparseable AAGUID under denylist must pass: %v", err)
	}
}

func TestCredentialAAGUID(t *testing.T) {
	t.Parallel()
	if got := CredentialAAGUID(rawAAGUID16); got != aaguidCanonical {
		t.Fatalf("CredentialAAGUID = %q, want %q", got, aaguidCanonical)
	}
	if got := CredentialAAGUID(zeroAAGUID16); got != ZeroAAGUID {
		t.Fatalf("CredentialAAGUID(zero) = %q, want %q", got, ZeroAAGUID)
	}
	if got := CredentialAAGUID([]byte{0x01}); got != "" {
		t.Fatalf("CredentialAAGUID(short) = %q, want empty", got)
	}
}

func TestMapConveyance(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"":           "",
		"none":       "",
		"NONE":       "",
		"  direct  ": "direct",
		"indirect":   "indirect",
		"enterprise": "enterprise",
	}
	for in, want := range cases {
		got, err := mapConveyance(in)
		if err != nil {
			t.Fatalf("mapConveyance(%q): %v", in, err)
		}
		if string(got) != want {
			t.Fatalf("mapConveyance(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := mapConveyance("bogus"); err == nil {
		t.Fatal("mapConveyance(bogus) must error")
	}
}

func TestNewHelper_InvalidConveyanceRejected(t *testing.T) {
	t.Parallel()
	_, err := NewHelper(Config{
		RPID:                  "example.com",
		RPOrigins:             []string{"https://sso.example.com"},
		AttestationConveyance: "definitely-not-valid",
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err == nil {
		t.Fatal("NewHelper with invalid conveyance must error")
	}
}

// TestFinishRegistrationGate exercises the actual gate seam used by
// FinishRegistration (checkAttestationPolicy) against a synthesized verified
// credential — this is the hook that runs AFTER go-webauthn verifies the
// attestation and BEFORE persistence. Faking the full attestation ceremony
// (real crypto) is intentionally avoided; the gate logic is the part this
// feature owns.
func TestFinishRegistrationGate(t *testing.T) {
	t.Parallel()
	credWith := func(aaguid []byte) *gw.Credential {
		c := &gw.Credential{ID: []byte("cred-1")}
		c.Authenticator.AAGUID = aaguid
		return c
	}

	t.Run("off helper permits any AAGUID", func(t *testing.T) {
		h := newHelperForTest(t) // no policy configured
		if err := h.checkAttestationPolicy(credWith(rawAAGUID16)); err != nil {
			t.Fatalf("off helper rejected: %v", err)
		}
		if err := h.checkAttestationPolicy(credWith(zeroAAGUID16)); err != nil {
			t.Fatalf("off helper rejected zero AAGUID: %v", err)
		}
	})

	t.Run("allowlist permits listed, denies others with typed error", func(t *testing.T) {
		policy, err := NewAttestationPolicy(AttestationPolicyAllowlist, []string{aaguidCanonical})
		if err != nil {
			t.Fatalf("policy: %v", err)
		}
		h, err := NewHelper(Config{
			RPID:                  "example.com",
			RPOrigins:             []string{"https://sso.example.com"},
			AttestationConveyance: "direct", // required for an active policy
			AttestationPolicy:     policy,
		}, NewMemoryUserStore(), NewMemorySessionStore())
		if err != nil {
			t.Fatalf("NewHelper: %v", err)
		}
		if err := h.checkAttestationPolicy(credWith(rawAAGUID16)); err != nil {
			t.Fatalf("listed AAGUID rejected: %v", err)
		}
		other := append([]byte(nil), rawAAGUID16...)
		other[0] ^= 0xff
		err = h.checkAttestationPolicy(credWith(other))
		var denied *AttestationDeniedError
		if !errors.As(err, &denied) {
			t.Fatalf("expected *AttestationDeniedError, got %v", err)
		}
		if !errors.Is(err, ErrAttestationDenied) {
			t.Fatalf("denial must wrap ErrAttestationDenied, got %v", err)
		}
		// The typed error carries the canonical AAGUID + mode for audit.
		wantCanon, _ := canonicalAAGUIDFromBytes(other)
		if denied.AAGUID != wantCanon {
			t.Fatalf("denied.AAGUID = %q, want %q", denied.AAGUID, wantCanon)
		}
		if denied.Mode != AttestationPolicyAllowlist {
			t.Fatalf("denied.Mode = %q, want allowlist", denied.Mode)
		}
		// And the error string carries the AAGUID (operator visibility).
		if !strings.Contains(denied.Error(), wantCanon) {
			t.Fatalf("denied.Error() = %q, want it to mention %q", denied.Error(), wantCanon)
		}
	})

	t.Run("zero AAGUID denied under allowlist", func(t *testing.T) {
		policy, _ := NewAttestationPolicy(AttestationPolicyAllowlist, []string{aaguidCanonical})
		h, _ := NewHelper(Config{
			RPID:                  "example.com",
			RPOrigins:             []string{"https://sso.example.com"},
			AttestationConveyance: "direct",
			AttestationPolicy:     policy,
		}, NewMemoryUserStore(), NewMemorySessionStore())
		if err := h.checkAttestationPolicy(credWith(zeroAAGUID16)); !errors.Is(err, ErrAttestationDenied) {
			t.Fatalf("zero AAGUID under allowlist: got %v, want denial", err)
		}
	})
}

// TestFinishRegistrationGate_NoneAttestationRejected proves the downgrade
// fix: when a policy is active, a credential conveying NO attestation
// (AttestationFormat "none") is rejected even when its AAGUID would otherwise
// satisfy the gate. go-webauthn accepts the "none" format with zero signature
// verification, so the AAGUID is untrustworthy; an active policy MUST demand a
// verified attestation statement. Default-off performs no format check.
func TestFinishRegistrationGate_NoneAttestationRejected(t *testing.T) {
	t.Parallel()
	credNone := func(aaguid []byte) *gw.Credential {
		c := &gw.Credential{ID: []byte("cred-none"), AttestationFormat: "none"}
		c.Authenticator.AAGUID = aaguid
		return c
	}

	// Active denylist (banning a specific model): a none-attestation cred
	// carries the zero AAGUID, which the denylist would NOT match — the exact
	// silent bypass the fix closes. It must be rejected as
	// attestation_format_none.
	denyPolicy, err := NewAttestationPolicy(AttestationPolicyDenylist, []string{aaguidCanonical})
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	hDeny, err := NewHelper(Config{
		RPID:                  "example.com",
		RPOrigins:             []string{"https://sso.example.com"},
		AttestationConveyance: "direct",
		AttestationPolicy:     denyPolicy,
	}, NewMemoryUserStore(), NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	err = hDeny.checkAttestationPolicy(credNone(zeroAAGUID16))
	var denied *AttestationDeniedError
	if !errors.As(err, &denied) {
		t.Fatalf("none-attestation under denylist: expected *AttestationDeniedError, got %v", err)
	}
	if denied.Reason != ReasonAttestationFormatNone {
		t.Fatalf("denied.Reason = %q, want %q", denied.Reason, ReasonAttestationFormatNone)
	}
	if !errors.Is(err, ErrAttestationDenied) {
		t.Fatalf("none denial must wrap ErrAttestationDenied, got %v", err)
	}

	// Even an ALLOWLISTED AAGUID is rejected when the format is "none": the
	// client downgraded the (spoofable, unverified) AAGUID, so the gate can't
	// trust it. Reason is still attestation_format_none (the format check
	// precedes the AAGUID check).
	allowPolicy, _ := NewAttestationPolicy(AttestationPolicyAllowlist, []string{aaguidCanonical})
	hAllow, _ := NewHelper(Config{
		RPID:                  "example.com",
		RPOrigins:             []string{"https://sso.example.com"},
		AttestationConveyance: "direct",
		AttestationPolicy:     allowPolicy,
	}, NewMemoryUserStore(), NewMemorySessionStore())
	err = hAllow.checkAttestationPolicy(credNone(rawAAGUID16))
	if !errors.As(err, &denied) || denied.Reason != ReasonAttestationFormatNone {
		t.Fatalf("none-attestation with allowlisted AAGUID: got %v, want attestation_format_none denial", err)
	}

	// "NONE" (case-insensitive) is also rejected — the format string is
	// matched case-insensitively.
	if err := hAllow.checkAttestationPolicy(&gw.Credential{ID: []byte("c"), AttestationFormat: "NONE"}); !errors.Is(err, ErrAttestationDenied) {
		t.Fatalf("case-insensitive NONE must be rejected, got %v", err)
	}

	// Default-off (no policy) performs NO format check — a none-attestation
	// cred passes, byte-identical to a pre-policy build.
	hOff := newHelperForTest(t)
	if err := hOff.checkAttestationPolicy(credNone(zeroAAGUID16)); err != nil {
		t.Fatalf("off helper must not format-check (none passes), got %v", err)
	}

	// A packed-attestation cred with an allowlisted AAGUID still passes — the
	// none-rejection does not over-reach to real attestation formats.
	packed := &gw.Credential{ID: []byte("c-packed"), AttestationFormat: "packed"}
	packed.Authenticator.AAGUID = rawAAGUID16
	if err := hAllow.checkAttestationPolicy(packed); err != nil {
		t.Fatalf("packed attestation with allowlisted AAGUID rejected: %v", err)
	}
}

// TestNewHelper_ActivePolicyRequiresDirectConveyance proves the boot guard:
// an active policy demands conveyance direct|enterprise; ""/none/indirect
// fail loud; mode-off with any conveyance is fine (no guard).
func TestNewHelper_ActivePolicyRequiresDirectConveyance(t *testing.T) {
	t.Parallel()
	mk := func(conv string, policy *AttestationPolicy) error {
		_, err := NewHelper(Config{
			RPID:                  "example.com",
			RPOrigins:             []string{"https://sso.example.com"},
			AttestationConveyance: conv,
			AttestationPolicy:     policy,
		}, NewMemoryUserStore(), NewMemorySessionStore())
		return err
	}
	allow, _ := NewAttestationPolicy(AttestationPolicyAllowlist, []string{aaguidCanonical})
	deny, _ := NewAttestationPolicy(AttestationPolicyDenylist, []string{aaguidCanonical})

	// Active policy + below-direct conveyance → boot error.
	for _, conv := range []string{"", "none", "indirect"} {
		if err := mk(conv, allow); err == nil {
			t.Fatalf("allowlist + conveyance %q must error at NewHelper", conv)
		}
		if err := mk(conv, deny); err == nil {
			t.Fatalf("denylist + conveyance %q must error at NewHelper", conv)
		}
	}
	// Active policy + direct|enterprise → ok.
	for _, conv := range []string{"direct", "enterprise", "DIRECT"} {
		if err := mk(conv, allow); err != nil {
			t.Fatalf("allowlist + conveyance %q must be accepted, got %v", conv, err)
		}
	}
	// Mode-off (nil policy, or an explicit off policy) + any conveyance → no
	// guard (the guard only fires for an active policy).
	for _, conv := range []string{"", "none", "indirect", "direct"} {
		if err := mk(conv, nil); err != nil {
			t.Fatalf("nil policy + conveyance %q must be accepted, got %v", conv, err)
		}
	}
	offPolicy, _ := NewAttestationPolicy(AttestationPolicyOff, nil)
	if err := mk("", offPolicy); err != nil {
		t.Fatalf("off policy + empty conveyance must be accepted, got %v", err)
	}
}
