package fipspolicy

import "testing"

// TestValidateIssuerAlg_DisabledIsAlwaysNil proves the default-off path is
// unconditional — no runtime check, no alg check — so a deployment that
// never sets keys.signing.fips_mode is completely unaffected regardless of
// what alg or allowlist it configures.
func TestValidateIssuerAlg_DisabledIsAlwaysNil(t *testing.T) {
	cases := []string{"", "eddsa", "ed25519", "es256", "rs256", "ps256", "bogus-alg"}
	for _, alg := range cases {
		if err := ValidateIssuerAlg(false, alg, nil); err != nil {
			t.Errorf("fipsMode=false, alg=%q: got %v, want nil", alg, err)
		}
		if err := ValidateIssuerAlg(false, alg, []string{"es256"}); err != nil {
			t.Errorf("fipsMode=false, alg=%q with allowlist: got %v, want nil", alg, err)
		}
	}
}

// TestValidateIssuerAlg_RequiresRuntimeEnabled proves that enabling
// fips_mode without an actual GOFIPS140 build/GODEBUG is rejected — a
// config flag alone must not create false confidence. This test runs in
// the ordinary (non-FIPS) test binary, so RuntimeEnabled() is false here.
func TestValidateIssuerAlg_RequiresRuntimeEnabled(t *testing.T) {
	if RuntimeEnabled() {
		t.Skip("test binary is running with the Go Cryptographic Module active; this test needs the non-FIPS case")
	}
	err := ValidateIssuerAlg(true, "es256", nil)
	if err == nil {
		t.Fatal("expected an error when fips_mode is set but the runtime is not FIPS-enabled")
	}
}

// TestApprovedAlgs_DefaultSetIncludesEd25519 pins the (research-verified)
// decision that Ed25519/EdDSA is FIPS 186-5 approved and MUST NOT be
// rejected by the default allowlist — see the package doc for the
// verification trail. A regression here would silently reintroduce the
// stale pre-2023 assumption.
func TestApprovedAlgs_DefaultSetIncludesEd25519(t *testing.T) {
	for _, alg := range []string{"", "eddsa", "ed25519"} {
		if _, ok := ApprovedAlgs[alg]; !ok {
			t.Errorf("ApprovedAlgs missing %q — Ed25519/EdDSA is FIPS 186-5 approved and must stay allowed by default", alg)
		}
	}
}

// TestCheckAlgAllowed_DefaultSetAllowsEveryConfigurableAlg proves the
// default (no explicit FIPSAllowedAlgs) path accepts every alg
// config.SigningConfig.Alg currently supports, INCLUDING eddsa/ed25519 —
// see the package doc for why that is the factually correct default.
func TestCheckAlgAllowed_DefaultSetAllowsEveryConfigurableAlg(t *testing.T) {
	for _, alg := range []string{"", "eddsa", "ED25519", " es256 ", "ECDSA", "rs256", "ps256", "RSA"} {
		if err := checkAlgAllowed(alg, nil); err != nil {
			t.Errorf("checkAlgAllowed(%q, nil): got %v, want nil", alg, err)
		}
	}
}

// TestCheckAlgAllowed_RejectsUnknownAlg proves a genuinely unsupported alg
// string is rejected even under the default (unrestricted) allowlist.
func TestCheckAlgAllowed_RejectsUnknownAlg(t *testing.T) {
	if err := checkAlgAllowed("hs256", nil); err == nil {
		t.Fatal("expected hs256 (a symmetric alg, never issuer-selectable) to be rejected")
	}
}

// TestCheckAlgAllowed_AllowlistNarrows proves an operator-supplied
// FIPSAllowedAlgs list can restrict beyond the default ApprovedAlgs set —
// e.g. a compliance posture that wants ECDSA/RSA only and deliberately
// excludes Ed25519 despite it being FIPS 186-5 approved.
func TestCheckAlgAllowed_AllowlistNarrows(t *testing.T) {
	restricted := []string{"es256", "rs256", "ps256"}
	if err := checkAlgAllowed("eddsa", restricted); err == nil {
		t.Fatal("expected eddsa to be rejected by an ECDSA/RSA-only allowlist")
	}
	if err := checkAlgAllowed("", restricted); err == nil {
		t.Fatal("expected the default alg (eddsa) to be rejected by an ECDSA/RSA-only allowlist")
	}
	if err := checkAlgAllowed("ES256", restricted); err != nil {
		t.Fatalf("expected ES256 to pass an ECDSA/RSA-only allowlist, got %v", err)
	}
}

// TestValidateIssuerAlg_AllowlistRequiresRuntimeEnabled proves the
// runtime-enabled gate is checked BEFORE the allowlist — an operator who
// sets both fips_mode and fips_allowed_algs without a real FIPS build still
// gets the runtime error, not a silently-passed alg check.
func TestValidateIssuerAlg_AllowlistRequiresRuntimeEnabled(t *testing.T) {
	if RuntimeEnabled() {
		t.Skip("test binary is running with the Go Cryptographic Module active; this test needs the non-FIPS case")
	}
	if err := ValidateIssuerAlg(true, "es256", []string{"es256"}); err == nil {
		t.Fatal("expected the runtime-enabled error even with a matching allowlist")
	}
}
