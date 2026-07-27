package serverbuildsign

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/shared/security/fipspolicy"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// TestBuildSigningIssuer_FIPSModeDefaultOff proves keys.signing.fips_mode's
// zero value (false) leaves BuildSigningIssuer completely unaffected —
// every alg this server supports still constructs, including eddsa, exactly
// as it did before this package existed. This is the default-off byte-
// identical-behavior guarantee every new feature in this repo must uphold.
func TestBuildSigningIssuer_FIPSModeDefaultOff(t *testing.T) {
	t.Parallel()
	for _, alg := range []string{"", "eddsa", "es256", "rs256", "ps256"} {
		_, _, _, err := BuildSigningIssuer(
			config.SigningConfig{Alg: alg},
			config.ServerConfig{Issuer: "https://sso.test"},
			nil,
			spi.NopLogger{},
		)
		if err != nil {
			t.Errorf("alg=%q, fips_mode unset: got %v, want nil", alg, err)
		}
	}
}

// TestBuildSigningIssuer_FIPSModeRequiresRuntimeEnabled proves the gate is
// actually wired into BuildSigningIssuer (not just unit-tested in
// isolation in shared/security/fipspolicy): setting fips_mode true without
// a GOFIPS140/GODEBUG=fips140 build fails issuer construction fast, for
// every alg — including es256/rs256/ps256, which would otherwise be
// mistaken for "already FIPS-safe" and skip the runtime check.
func TestBuildSigningIssuer_FIPSModeRequiresRuntimeEnabled(t *testing.T) {
	t.Parallel()
	if fipspolicy.RuntimeEnabled() {
		t.Skip("test binary is running with the Go Cryptographic Module active; this test needs the non-FIPS case")
	}
	for _, alg := range []string{"", "eddsa", "es256", "rs256", "ps256"} {
		iss, _, _, err := BuildSigningIssuer(
			config.SigningConfig{Alg: alg, FIPSMode: true},
			config.ServerConfig{Issuer: "https://sso.test"},
			nil,
			spi.NopLogger{},
		)
		if err == nil {
			t.Errorf("alg=%q, fips_mode=true on a non-FIPS binary: expected an error, got a constructed issuer %v", alg, iss)
		}
	}
}

// TestBuildSigningIssuer_FIPSModeApprovedAlgsConstruct proves that, on an
// ACTUAL GOFIPS140/GODEBUG=fips140 build (this test skips otherwise — run
// with `GOFIPS140=latest go test ./cmd/sso-server/serverbuildsign/...` to
// exercise it), fips_mode=true still constructs every alg this server
// supports by default, INCLUDING eddsa — Ed25519 is FIPS 186-5 approved
// (see shared/security/fipspolicy's doc comment) so it must not be
// rejected. A narrower FIPSAllowedAlgs list, however, can still exclude it
// for an operator that wants ECDSA/RSA only.
func TestBuildSigningIssuer_FIPSModeApprovedAlgsConstruct(t *testing.T) {
	t.Parallel()
	if !fipspolicy.RuntimeEnabled() {
		t.Skip("requires a GOFIPS140/GODEBUG=fips140 build — see docs/fips.md")
	}
	for _, alg := range []string{"", "eddsa", "es256", "rs256", "ps256"} {
		if _, _, _, err := BuildSigningIssuer(
			config.SigningConfig{Alg: alg, FIPSMode: true},
			config.ServerConfig{Issuer: "https://sso.test"},
			nil,
			spi.NopLogger{},
		); err != nil {
			t.Errorf("alg=%q under a real FIPS build: got %v, want nil (all default algs are FIPS 186-5 approved)", alg, err)
		}
	}

	// A stricter operator-chosen allowlist can still exclude eddsa.
	restricted := config.SigningConfig{Alg: "eddsa", FIPSMode: true, FIPSAllowedAlgs: []string{"es256", "rs256", "ps256"}}
	if _, _, _, err := BuildSigningIssuer(restricted, config.ServerConfig{Issuer: "https://sso.test"}, nil, spi.NopLogger{}); err == nil {
		t.Error("eddsa with an ECDSA/RSA-only fips_allowed_algs: expected an error, got nil")
	}
}
