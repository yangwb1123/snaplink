// Package fipspolicy centralizes FIPS 140-3 crypto-algorithm governance for
// this server's JWT signing issuer. It is the ONE place FIPS-awareness
// exists in the codebase (per AGENTS.md: don't scatter FIPS checks across
// every crypto call site) — issuer construction
// (cmd/sso-server/serverbuildsign.BuildSigningIssuer) is the single call
// site that consults it. See docs/fips.md for the operator-facing guide.
//
// Scope note (verified against Go 1.26's stdlib source, not assumed):
// Go's native FIPS 140-3 mode (GOFIPS140=latest / GODEBUG=fips140=on,
// available since Go 1.24) needs NO cgo and NO BoringCrypto — crypto/ecdsa,
// crypto/rsa, AND crypto/ed25519 are all backed by the Go Cryptographic
// Module and each has its own known-answer self-test (CAST) registered
// under crypto/internal/fips140/{ecdsa,rsa,ed25519}. FIPS 186-5 (2023) added
// EdDSA (Ed25519/Ed448) to NIST's approved digital-signature algorithms,
// superseding the older (pre-2023) understanding that only RSA/ECDSA/DSA
// are approved — a belief still common in blog posts and backlogs, but
// stale. Go's own crypto/tls FIPS-mode-allowed signature-scheme list
// (crypto/tls/defaults_fips140.go) includes Ed25519 for exactly this
// reason. Consequently ApprovedAlgs below does NOT reject Ed25519 by
// default; a deployment that needs a narrower allowlist (e.g. a compliance
// posture pinned to a CMVP certificate issued before EdDSA validation
// landed) can set FIPSAllowedAlgs explicitly.
package fipspolicy

import (
	"crypto/fips140"
	"fmt"
	"strings"
)

// ApprovedAlgs is the default set of config.SigningConfig.Alg values this
// package treats as FIPS 140-3 approved: EdDSA (Ed25519), ECDSA (P-256 —
// the only curve this server's issuer constructs today), and RSA
// (PKCS#1v1.5 via RS256, PSS via PS256). "" is included because it is
// config.SigningConfig's own documented default (Ed25519) — an unset alg
// is not a policy violation.
var ApprovedAlgs = map[string]struct{}{
	"":        {},
	"eddsa":   {},
	"ed25519": {},
	"es256":   {},
	"ecdsa":   {},
	"rs256":   {},
	"ps256":   {},
	"rsa":     {},
}

// RuntimeEnabled reports whether the running binary's Go Cryptographic
// Module is actually active — i.e. it was built with GOFIPS140 set, or is
// running with GODEBUG=fips140=on/only. Thin wrapper so callers elsewhere in
// this repo don't each need their own crypto/fips140 import.
func RuntimeEnabled() bool {
	return fips140.Enabled()
}

// ValidateIssuerAlg gates JWT-issuer construction against this
// deployment's FIPS 140-3 policy. alg is config.SigningConfig.Alg
// (case/whitespace-insensitive); allowlist optionally narrows ApprovedAlgs
// to a stricter subset (nil/empty = ApprovedAlgs unmodified).
//
// When fipsMode is false this always returns nil — the default, byte-
// identical path for every deployment that doesn't opt in. When true, it
// first requires the runtime to actually be FIPS-enabled (catching an
// operator who set keys.signing.fips_mode without a GOFIPS140 build or
// GODEBUG=fips140=on/only — a config flag alone provides no protection),
// then checks alg against the effective allowlist.
func ValidateIssuerAlg(fipsMode bool, alg string, allowlist []string) error {
	if !fipsMode {
		return nil
	}
	if !RuntimeEnabled() {
		return fmt.Errorf("keys.signing.fips_mode is enabled but this binary's Go Cryptographic Module is not active " +
			"(build with GOFIPS140=latest, or run with GODEBUG=fips140=on/only; see docs/fips.md)")
	}
	return checkAlgAllowed(alg, allowlist)
}

// checkAlgAllowed is the pure alg-vs-allowlist decision, split out from
// ValidateIssuerAlg so it can be unit-tested without a GOFIPS140/
// GODEBUG=fips140 build (RuntimeEnabled() is otherwise always false in a
// plain `go test` run, which would make the allowlist-narrowing behavior
// untestable in ordinary CI).
func checkAlgAllowed(alg string, allowlist []string) error {
	normalized := strings.ToLower(strings.TrimSpace(alg))
	allowed := ApprovedAlgs
	if len(allowlist) > 0 {
		allowed = normalizeAllowlist(allowlist)
	}
	if _, ok := allowed[normalized]; ok {
		return nil
	}

	shown := alg
	if strings.TrimSpace(shown) == "" {
		shown = "eddsa (default)"
	}
	return fmt.Errorf("keys.signing.fips_mode: signing algorithm %q is not in the FIPS-mode allowlist "+
		"(keys.signing.fips_allowed_algs, or the default eddsa/es256/rs256/ps256); see docs/fips.md", shown)
}

// normalizeAllowlist lowercases + trims an operator-supplied
// FIPSAllowedAlgs list into a lookup set.
func normalizeAllowlist(allowlist []string) map[string]struct{} {
	out := make(map[string]struct{}, len(allowlist))
	for _, a := range allowlist {
		out[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	return out
}
