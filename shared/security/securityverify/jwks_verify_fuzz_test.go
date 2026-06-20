package securityverify

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

// fuzzVerifyKeys is a fixed, small, asymmetric JWKS the fuzzer verifies the
// arbitrary compact-JWS input against. The Ed25519 OKP key matches the valid
// seed token below (deterministic seed bytes 1..32 → this X coordinate). The
// fuzzer is free to mutate the token any way it likes; the only token that can
// ever verify is one genuinely signed by the matching private key, so the
// "must never accept a forbidden-alg token" assertion has real teeth.
var fuzzVerifyKeys = []core.JWK{
	{
		Kty: "OKP",
		Crv: "Ed25519",
		Use: "sig",
		Kid: "k1",
		X:   "ebVWLo_mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ",
	},
}

// FuzzVerifyCompactJWS throws arbitrary compact-JWS strings at the real
// VerifyCompactJWS against a fixed asymmetric JWKS and asserts the two
// load-bearing security invariants survive ANY input:
//
//   - it NEVER panics (a panic on a malformed externally-minted JWT is a
//     remote DoS — this primitive sits on the SPIFFE / private_key_jwt / JAR
//     / DPoP / federation untrusted-input paths);
//   - it NEVER returns a non-nil payload with a nil error for a token whose
//     header `alg` is `none` or any symmetric HS* — the alg-confusion /
//     public-key-as-HMAC downgrade must always fail closed, regardless of how
//     the rest of the token is shaped.
func FuzzVerifyCompactJWS(f *testing.F) {
	// A genuinely valid EdDSA token (verifies against fuzzVerifyKeys["k1"]).
	f.Add("eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIiwidHlwIjoiSldUIn0.eyJhdWQiOiJzZWxmIiwic3ViIjoic3BpZmZlOi8vZXhhbXBsZS5vcmcvc3ZjIn0.ns7N85tYmlgX-mQsfi1cKBmUMJUkhGSlrHpGz5E0IoXJ-3hFYOSNY3G7JjST0ONK89Dahv_dwjYUiDoFEAEUBg")
	// alg=none unsigned token: {"alg":"none","kid":"k1"}.{}.
	f.Add("eyJhbGciOiJub25lIiwia2lkIjoiazEifQ.e30.")
	// alg=HS256 (symmetric) — the RS/HS confusion shape.
	f.Add("eyJhbGciOiJIUzI1NiIsImtpZCI6ImsxIn0.e30.AAAA")
	// Structurally broken: wrong segment count / empties.
	f.Add("not.a.valid.jws")
	f.Add("")
	f.Add("...")
	f.Add("a.b")
	// Non-base64 header / payload / signature.
	f.Add("!!!.@@@.###")
	// Valid header shape, garbage signature.
	f.Add("eyJhbGciOiJFZERTQSIsImtpZCI6ImsxIn0.eyJhIjoxfQ.____")

	allowed := AsymmetricJWSAlgs()

	f.Fuzz(func(t *testing.T, compact string) {
		payload, err := VerifyCompactJWS(compact, fuzzVerifyKeys, allowed)

		if err != nil {
			// Failure path must not yield a payload.
			if payload != nil {
				t.Fatalf("VerifyCompactJWS returned non-nil payload (%q) alongside error %v", payload, err)
			}
			return
		}

		// Success path: assert the alg the header claimed is asymmetric and
		// NEVER none/HS*. We decode the header ourselves (independent of the
		// implementation) to catch any accept-with-symmetric-alg regression.
		alg := headerAlgOf(compact)
		if alg == "none" || strings.HasPrefix(alg, "HS") {
			t.Fatalf("VerifyCompactJWS ACCEPTED a token with forbidden alg %q: %q", alg, compact)
		}
		if !isAsymmetricJWSAlg(alg) {
			t.Fatalf("VerifyCompactJWS ACCEPTED a token with non-asymmetric alg %q: %q", alg, compact)
		}
		if payload == nil {
			t.Fatalf("VerifyCompactJWS returned nil payload with nil error: %q", compact)
		}
	})
}

// headerAlgOf extracts the `alg` from a compact JWS header WITHOUT reusing the
// implementation under test, so the fuzz assertion is an independent check.
// Returns "" when the header can't be parsed (the token couldn't have
// verified in that case anyway).
func headerAlgOf(compact string) string {
	dot := strings.IndexByte(compact, '.')
	if dot < 0 {
		return ""
	}
	hdr, err := base64.RawURLEncoding.DecodeString(compact[:dot])
	if err != nil {
		return ""
	}
	// Minimal, dependency-free scan for "alg":"...". A real parse isn't worth
	// pulling encoding/json semantics into the oracle; this is robust enough
	// for the forbidden-alg gate (alg values are simple ASCII identifiers).
	const key = `"alg"`
	i := strings.Index(string(hdr), key)
	if i < 0 {
		return ""
	}
	rest := string(hdr)[i+len(key):]
	q1 := strings.IndexByte(rest, '"')
	if q1 < 0 {
		return ""
	}
	rest = rest[q1+1:]
	q2 := strings.IndexByte(rest, '"')
	if q2 < 0 {
		return ""
	}
	return rest[:q2]
}
