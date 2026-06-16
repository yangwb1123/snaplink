package security_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

// Malformed-input + malformed-key error branches of VerifyCompactJWS
// and the public-key reconstructors. Each must fail (fail-closed); the
// kty/crv consistency checks defend against alg-confusion via a JWK
// whose key type doesn't match the header alg.

func es256JWK(t *testing.T) (core.JWK, func(in []byte) []byte) {
	t.Helper()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	jwk := core.JWK{Kty: "EC", Crv: "P-256", Kid: "k1", Use: "sig", Alg: "ES256", X: b64(xb), Y: b64(yb)}
	return jwk, func(in []byte) []byte { return signECDSA(t, priv, "ES256", in) }
}

func TestVerifyCompactJWS_MalformedInputs(t *testing.T) {
	t.Parallel()
	jwk, sign := es256JWK(t)
	allow := map[string]struct{}{"ES256": {}}

	t.Run("empty allowlist", func(t *testing.T) {
		t.Parallel()
		token := compactJWS("ES256", "k1", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{}); err == nil {
			t.Fatal("empty allowlist accepted")
		}
	})

	t.Run("not three segments", func(t *testing.T) {
		t.Parallel()
		if _, err := security.VerifyCompactJWS("only.two", []core.JWK{jwk}, allow); err == nil {
			t.Fatal("two-segment token accepted")
		}
		if _, err := security.VerifyCompactJWS("a.b.c.d", []core.JWK{jwk}, allow); err == nil {
			t.Fatal("four-segment token accepted")
		}
		if _, err := security.VerifyCompactJWS("a.b.", []core.JWK{jwk}, allow); err == nil {
			t.Fatal("empty trailing segment accepted")
		}
	})

	t.Run("bad header base64", func(t *testing.T) {
		t.Parallel()
		if _, err := security.VerifyCompactJWS("!!!.eyJ9.sig", []core.JWK{jwk}, allow); err == nil {
			t.Fatal("undecodable header accepted")
		}
	})

	t.Run("bad header json", func(t *testing.T) {
		t.Parallel()
		bad := base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".eyJ9.c2ln"
		if _, err := security.VerifyCompactJWS(bad, []core.JWK{jwk}, allow); err == nil {
			t.Fatal("non-json header accepted")
		}
	})

	t.Run("bad signature base64", func(t *testing.T) {
		t.Parallel()
		// Valid header + payload, but signature segment is not base64url.
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","kid":"k1"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
		token := header + "." + payload + ".!!!notb64"
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, allow); err == nil {
			t.Fatal("undecodable signature accepted")
		}
	})
}

func TestPublicKeyReconstruct_MalformedKeys(t *testing.T) {
	t.Parallel()

	t.Run("EdDSA wrong kty", func(t *testing.T) {
		t.Parallel()
		// Header says EdDSA but the JWK is an EC key → mismatch rejected.
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		_ = pub
		ecJWK := core.JWK{Kty: "EC", Crv: "P-256", Kid: "k1", Alg: "EdDSA", X: "AA", Y: "AA"}
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
		sig := ed25519.Sign(priv, []byte(header+"."+payload))
		token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{ecJWK}, map[string]struct{}{"EdDSA": {}}); err == nil {
			t.Fatal("EdDSA header with EC JWK accepted")
		}
	})

	t.Run("EdDSA malformed x", func(t *testing.T) {
		t.Parallel()
		priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		// X is valid base64 but the wrong length for an Ed25519 public key.
		badJWK := core.JWK{Kty: "OKP", Crv: "Ed25519", Kid: "k1", Alg: "EdDSA", X: base64.RawURLEncoding.EncodeToString([]byte("short"))}
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","kid":"k1"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
		sig := ed25519.Sign(priv, []byte(header+"."+payload))
		token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString(sig)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{badJWK}, map[string]struct{}{"EdDSA": {}}); err == nil {
			t.Fatal("wrong-length Ed25519 X accepted")
		}
	})

	t.Run("ECDSA wrong curve", func(t *testing.T) {
		t.Parallel()
		// Header alg ES256 (wants P-256) but JWK declares P-384 → rejected.
		jwk, sign := es256JWK(t)
		jwk.Crv = "P-384"
		token := compactJWS("ES256", "k1", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"ES256": {}}); err == nil {
			t.Fatal("ES256 with P-384-declared JWK accepted")
		}
	})

	t.Run("ECDSA malformed x", func(t *testing.T) {
		t.Parallel()
		jwk, sign := es256JWK(t)
		jwk.X = "!!!not-base64"
		token := compactJWS("ES256", "k1", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"ES256": {}}); err == nil {
			t.Fatal("undecodable EC x accepted")
		}
	})

	t.Run("ECDSA off-curve point", func(t *testing.T) {
		t.Parallel()
		// X/Y decode fine but the point is not on P-256 (invalid-curve
		// attack surface) → rejected.
		jwk, sign := es256JWK(t)
		jwk.X = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) // (0,0)
		jwk.Y = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
		token := compactJWS("ES256", "k1", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"ES256": {}}); err == nil {
			t.Fatal("off-curve EC point accepted")
		}
	})

	t.Run("RSA below 2048-bit floor", func(t *testing.T) {
		t.Parallel()
		// A short modulus (< 256 bytes) is a weak key — rejected per
		// RFC 7518 §3.3 even though the rest of the JWK is well-formed.
		shortN := base64.RawURLEncoding.EncodeToString(make([]byte, 64)) // 512-bit
		jwk := core.JWK{Kty: "RSA", Kid: "k1", Alg: "RS256", N: shortN, E: "AQAB"}
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
		token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"RS256": {}}); err == nil {
			t.Fatal("sub-2048-bit RSA key accepted")
		}
	})

	t.Run("RSA wrong kty", func(t *testing.T) {
		t.Parallel()
		// RS256 header but the JWK is EC → kty mismatch rejected.
		jwk, _ := es256JWK(t)
		jwk.Alg = "RS256"
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
		payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"x"}`))
		token := header + "." + payload + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"RS256": {}}); err == nil {
			t.Fatal("RS256 header with EC JWK accepted")
		}
	})
}
