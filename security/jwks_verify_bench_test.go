package security_test

// Hot-path benchmark for security.VerifyCompactJWS — the alg-gated
// asymmetric-JWS verifier on the hot path for DPoP proofs,
// private_key_jwt client assertions, JAR request objects, SPIFFE
// JWT-SVIDs, and inbound SETs. It parses the compact JWS, enforces the
// alg allowlist BEFORE touching the signature (alg-confusion defense),
// then verifies. Benchmarked over a valid EdDSA token + its OKP JWK.
//
// External test package (security_test) so the bench depends only on the
// exported surface. Dep-free: a valid token + JWK are built inline with
// std crypto/ed25519, no issuer import. b.ReportAllocs() + sinks.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

var (
	benchPayloadSink []byte
	benchVerifyErr   error
)

// buildEdDSAJWS mints a real 3-segment EdDSA compact JWS over a
// representative access-token-shaped payload and returns it with the
// matching OKP JWK the verifier resolves by kid.
func buildEdDSAJWS(b *testing.B) (string, []core.JWK) {
	b.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("generate key: %v", err)
	}
	const kid = "bench-kid-1"

	header := map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": kid}
	payload := map[string]any{
		"iss":   "https://sso.example.com",
		"sub":   "user-1234567890",
		"aud":   "web-app",
		"iat":   1700000000,
		"exp":   1700003600,
		"jti":   "0123456789abcdef0123456789abcdef",
		"scope": "openid profile email offline_access",
	}

	hb, err := json.Marshal(header)
	if err != nil {
		b.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		b.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(hb) + "." + enc.EncodeToString(pb)
	sig := ed25519.Sign(priv, []byte(signingInput))
	compact := signingInput + "." + enc.EncodeToString(sig)

	jwks := []core.JWK{{
		Kty: "OKP",
		Crv: "Ed25519",
		Use: "sig",
		Alg: "EdDSA",
		Kid: kid,
		X:   enc.EncodeToString(pub),
	}}
	return compact, jwks
}

func BenchmarkVerifyCompactJWS_EdDSA(b *testing.B) {
	compact, jwks := buildEdDSAJWS(b)
	algs := security.AsymmetricJWSAlgs()

	// Sanity: confirm the token actually verifies before timing it, so a
	// silently-failing fast-path can't masquerade as a fast benchmark.
	if _, err := security.VerifyCompactJWS(compact, jwks, algs); err != nil {
		b.Fatalf("precondition verify failed: %v", err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		payload, err := security.VerifyCompactJWS(compact, jwks, algs)
		benchPayloadSink, benchVerifyErr = payload, err
	}
}
