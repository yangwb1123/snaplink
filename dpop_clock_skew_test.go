package sso

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

// signDPoPProofWithIAT mints a minimal valid DPoP proof JWT (EdDSA /
// OKP-Ed25519) for the given method+URL with a caller-supplied iat. Only
// the fields verifyDPoPProof inspects are populated. No nonce is set
// (these tests wire no nonce provider).
func signDPoPProofWithIAT(t *testing.T, priv ed25519.PrivateKey, pubX string, method, url string, iat int64) string {
	t.Helper()
	header := map[string]any{
		"alg": "EdDSA",
		"typ": dpopProofTyp,
		"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": pubX},
	}
	payload := map[string]any{
		"htm": method,
		"htu": url,
		"iat": iat,
		"jti": "dpop-jti-" + randomTokenForTest(),
	}
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(payload)
	signingInput := base64.RawURLEncoding.EncodeToString(hraw) + "." + base64.RawURLEncoding.EncodeToString(praw)
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func randomTokenForTest() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func dpopKeyForTest(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	return priv, base64.RawURLEncoding.EncodeToString(pub)
}

// TestDPoPProofClockSkewConfigurable proves WithDPoPMaxClockSkew honors a
// future-iat window wider than the 60s default, while the default still
// rejects beyond 60s. A proof's iat in the FUTURE is gated by clock-skew.
func TestDPoPProofClockSkewConfigurable(t *testing.T) {
	const method = "POST"
	const url = "https://sso.test/token"
	priv, pubX := dpopKeyForTest(t)

	// iat 90s in the future: beyond the 60s default, within a 5m skew.
	futureIAT := time.Now().Add(90 * time.Second).Unix()

	// Default server (no skew option) MUST reject a 90s-future proof —
	// this locks the byte-identical 60s default behavior.
	def := NewServer()
	proof := signDPoPProofWithIAT(t, priv, pubX, method, url, futureIAT)
	if _, err := verifyDPoPProof(
		context.Background(), proof, method, url,
		nil, false, nil,
		def.resolvedDPoPProofMaxAge(), def.resolvedDPoPProofClockSkew(),
	); err == nil {
		t.Fatalf("default 60s skew: 90s-future iat accepted, want reject")
	}

	// Server with a 5m skew MUST accept the 90s-future proof.
	loose := NewServer(WithDPoPMaxClockSkew(5 * time.Minute))
	proof = signDPoPProofWithIAT(t, priv, pubX, method, url, futureIAT)
	if _, err := verifyDPoPProof(
		context.Background(), proof, method, url,
		nil, false, nil,
		loose.resolvedDPoPProofMaxAge(), loose.resolvedDPoPProofClockSkew(),
	); err != nil {
		t.Fatalf("5m skew: 90s-future iat rejected: %v", err)
	}

	// ...but a proof beyond the configured 5m skew (10m future) is still
	// rejected — the wider window is bounded, not unbounded.
	beyond := signDPoPProofWithIAT(t, priv, pubX, method, url, time.Now().Add(10*time.Minute).Unix())
	if _, err := verifyDPoPProof(
		context.Background(), beyond, method, url,
		nil, false, nil,
		loose.resolvedDPoPProofMaxAge(), loose.resolvedDPoPProofClockSkew(),
	); err == nil {
		t.Fatalf("5m skew: 10m-future iat accepted, want reject")
	}
}

// TestDPoPProofMaxAgeConfigurable proves WithDPoPProofMaxAge honors a
// staleness window wider than the 60s default, while the default still
// rejects beyond 60s. A proof's iat in the PAST is gated by max-age.
func TestDPoPProofMaxAgeConfigurable(t *testing.T) {
	const method = "POST"
	const url = "https://sso.test/token"
	priv, pubX := dpopKeyForTest(t)

	// iat 90s in the past: beyond the 60s default, within a 5m max-age.
	staleIAT := time.Now().Add(-90 * time.Second).Unix()

	// Default server MUST reject a 90s-stale proof (locks 60s default).
	def := NewServer()
	proof := signDPoPProofWithIAT(t, priv, pubX, method, url, staleIAT)
	if _, err := verifyDPoPProof(
		context.Background(), proof, method, url,
		nil, false, nil,
		def.resolvedDPoPProofMaxAge(), def.resolvedDPoPProofClockSkew(),
	); err == nil {
		t.Fatalf("default 60s max-age: 90s-stale iat accepted, want reject")
	}

	// Server with a 5m max-age MUST accept the 90s-stale proof.
	loose := NewServer(WithDPoPProofMaxAge(5 * time.Minute))
	proof = signDPoPProofWithIAT(t, priv, pubX, method, url, staleIAT)
	if _, err := verifyDPoPProof(
		context.Background(), proof, method, url,
		nil, false, nil,
		loose.resolvedDPoPProofMaxAge(), loose.resolvedDPoPProofClockSkew(),
	); err != nil {
		t.Fatalf("5m max-age: 90s-stale iat rejected: %v", err)
	}

	// ...but a proof older than the configured 5m max-age (10m) is still
	// rejected.
	beyond := signDPoPProofWithIAT(t, priv, pubX, method, url, time.Now().Add(-10*time.Minute).Unix())
	if _, err := verifyDPoPProof(
		context.Background(), beyond, method, url,
		nil, false, nil,
		loose.resolvedDPoPProofMaxAge(), loose.resolvedDPoPProofClockSkew(),
	); err == nil {
		t.Fatalf("5m max-age: 10m-stale iat accepted, want reject")
	}
}

// TestDPoPProofClockSkewClampToDefault proves a non-positive option value
// is ignored (clamps to the 60s default), so the resolver helpers never
// return 0 and an explicit zero/negative is a no-op (byte-identical).
func TestDPoPProofClockSkewClampToDefault(t *testing.T) {
	s := NewServer(WithDPoPMaxClockSkew(0), WithDPoPProofMaxAge(-time.Second))
	if got := s.resolvedDPoPProofClockSkew(); got != dpopProofClockSkewDefault {
		t.Fatalf("clock skew clamp: got %v want %v", got, dpopProofClockSkewDefault)
	}
	if got := s.resolvedDPoPProofMaxAge(); got != dpopProofMaxAgeDefault {
		t.Fatalf("max-age clamp: got %v want %v", got, dpopProofMaxAgeDefault)
	}
}
