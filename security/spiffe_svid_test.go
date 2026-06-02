package security_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

// --- SPIFFE-ID parsing ---

func TestParseSPIFFEURI_Valid(t *testing.T) {
	id, err := security.ParseSPIFFEURI("spiffe://example.org/ns/prod/sa/payments")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id.TrustDomain != "example.org" {
		t.Errorf("trust domain = %q", id.TrustDomain)
	}
	if id.Namespace != "prod" || id.ServiceAccount != "payments" {
		t.Errorf("ns/sa = %q/%q", id.Namespace, id.ServiceAccount)
	}
	attrs := id.Attributes()
	if attrs[security.AttrSPIFFETrustDomain] != "example.org" ||
		attrs[security.AttrSPIFFENamespace] != "prod" ||
		attrs[security.AttrSPIFFEServiceAccount] != "payments" {
		t.Errorf("attributes = %v", attrs)
	}
}

func TestParseSPIFFEURI_NonK8sPath(t *testing.T) {
	id, err := security.ParseSPIFFEURI("spiffe://example.org/workload/frontend")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if id.Namespace != "" || id.ServiceAccount != "" {
		t.Errorf("ns/sa should be empty for non-k8s path: %q/%q", id.Namespace, id.ServiceAccount)
	}
	// Still carries trust domain + full id.
	attrs := id.Attributes()
	if attrs[security.AttrSPIFFETrustDomain] != "example.org" {
		t.Errorf("trust domain attr missing: %v", attrs)
	}
}

func TestParseSPIFFEURI_Rejects(t *testing.T) {
	cases := []string{
		"",
		"https://example.org/x",            // wrong scheme
		"spiffe:///ns/x/sa/y",              // empty trust domain
		"spiffe://EXAMPLE.org/x",           // uppercase trust domain
		"spiffe://example.org:8443/x",      // port
		"spiffe://example.org/a//b",        // empty path segment
		"spiffe://example.org/x?foo=bar",   // query
		"spiffe://example.org/x#frag",      // fragment
		"spiffe://user@example.org/x",      // userinfo
		"not-a-uri at all with spaces ://", // garbage
	}
	for _, c := range cases {
		if _, err := security.ParseSPIFFEURI(c); err == nil {
			t.Errorf("ParseSPIFFEURI(%q) = nil err, want rejection", c)
		}
	}
}

// --- test SVID minting helpers (real keys, no mocks) ---

type testKey struct {
	es25519 ed25519.PrivateKey
	ecdsa   *ecdsa.PrivateKey
	rsa     *rsa.PrivateKey
	kid     string
	jwk     core.JWK
	alg     string
}

// newPS256Key generates an RSA key of bits size and returns it as a PS256
// signing key whose JWK carries the modulus/exponent. bits < 2048 produces a
// weak key (used to assert the trust-bundle RSA floor).
func newPS256Key(t *testing.T, kid string, bits int) testKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	eb := big.NewInt(int64(priv.E)).Bytes()
	return testKey{
		rsa: priv,
		kid: kid,
		alg: "PS256",
		jwk: core.JWK{
			Kty: "RSA", Kid: kid, Use: "sig", Alg: "PS256",
			N: base64.RawURLEncoding.EncodeToString(priv.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(eb),
		},
	}
}

func newES256Key(t *testing.T, kid string) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ec: %v", err)
	}
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	return testKey{
		ecdsa: priv,
		kid:   kid,
		alg:   "ES256",
		jwk: core.JWK{
			Kty: "EC", Crv: "P-256", Kid: kid, Use: "sig", Alg: "ES256",
			X: base64.RawURLEncoding.EncodeToString(xb),
			Y: base64.RawURLEncoding.EncodeToString(yb),
		},
	}
}

func newEdDSAKey(t *testing.T, kid string) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	return testKey{
		es25519: priv,
		kid:     kid,
		alg:     "EdDSA",
		jwk: core.JWK{
			Kty: "OKP", Crv: "Ed25519", Kid: kid, Use: "sig", Alg: "EdDSA",
			X: base64.RawURLEncoding.EncodeToString(pub),
		},
	}
}

// mintSVID signs a compact JWS with the given header alg/kid and claims.
// algOverride lets a test forge an `alg` header that differs from the key
// (alg=none / confusion cases).
func mintSVID(t *testing.T, k testKey, algOverride string, claims map[string]any) string {
	t.Helper()
	alg := k.alg
	if algOverride != "" {
		alg = algOverride
	}
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if k.kid != "" {
		header["kid"] = k.kid
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)

	var sig []byte
	switch alg {
	case "none":
		sig = nil
	case "EdDSA":
		sig = ed25519.Sign(k.es25519, []byte(signingInput))
	case "ES256":
		digest := sha256.Sum256([]byte(signingInput))
		r, s, err := ecdsa.Sign(rand.Reader, k.ecdsa, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
		out := make([]byte, 64)
		r.FillBytes(out[:32])
		s.FillBytes(out[32:])
		sig = out
	case "PS256":
		// Standard-signer behavior: go-jose / golang-jwt (and SPIRE) use
		// PSSSaltLengthAuto, i.e. the MAXIMUM salt, NOT the hash length.
		digest := sha256.Sum256([]byte(signingInput))
		out, err := rsa.SignPSS(rand.Reader, k.rsa, crypto.SHA256, digest[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			t.Fatalf("sign pss: %v", err)
		}
		sig = out
	default:
		t.Fatalf("unsupported test alg %q", alg)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func baseClaims(sub, aud string) map[string]any {
	now := time.Now()
	return map[string]any{
		"sub": sub,
		"aud": aud,
		"iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(),
	}
}

// --- VerifyCompactJWS primitive ---

func TestVerifyCompactJWS_RejectsSymmetricAllowlist(t *testing.T) {
	k := newES256Key(t, "k1")
	svid := mintSVID(t, k, "", baseClaims("spiffe://example.org/x", "aud"))
	// An HS256 in the allowlist must be refused outright.
	_, err := security.VerifyCompactJWS(svid, []core.JWK{k.jwk}, map[string]struct{}{"HS256": {}})
	if err == nil {
		t.Fatal("expected refusal of symmetric alg in allowlist")
	}
}

func TestVerifyCompactJWS_RejectsAlgNone(t *testing.T) {
	k := newES256Key(t, "k1")
	svid := mintSVID(t, k, "none", baseClaims("spiffe://example.org/x", "aud"))
	_, err := security.VerifyCompactJWS(svid, []core.JWK{k.jwk}, map[string]struct{}{"ES256": {}})
	if err == nil {
		t.Fatal("expected alg=none rejection")
	}
}

// --- SPIFFEValidator happy path + security cases ---

const (
	testTrustDomain = "example.org"
	testAudience    = "https://sso.example/"
	testSub         = "spiffe://example.org/ns/prod/sa/payments"
)

func newValidator(t *testing.T, keys ...core.JWK) *security.SPIFFEValidator {
	t.Helper()
	src := security.NewStaticJWKS(keys)
	v, err := security.NewSPIFFEValidator(testTrustDomain, src)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	return v
}

func TestSPIFFEValidator_HappyPath_ES256(t *testing.T) {
	k := newES256Key(t, "spire-1")
	v := newValidator(t, k.jwk)
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))

	id, err := v.Validate(context.Background(), svid, testAudience)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if id.URI != testSub {
		t.Errorf("uri = %q", id.URI)
	}
	if id.Namespace != "prod" || id.ServiceAccount != "payments" {
		t.Errorf("ns/sa = %q/%q", id.Namespace, id.ServiceAccount)
	}
}

func TestSPIFFEValidator_HappyPath_EdDSA(t *testing.T) {
	k := newEdDSAKey(t, "spire-ed")
	v := newValidator(t, k.jwk)
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))
	if _, err := v.Validate(context.Background(), svid, testAudience); err != nil {
		t.Fatalf("validate eddsa: %v", err)
	}
}

// TestSPIFFEValidator_HappyPath_PS256 mints a PS256 JWT-SVID with the
// standard auto/max salt (rsa.PSSSaltLengthAuto) and asserts it VERIFIES.
// Before the verify-side fix (PSSSaltLengthEqualsHash), this auto-salt
// signature was rejected with crypto/rsa: verification error →
// ErrSPIFFESVIDInvalid, silently breaking the allowlisted PS256 branch.
func TestSPIFFEValidator_HappyPath_PS256(t *testing.T) {
	k := newPS256Key(t, "spire-ps", 2048)
	v := newValidator(t, k.jwk)
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))
	if _, err := v.Validate(context.Background(), svid, testAudience); err != nil {
		t.Fatalf("validate ps256 (auto-salt): %v", err)
	}
}

// TestSPIFFEValidator_WeakRSAKeyRejected: a trust-bundle RSA key below the
// 2048-bit floor (RFC 7518 §3.3) is rejected. The external trust boundary
// must meet the same modulus floor as keys the SSO itself issues.
func TestSPIFFEValidator_WeakRSAKeyRejected(t *testing.T) {
	k := newPS256Key(t, "weak-rsa", 1024) // below the 2048-bit minimum
	v := newValidator(t, k.jwk)
	svid := mintSVID(t, k, "", baseClaims(testSub, testAudience))
	_, err := v.Validate(context.Background(), svid, testAudience)
	if err == nil {
		t.Fatal("expected weak (1024-bit) RSA trust-bundle key to be rejected")
	}
	if err != security.ErrSPIFFESVIDInvalid {
		t.Errorf("err = %v want ErrSPIFFESVIDInvalid (oracle-safe)", err)
	}
}

func TestSPIFFEValidator_AudInArrayAccepted(t *testing.T) {
	k := newES256Key(t, "spire-1")
	v := newValidator(t, k.jwk)
	claims := baseClaims(testSub, "")
	claims["aud"] = []string{"https://other/", testAudience}
	svid := mintSVID(t, k, "", claims)
	if _, err := v.Validate(context.Background(), svid, testAudience); err != nil {
		t.Fatalf("validate array aud: %v", err)
	}
}

// SECURITY cases — each MUST fail with the SINGLE opaque error.

func TestSPIFFEValidator_SecurityRejections(t *testing.T) {
	good := newES256Key(t, "spire-1")
	other := newES256Key(t, "attacker") // NOT in the bundle

	cases := []struct {
		name string
		// build returns the compact SVID + the validator to run it on.
		build func(t *testing.T) (string, *security.SPIFFEValidator)
	}{
		{
			name: "wrong trust domain",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				v := newValidator(t, good.jwk)
				return mintSVID(t, good, "", baseClaims("spiffe://evil.example/ns/x/sa/y", testAudience)), v
			},
		},
		{
			name: "aud mismatch (minted for service-B, used for service-A)",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				v := newValidator(t, good.jwk)
				// SVID aud is service-B; we ask validate for service-A.
				return mintSVID(t, good, "", baseClaims(testSub, "https://service-b/")), v
			},
		},
		{
			name: "expired svid",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				v := newValidator(t, good.jwk)
				c := baseClaims(testSub, testAudience)
				c["iat"] = time.Now().Add(-10 * time.Minute).Unix()
				c["exp"] = time.Now().Add(-5 * time.Minute).Unix()
				return mintSVID(t, good, "", c), v
			},
		},
		{
			name: "bad signature (key not in bundle)",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				// Validator trusts `good`; SVID is signed by `other`
				// but carries good's kid so it resolves to good's key
				// and the signature fails to verify.
				v := newValidator(t, good.jwk)
				forged := other
				forged.kid = good.kid
				return mintSVID(t, forged, "", baseClaims(testSub, testAudience)), v
			},
		},
		{
			name: "alg=none",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				v := newValidator(t, good.jwk)
				return mintSVID(t, good, "none", baseClaims(testSub, testAudience)), v
			},
		},
		{
			name: "malformed spiffe sub",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				v := newValidator(t, good.jwk)
				return mintSVID(t, good, "", baseClaims("https://not-spiffe/x", testAudience)), v
			},
		},
		{
			name: "unknown kid",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				v := newValidator(t, good.jwk)
				k := good
				k.kid = "no-such-kid"
				return mintSVID(t, k, "", baseClaims(testSub, testAudience)), v
			},
		},
		{
			name: "garbage token",
			build: func(t *testing.T) (string, *security.SPIFFEValidator) {
				return "not-a-jwt", newValidator(t, good.jwk)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svid, v := tc.build(t)
			_, err := v.Validate(context.Background(), svid, testAudience)
			if err == nil {
				t.Fatalf("%s: expected rejection", tc.name)
			}
			// Oracle-leak: every failure is the SAME opaque error.
			if err != security.ErrSPIFFESVIDInvalid {
				t.Errorf("%s: err = %v want ErrSPIFFESVIDInvalid (no per-cause oracle)", tc.name, err)
			}
		})
	}
}

func TestSPIFFEValidator_RSConfusionRejected(t *testing.T) {
	// An attacker who knows the EC public key cannot get it treated as an
	// HMAC secret: the validator's allowlist is asymmetric-only, and an
	// HS256-header token never reaches signature verification.
	k := newES256Key(t, "spire-1")
	v := newValidator(t, k.jwk)
	// Forge an HS256 header (we don't even need a valid MAC — the alg
	// gate rejects it before any verification).
	header := map[string]any{"alg": "HS256", "typ": "JWT", "kid": k.kid}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(baseClaims(testSub, testAudience))
	signingInput := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(pb)
	// "Sign" with the EC public key bytes as if they were an HMAC secret —
	// irrelevant, the alg gate fires first.
	forged := signingInput + "." + base64.RawURLEncoding.EncodeToString([]byte("whatever"))
	if _, err := v.Validate(context.Background(), forged, testAudience); err != security.ErrSPIFFESVIDInvalid {
		t.Fatalf("HS-confusion not rejected opaquely: %v", err)
	}
}

func TestNewSPIFFEValidator_RequiresArgs(t *testing.T) {
	src := security.NewStaticJWKS(nil)
	if _, err := security.NewSPIFFEValidator("", src); err == nil {
		t.Error("empty trust domain accepted")
	}
	if _, err := security.NewSPIFFEValidator("example.org", nil); err == nil {
		t.Error("nil source accepted")
	}
}

func TestParseStaticJWKS_RejectsEmpty(t *testing.T) {
	if _, err := security.ParseStaticJWKS([]byte(`{"keys":[]}`)); err == nil {
		t.Error("empty keys accepted")
	}
	if _, err := security.ParseStaticJWKS([]byte(`not json`)); err == nil {
		t.Error("bad json accepted")
	}
	k := newES256Key(t, "k1")
	doc, _ := json.Marshal(map[string]any{"keys": []core.JWK{k.jwk}})
	src, err := security.ParseStaticJWKS(doc)
	if err != nil {
		t.Fatalf("parse valid bundle: %v", err)
	}
	keys, _ := src.GetJWKS(context.Background())
	if len(keys) != 1 || keys[0].Kid != "k1" {
		t.Errorf("round-trip keys = %v", keys)
	}
}

// guard: P-521 coord width sanity (the digestOf/coordBytes wiring) via a
// happy ES256 path already exercised; this confirms multi-key kid select.
func TestSPIFFEValidator_MultiKeyBundleSelectsByKid(t *testing.T) {
	k1 := newES256Key(t, "k1")
	k2 := newEdDSAKey(t, "k2")
	v := newValidator(t, k1.jwk, k2.jwk)
	// Mint with k2; must select k2 by kid out of the 2-key bundle.
	svid := mintSVID(t, k2, "", baseClaims(testSub, testAudience))
	if _, err := v.Validate(context.Background(), svid, testAudience); err != nil {
		t.Fatalf("multi-key select: %v", err)
	}
}
