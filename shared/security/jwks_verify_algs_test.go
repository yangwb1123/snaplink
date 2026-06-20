package security_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// VerifyCompactJWS is the shared signature primitive behind
// private_key_jwt, JAR, DPoP and SPIFFE-SVID. spiffe_svid_test.go
// already covers ES256/EdDSA/PS256; this table fills in the remaining
// curve/hash sizes (ES384, ES512, RS256/384/512, PS384/PS512) so every
// branch of verifyJWSWithJWK / hashForAlg / digestOf is exercised.

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ecCoordWidth returns the per-scalar R||S byte width for an ES alg.
func ecCoordWidth(alg string) int {
	switch alg {
	case "ES256":
		return 32
	case "ES384":
		return 48
	case "ES512":
		return 66
	default:
		return 0
	}
}

// signECDSA returns a fixed-width R||S signature (RFC 7518 §3.4).
func signECDSA(t *testing.T, priv *ecdsa.PrivateKey, alg string, input []byte) []byte {
	t.Helper()
	digest := hashInput(alg, input)
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatalf("ecdsa sign: %v", err)
	}
	w := ecCoordWidth(alg)
	out := make([]byte, 2*w)
	r.FillBytes(out[:w])
	s.FillBytes(out[w:])
	return out
}

func hashInput(alg string, input []byte) []byte {
	switch alg[1:] { // strip leading E/R/P, keep the size suffix
	case "S256":
		d := sha256.Sum256(input)
		return d[:]
	case "S384":
		d := sha512.Sum384(input)
		return d[:]
	case "S512":
		d := sha512.Sum512(input)
		return d[:]
	}
	return nil
}

func cryptoHash(alg string) crypto.Hash {
	switch alg[1:] {
	case "S256":
		return crypto.SHA256
	case "S384":
		return crypto.SHA384
	case "S512":
		return crypto.SHA512
	}
	return 0
}

// compactJWS assembles the b64url header.payload.sig string.
func compactJWS(alg, kid string, claims map[string]any, sign func(input []byte) []byte) string {
	header := map[string]any{"alg": alg, "typ": "JWT"}
	if kid != "" {
		header["kid"] = kid
	}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	input := b64(hb) + "." + b64(pb)
	return input + "." + b64(sign([]byte(input)))
}

func TestVerifyCompactJWS_AllECCurves(t *testing.T) {
	t.Parallel()
	curves := map[string]elliptic.Curve{
		"ES384": elliptic.P384(),
		"ES512": elliptic.P521(),
	}
	crvName := map[string]string{"ES384": "P-384", "ES512": "P-521"}

	for alg, curve := range curves {
		alg, curve := alg, curve
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			priv, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatalf("gen ec: %v", err)
			}
			w := ecCoordWidth(alg)
			xb := make([]byte, w)
			yb := make([]byte, w)
			priv.X.FillBytes(xb)
			priv.Y.FillBytes(yb)
			jwk := core.JWK{Kty: "EC", Crv: crvName[alg], Kid: "k1", Use: "sig", Alg: alg, X: b64(xb), Y: b64(yb)}

			token := compactJWS(alg, "k1", map[string]any{"sub": "x"}, func(in []byte) []byte {
				return signECDSA(t, priv, alg, in)
			})
			if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{alg: {}}); err != nil {
				t.Fatalf("%s verify: %v", alg, err)
			}
		})
	}
}

func TestVerifyCompactJWS_AllRSASizes(t *testing.T) {
	t.Parallel()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	eb := big.NewInt(int64(priv.E)).Bytes()
	mkJWK := func(alg string) core.JWK {
		return core.JWK{Kty: "RSA", Kid: "k1", Use: "sig", Alg: alg, N: b64(priv.N.Bytes()), E: b64(eb)}
	}

	for _, alg := range []string{"RS256", "RS384", "RS512"} {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			token := compactJWS(alg, "k1", map[string]any{"sub": "x"}, func(in []byte) []byte {
				sig, err := rsa.SignPKCS1v15(rand.Reader, priv, cryptoHash(alg), hashInput(alg, in))
				if err != nil {
					t.Fatalf("sign pkcs1: %v", err)
				}
				return sig
			})
			if _, err := security.VerifyCompactJWS(token, []core.JWK{mkJWK(alg)}, map[string]struct{}{alg: {}}); err != nil {
				t.Fatalf("%s verify: %v", alg, err)
			}
		})
	}

	for _, alg := range []string{"PS384", "PS512"} {
		alg := alg
		t.Run(alg, func(t *testing.T) {
			t.Parallel()
			token := compactJWS(alg, "k1", map[string]any{"sub": "x"}, func(in []byte) []byte {
				sig, err := rsa.SignPSS(rand.Reader, priv, cryptoHash(alg), hashInput(alg, in), &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       cryptoHash(alg),
				})
				if err != nil {
					t.Fatalf("sign pss: %v", err)
				}
				return sig
			})
			if _, err := security.VerifyCompactJWS(token, []core.JWK{mkJWK(alg)}, map[string]struct{}{alg: {}}); err != nil {
				t.Fatalf("%s verify: %v", alg, err)
			}
		})
	}
}

func TestVerifyCompactJWS_ESWrongSignatureLength(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	jwk := core.JWK{Kty: "EC", Crv: "P-256", Kid: "k1", Use: "sig", Alg: "ES256", X: b64(xb), Y: b64(yb)}
	// A DER-shaped (variable-length) signature must be rejected — ES
	// expects fixed-width R||S, not ASN.1 DER.
	token := compactJWS("ES256", "k1", map[string]any{"sub": "x"}, func(in []byte) []byte {
		return []byte("short") // wrong length on purpose
	})
	if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"ES256": {}}); err == nil {
		t.Fatal("ES256 accepted a wrong-length signature")
	}
}

func TestVerifyCompactJWS_KidSelection(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	jwk := core.JWK{Kty: "EC", Crv: "P-256", Kid: "k1", Use: "sig", Alg: "ES256", X: b64(xb), Y: b64(yb)}
	sign := func(in []byte) []byte { return signECDSA(t, priv, "ES256", in) }

	t.Run("empty kid single key OK", func(t *testing.T) {
		t.Parallel()
		token := compactJWS("ES256", "", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"ES256": {}}); err != nil {
			t.Fatalf("single-key empty-kid: %v", err)
		}
	})

	t.Run("empty kid multi key ambiguous", func(t *testing.T) {
		t.Parallel()
		// Two keys + no kid in the header → ambiguous → rejected.
		jwk2 := jwk
		jwk2.Kid = "k2"
		token := compactJWS("ES256", "", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk, jwk2}, map[string]struct{}{"ES256": {}}); err == nil {
			t.Fatal("multi-key empty-kid not rejected as ambiguous")
		}
	})

	t.Run("no matching kid", func(t *testing.T) {
		t.Parallel()
		token := compactJWS("ES256", "no-such", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"ES256": {}}); err == nil {
			t.Fatal("non-matching kid not rejected")
		}
	})

	t.Run("empty JWKS", func(t *testing.T) {
		t.Parallel()
		token := compactJWS("ES256", "k1", map[string]any{"sub": "x"}, sign)
		if _, err := security.VerifyCompactJWS(token, nil, map[string]struct{}{"ES256": {}}); err == nil {
			t.Fatal("empty JWKS not rejected")
		}
	})
}

func TestVerifyCompactJWS_AlgNotInAllowlist(t *testing.T) {
	t.Parallel()
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xb := make([]byte, 32)
	yb := make([]byte, 32)
	priv.X.FillBytes(xb)
	priv.Y.FillBytes(yb)
	jwk := core.JWK{Kty: "EC", Crv: "P-256", Kid: "k1", Use: "sig", Alg: "ES256", X: b64(xb), Y: b64(yb)}
	token := compactJWS("ES256", "k1", map[string]any{"sub": "x"}, func(in []byte) []byte {
		return signECDSA(t, priv, "ES256", in)
	})
	// ES256 is valid but absent from the (RS256-only) allowlist → rejected
	// before any signature work.
	if _, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, map[string]struct{}{"RS256": {}}); err == nil {
		t.Fatal("alg outside allowlist accepted")
	}
}
