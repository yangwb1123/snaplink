package sso

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
)

// RFC 7638 §3.1 worked example. The spec computes the thumbprint of this
// exact RSA public key and publishes the answer, so it is a known-answer
// vector that pins jwkThumbprintRFC7638's RSA canonical form (members
// e/kty/n, lexically ordered, no whitespace). A wrong member set or order
// would produce a different hash and fail here. For DPoP a wrong RSA
// thumbprint is a binding bypass, so this is a security regression guard.
func TestJWKThumbprintRFC7638_RSAKnownAnswer(t *testing.T) {
	t.Parallel()
	const (
		n = "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
			"4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
			"tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
			"QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
			"SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
			"w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw"
		e = "AQAB"
		// Published in RFC 7638 §3.1.
		wantThumbprint = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	)
	got, err := jwkThumbprintRFC7638(JWK{Kty: "RSA", N: n, E: e})
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	if got != wantThumbprint {
		t.Fatalf("RSA thumbprint = %q, want RFC 7638 §3.1 answer %q", got, wantThumbprint)
	}
}

// EC + OKP thumbprints have no single published vector in the RFC, so the
// canonical form is pinned against an independent recomputation of the exact
// member set RFC 7638 §3.2 mandates (EC: crv/kty/x/y; OKP: crv/kty/x). This
// also documents the canonical string so a future edit that reorders members
// is caught.
func TestJWKThumbprintRFC7638_ECCanonicalForm(t *testing.T) {
	t.Parallel()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x, y := ecCoordsP256(t, priv)

	got, err := jwkThumbprintRFC7638(JWK{Kty: "EC", Crv: "P-256", X: x, Y: y})
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	// Independent canonical-form recomputation (members lexically ordered:
	// crv, kty, x, y — no whitespace).
	canonical := `{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("EC thumbprint = %q, want %q (canonical %q)", got, want, canonical)
	}
}

func TestJWKThumbprintRFC7638_OKPCanonicalForm(t *testing.T) {
	t.Parallel()
	x := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	got, err := jwkThumbprintRFC7638(JWK{Kty: "OKP", Crv: "Ed25519", X: x})
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	sum := sha256.Sum256([]byte(canonical))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("OKP thumbprint = %q, want %q", got, want)
	}
}

// The whole point of the multi-kty fix: EC and RSA keys produce DISTINCT,
// correct thumbprints (not the same value, not an error). Before the fix the
// only thumbprint path was OKP-only.
func TestJWKThumbprintRFC7638_PerKtyDistinct(t *testing.T) {
	t.Parallel()
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("EC keygen: %v", err)
	}
	ecX, ecY := ecCoordsP256(t, ecPriv)
	ecJKT, err := jwkThumbprintRFC7638(JWK{Kty: "EC", Crv: "P-256", X: ecX, Y: ecY})
	if err != nil {
		t.Fatalf("EC thumbprint: %v", err)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("RSA keygen: %v", err)
	}
	rsaN := base64.RawURLEncoding.EncodeToString(rsaPriv.N.Bytes())
	rsaE := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaPriv.E)).Bytes())
	rsaJKT, err := jwkThumbprintRFC7638(JWK{Kty: "RSA", N: rsaN, E: rsaE})
	if err != nil {
		t.Fatalf("RSA thumbprint: %v", err)
	}
	if ecJKT == "" || rsaJKT == "" || ecJKT == rsaJKT {
		t.Fatalf("expected distinct non-empty EC/RSA thumbprints, got ec=%q rsa=%q", ecJKT, rsaJKT)
	}
}

// ecCoordsP256 returns the base64url-encoded raw 32-byte X and Y coordinates
// of a P-256 ECDSA public key. It routes through crypto/ecdh rather than the
// deprecated big.Int X/Y fields: ecdh.PublicKey.Bytes() yields the uncompressed
// SEC1 point 0x04 || X(32) || Y(32), from which the fixed-width halves are
// sliced directly.
func ecCoordsP256(t *testing.T, priv *ecdsa.PrivateKey) (x, y string) {
	t.Helper()
	pub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("ECDH conversion: %v", err)
	}
	raw := pub.Bytes() // 1 (0x04 prefix) + 32 + 32 for P-256
	if len(raw) != 65 {
		t.Fatalf("unexpected P-256 point length %d", len(raw))
	}
	x = base64.RawURLEncoding.EncodeToString(raw[1:33])
	y = base64.RawURLEncoding.EncodeToString(raw[33:65])
	return x, y
}

// parseDPoPHeaderJWK keeps only the public members per kty and rejects
// malformed shapes, so a proof cannot smuggle a private component or an
// incomplete key past the verifier.
func TestParseDPoPHeaderJWK(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		raw     string
		wantErr bool
		wantKty string
	}{
		{"okp ok", `{"kty":"OKP","crv":"Ed25519","x":"AAAA"}`, false, "OKP"},
		{"ec ok", `{"kty":"EC","crv":"P-256","x":"AAAA","y":"BBBB"}`, false, "EC"},
		{"rsa ok", `{"kty":"RSA","n":"AAAA","e":"AQAB"}`, false, "RSA"},
		{"ec missing y", `{"kty":"EC","crv":"P-256","x":"AAAA"}`, true, ""},
		{"rsa missing e", `{"kty":"RSA","n":"AAAA"}`, true, ""},
		{"okp missing x", `{"kty":"OKP","crv":"Ed25519"}`, true, ""},
		{"unknown kty", `{"kty":"oct","k":"AAAA"}`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := parseDPoPHeaderJWK(json.RawMessage(tc.raw))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s", tc.raw)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if jwk.Kty != tc.wantKty {
				t.Errorf("kty = %q want %q", jwk.Kty, tc.wantKty)
			}
		})
	}
}
