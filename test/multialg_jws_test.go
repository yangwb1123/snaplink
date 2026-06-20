package ssotest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

// hmacSHA256 is the symmetric-forgery primitive the alg-confusion tests use
// to attempt the public-key-as-HMAC-secret attack (which MUST be rejected).
func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// expectedJKT recomputes the RFC 7638 §3 JWK thumbprint independently of the
// production code, so a DPoP cnf.jkt assertion verifies the server's binding
// rather than tautologically trusting it. Required members per kty (§3.2),
// lexically ordered, no whitespace.
func expectedJKT(t *testing.T, jwk sso.JWK) string {
	t.Helper()
	var canonical string
	switch jwk.Kty {
	case "OKP":
		canonical = `{"crv":"` + jwk.Crv + `","kty":"OKP","x":"` + jwk.X + `"}`
	case "EC":
		canonical = `{"crv":"` + jwk.Crv + `","kty":"EC","x":"` + jwk.X + `","y":"` + jwk.Y + `"}`
	case "RSA":
		canonical = `{"e":"` + jwk.E + `","kty":"RSA","n":"` + jwk.N + `"}`
	default:
		t.Fatalf("expectedJKT: unsupported kty %q", jwk.Kty)
	}
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Shared multi-alg JWS signing helpers for the private_key_jwt / JAR / DPoP
// interop tests. Each signer produces a real compact JWS over a real
// asymmetric key and exposes the matching public JWK, so the tests exercise
// the same security.VerifyCompactJWS path a real RP would hit. No mocks.

// multiAlgSigner signs a JWS for one alg and yields the public JWK.
type multiAlgSigner struct {
	alg       string
	publicJWK sso.JWK // kid filled in by the caller
	sign      func(signingInput []byte) []byte
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// newSignerForAlg builds a signer + public JWK for the given JWS alg.
func newSignerForAlg(t *testing.T, alg, kid string) *multiAlgSigner {
	t.Helper()
	switch alg {
	case "EdDSA":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &multiAlgSigner{
			alg:       alg,
			publicJWK: sso.JWK{Kty: "OKP", Crv: "Ed25519", Kid: kid, Alg: alg, Use: "sig", X: b64(pub)},
			sign:      func(in []byte) []byte { return ed25519.Sign(priv, in) },
		}
	case "ES256", "ES384", "ES512":
		curve, hash, coord := esParams(alg)
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		// Derive raw X/Y from the uncompressed point (0x04 || X || Y) rather
		// than the deprecated big.Int coordinate fields (Go 1.26 SA1019).
		ecdhPub, err := priv.PublicKey.ECDH()
		if err != nil {
			t.Fatal(err)
		}
		raw := ecdhPub.Bytes() // 1 + 2*coord bytes
		x := b64(raw[1 : 1+coord])
		y := b64(raw[1+coord:])
		return &multiAlgSigner{
			alg:       alg,
			publicJWK: sso.JWK{Kty: "EC", Crv: esCrv(alg), Kid: kid, Alg: alg, Use: "sig", X: x, Y: y},
			sign: func(in []byte) []byte {
				digest := digestFor(hash, in)
				r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
				if err != nil {
					t.Fatal(err)
				}
				// JWS ES* signatures are fixed-width R||S (RFC 7518 §3.4).
				out := make([]byte, 2*coord)
				r.FillBytes(out[:coord])
				s.FillBytes(out[coord:])
				return out
			},
		}
	case "RS256", "PS256":
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		n := b64(priv.N.Bytes())
		e := b64(big.NewInt(int64(priv.E)).Bytes())
		jwk := sso.JWK{Kty: "RSA", Kid: kid, Alg: alg, Use: "sig", N: n, E: e}
		signFn := func(in []byte) []byte {
			digest := digestFor(crypto.SHA256, in)
			var sig []byte
			var serr error
			if alg == "RS256" {
				sig, serr = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)
			} else {
				sig, serr = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest, &rsa.PSSOptions{
					SaltLength: rsa.PSSSaltLengthAuto,
					Hash:       crypto.SHA256,
				})
			}
			if serr != nil {
				t.Fatal(serr)
			}
			return sig
		}
		return &multiAlgSigner{alg: alg, publicJWK: jwk, sign: signFn}
	default:
		t.Fatalf("unsupported test alg %q", alg)
		return nil
	}
}

func esParams(alg string) (elliptic.Curve, crypto.Hash, int) {
	switch alg {
	case "ES256":
		return elliptic.P256(), crypto.SHA256, 32
	case "ES384":
		return elliptic.P384(), crypto.SHA384, 48
	case "ES512":
		return elliptic.P521(), crypto.SHA512, 66
	}
	return nil, 0, 0
}

func esCrv(alg string) string {
	switch alg {
	case "ES256":
		return "P-256"
	case "ES384":
		return "P-384"
	case "ES512":
		return "P-521"
	}
	return ""
}

func digestFor(h crypto.Hash, msg []byte) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(msg)
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384(msg)
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512(msg)
		return d[:]
	}
	return nil
}

// signCompact assembles a compact JWS from a header + claims map using the
// signer. The header alg is taken from the signer; extra header fields
// (kid, typ, jwk) are supplied by the caller.
func (s *multiAlgSigner) signCompact(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	header["alg"] = s.alg
	hraw, _ := json.Marshal(header)
	praw, _ := json.Marshal(claims)
	signingInput := b64(hraw) + "." + b64(praw)
	sig := s.sign([]byte(signingInput))
	return signingInput + "." + b64(sig)
}
