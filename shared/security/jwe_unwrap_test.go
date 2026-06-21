package security_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// JWEUnwrap is the integration point verifyJAR calls: 3-segment JWS
// payloads pass through untouched; 5-segment JWE payloads are decrypted
// (when a decrypter is wired) or fail closed (when none is). These
// tests drive it with the REAL RSA-OAEP-256 + A256GCM encrypter /
// decrypter (no mock) so the round-trip is genuine.

// rsaDecrypter returns a real RSA decrypter + the recipient JWKS to
// encrypt to, derived from a freshly generated 2048-bit key.
func rsaDecrypter(t *testing.T) (*defaultimpl.RSAJWEDecrypter, []core.JWK) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	dec, err := defaultimpl.NewRSAJWEDecrypter(priv, "enc-1")
	if err != nil {
		t.Fatalf("new decrypter: %v", err)
	}
	ssoJWKS, err := dec.JWKS(context.Background())
	if err != nil {
		t.Fatalf("decrypter JWKS: %v", err)
	}
	jwks := make([]core.JWK, len(ssoJWKS))
	copy(jwks, ssoJWKS)
	return dec, jwks
}

func TestJWEUnwrap_PassThroughJWS(t *testing.T) {
	t.Parallel()
	// A 3-segment JWS is not JWE-shaped → returned verbatim, decrypter
	// untouched (passing nil proves the JWS branch never calls it).
	const jws = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJycCJ9.sig"
	out, err := security.JWEUnwrap(context.Background(), jws, nil)
	if err != nil {
		t.Fatalf("JWEUnwrap JWS: %v", err)
	}
	if out != jws {
		t.Errorf("JWS pass-through = %q, want %q", out, jws)
	}
}

func TestJWEUnwrap_EmptyPassThrough(t *testing.T) {
	t.Parallel()
	out, err := security.JWEUnwrap(context.Background(), "", nil)
	if err != nil || out != "" {
		t.Errorf("JWEUnwrap(\"\") = (%q, %v), want (\"\", nil)", out, err)
	}
}

func TestJWEUnwrap_DecryptsRealJWE(t *testing.T) {
	t.Parallel()
	dec, jwks := rsaDecrypter(t)
	enc := defaultimpl.NewRSAJWEResponseEncrypter()

	const inner = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJycCJ9.signedJAR"
	jweCompact, err := enc.Encrypt(context.Background(), []byte(inner), jwks, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	out, err := security.JWEUnwrap(context.Background(), jweCompact, dec)
	if err != nil {
		t.Fatalf("JWEUnwrap JWE: %v", err)
	}
	if out != inner {
		t.Errorf("decrypted inner = %q, want %q", out, inner)
	}
}

func TestJWEUnwrap_JWEWithoutDecrypterFailsClosed(t *testing.T) {
	t.Parallel()
	_, jwks := rsaDecrypter(t)
	enc := defaultimpl.NewRSAJWEResponseEncrypter()
	jweCompact, err := enc.Encrypt(context.Background(), []byte("inner"), jwks, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// JWE-shaped payload but no decrypter wired → fail closed.
	if _, err := security.JWEUnwrap(context.Background(), jweCompact, nil); err == nil {
		t.Fatal("JWE without decrypter did not fail closed")
	}
}

func TestJWEUnwrap_DecryptErrorPropagates(t *testing.T) {
	t.Parallel()
	// Encrypt to decrypter A's key, then unwrap with decrypter B (a
	// different key) — the decrypt fails and the error propagates.
	_, jwksA := rsaDecrypter(t)
	decB, _ := rsaDecrypter(t)
	enc := defaultimpl.NewRSAJWEResponseEncrypter()
	jweCompact, err := enc.Encrypt(context.Background(), []byte("inner"), jwksA, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := security.JWEUnwrap(context.Background(), jweCompact, decB); err == nil {
		t.Fatal("JWEUnwrap with wrong-key decrypter did not error")
	}
}

func TestJWEUnwrap_MalformedJWEShape(t *testing.T) {
	t.Parallel()
	dec, _ := rsaDecrypter(t)
	// 5 segments (JWE shape) but garbage content — decrypter parse fails.
	const garbage = "aaaa.bbbb.cccc.dddd.eeee"
	if _, err := security.JWEUnwrap(context.Background(), garbage, dec); err == nil {
		t.Fatal("JWEUnwrap accepted malformed JWE")
	}
}
