package defaultjwe

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/snaplink/sso/shared/core"
)

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return k
}

func pubJWK(priv *rsa.PrivateKey, use, kid string) core.JWK {
	pub := &priv.PublicKey
	return core.JWK{
		Kty: "RSA",
		Use: use,
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// TestEncrypt_RoundTrip encrypts to a generated RP key, then decrypts
// with the matching private key via the existing RSAJWEDecrypter to
// prove the JWE is well-formed and recoverable.
func TestEncrypt_RoundTrip(t *testing.T) {
	priv := testRSAKey(t)
	enc := NewRSAJWEResponseEncrypter()

	jwks := []core.JWK{pubJWK(priv, "enc", "rp-enc-1")}
	plaintext := []byte("eyJhbGciOiJFZERTQSJ9.payload.sig") // stand-in JWS

	compact, err := enc.Encrypt(context.Background(), plaintext, jwks, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// 5-segment JWE compact shape.
	dots := 0
	for _, c := range compact {
		if c == '.' {
			dots++
		}
	}
	if dots != 4 {
		t.Fatalf("not JWE compact shape: %d dots", dots)
	}

	dec, err := NewRSAJWEDecrypter(priv, "rp-enc-1")
	if err != nil {
		t.Fatalf("new decrypter: %v", err)
	}
	got, err := dec.Decrypt(context.Background(), compact)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("round-trip mismatch: got %q", got)
	}
}

func TestEncrypt_DualUseKeyFallback(t *testing.T) {
	priv := testRSAKey(t)
	enc := NewRSAJWEResponseEncrypter()
	// No use field -> dual-use, accepted as fallback.
	jwks := []core.JWK{pubJWK(priv, "", "")}
	if _, err := enc.Encrypt(context.Background(), []byte("x"), jwks, "RSA-OAEP-256", "A256GCM"); err != nil {
		t.Fatalf("dual-use key should be accepted: %v", err)
	}
}

func TestEncrypt_SkipsSigningKey(t *testing.T) {
	priv := testRSAKey(t)
	enc := NewRSAJWEResponseEncrypter()
	jwks := []core.JWK{pubJWK(priv, "sig", "sig-1")}
	if _, err := enc.Encrypt(context.Background(), []byte("x"), jwks, "RSA-OAEP-256", "A256GCM"); err == nil {
		t.Fatal("signing-only key must not be used for encryption")
	}
}

func TestEncrypt_NoKey(t *testing.T) {
	enc := NewRSAJWEResponseEncrypter()
	if _, err := enc.Encrypt(context.Background(), []byte("x"), nil, "RSA-OAEP-256", "A256GCM"); err == nil {
		t.Fatal("expected error with empty JWKS")
	}
}

func TestEncrypt_UnsupportedAlgEnc(t *testing.T) {
	priv := testRSAKey(t)
	enc := NewRSAJWEResponseEncrypter()
	jwks := []core.JWK{pubJWK(priv, "enc", "k")}
	if _, err := enc.Encrypt(context.Background(), []byte("x"), jwks, "RSA1_5", "A256GCM"); err == nil {
		t.Fatal("expected unsupported alg rejection")
	}
	if _, err := enc.Encrypt(context.Background(), []byte("x"), jwks, "RSA-OAEP-256", "A128GCM"); err == nil {
		t.Fatal("expected unsupported enc rejection")
	}
}

// TestEncrypt_PrefersEncOverDualUse ensures a use:"enc" key wins when
// both an enc key and a dual-use key are present.
func TestEncrypt_PrefersEncOverDualUse(t *testing.T) {
	dual := testRSAKey(t)
	encKey := testRSAKey(t)
	enc := NewRSAJWEResponseEncrypter()
	jwks := []core.JWK{pubJWK(dual, "", "dual"), pubJWK(encKey, "enc", "enc")}

	compact, err := enc.Encrypt(context.Background(), []byte("hello"), jwks, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// The enc key must decrypt it; the dual key must not.
	decEnc, _ := NewRSAJWEDecrypter(encKey, "enc")
	if _, err := decEnc.Decrypt(context.Background(), compact); err != nil {
		t.Fatalf("enc key should decrypt: %v", err)
	}
}
