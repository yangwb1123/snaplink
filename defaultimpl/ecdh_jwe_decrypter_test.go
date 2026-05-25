package defaultimpl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/snaplink/sso/defaultimpl"
)

func TestECDHJWEDecrypter_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	dec, err := defaultimpl.NewECDHJWEDecrypter(priv, "enc-1")
	if err != nil {
		t.Fatalf("new decrypter: %v", err)
	}
	// The AS advertises its enc key via JWKS; an RP encrypts to it.
	jwks, err := dec.JWKS(context.Background())
	if err != nil || len(jwks) != 1 {
		t.Fatalf("JWKS: %v (n=%d)", err, len(jwks))
	}
	if jwks[0].Use != "enc" || jwks[0].Kty != "EC" || jwks[0].Kid != "enc-1" {
		t.Fatalf("published JWK = %+v, want EC/enc/enc-1", jwks[0])
	}

	enc := defaultimpl.NewECDHJWEResponseEncrypter()
	plaintext := []byte(`{"request":"object"}`)
	for _, alg := range []string{"ECDH-ES", "ECDH-ES+A256KW"} {
		t.Run(alg, func(t *testing.T) {
			compact, err := enc.Encrypt(context.Background(), plaintext, jwks, alg, "A256GCM")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			got, err := dec.Decrypt(context.Background(), compact)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(got) != string(plaintext) {
				t.Errorf("round-trip mismatch: %s", got)
			}
		})
	}
}

func TestECDHJWEDecrypter_WrongRecipientFails(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dec, err := defaultimpl.NewECDHJWEDecrypter(priv, "enc-1")
	if err != nil {
		t.Fatalf("new decrypter: %v", err)
	}
	otherDec, _ := defaultimpl.NewECDHJWEDecrypter(other, "enc-2")
	otherJWKS, _ := otherDec.JWKS(context.Background())

	// Encrypt to a DIFFERENT key; our decrypter must fail.
	compact, err := defaultimpl.NewECDHJWEResponseEncrypter().
		Encrypt(context.Background(), []byte("x"), otherJWKS, "ECDH-ES", "A256GCM")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := dec.Decrypt(context.Background(), compact); err == nil {
		t.Error("decrypted a JWE addressed to a different key")
	}
}

func TestNewECDHJWEDecrypter_Rejects(t *testing.T) {
	if _, err := defaultimpl.NewECDHJWEDecrypter(nil, "k"); err == nil {
		t.Error("accepted nil private key")
	}
}
