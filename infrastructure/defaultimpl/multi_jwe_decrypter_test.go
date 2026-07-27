package defaultimpl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

func TestMultiJWEDecrypter_RoutesByAlg(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	rsaDec, err := defaultimpl.NewRSAJWEDecrypter(rsaPriv, "rsa-1")
	if err != nil {
		t.Fatalf("rsa decrypter: %v", err)
	}
	ecDec, err := defaultimpl.NewECDHJWEDecrypter(ecPriv, "ec-1")
	if err != nil {
		t.Fatalf("ecdh decrypter: %v", err)
	}
	multi := defaultimpl.NewMultiJWEDecrypter(rsaDec, ecDec)

	// JWKS aggregates both enc keys.
	jwks, err := multi.JWKS(ctx)
	if err != nil || len(jwks) != 2 {
		t.Fatalf("JWKS = %d keys, want 2 (err=%v)", len(jwks), err)
	}

	plaintext := []byte(`{"request":"object"}`)

	// RSA-encrypted request object routes to the RSA delegate.
	rsaJWKS, _ := rsaDec.JWKS(ctx)
	rsaCompact, err := defaultimpl.NewRSAJWEResponseEncrypter().
		Encrypt(ctx, plaintext, rsaJWKS, "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("rsa encrypt: %v", err)
	}
	if got, err := multi.Decrypt(ctx, rsaCompact); err != nil || string(got) != string(plaintext) {
		t.Errorf("rsa route: got %q err %v", got, err)
	}

	// EC-encrypted request object routes to the ECDH delegate.
	ecJWKS, _ := ecDec.JWKS(ctx)
	ecCompact, err := defaultimpl.NewECDHJWEResponseEncrypter().
		Encrypt(ctx, plaintext, ecJWKS, "ECDH-ES", "A256GCM")
	if err != nil {
		t.Fatalf("ec encrypt: %v", err)
	}
	if got, err := multi.Decrypt(ctx, ecCompact); err != nil || string(got) != string(plaintext) {
		t.Errorf("ec route: got %q err %v", got, err)
	}
}

func TestMultiJWEDecrypter_DuplicateAlgPanics(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate alg across decrypters")
		}
	}()
	ec1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ec2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	d1, _ := defaultimpl.NewECDHJWEDecrypter(ec1, "a")
	d2, _ := defaultimpl.NewECDHJWEDecrypter(ec2, "b")
	defaultimpl.NewMultiJWEDecrypter(d1, d2)
}

func TestMultiJWEDecrypter_UnknownAlg(t *testing.T) {
	t.Parallel()
	ecPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecDec, _ := defaultimpl.NewECDHJWEDecrypter(ecPriv, "ec-1")
	multi := defaultimpl.NewMultiJWEDecrypter(ecDec)
	// Not a JWE / no readable header.
	if _, err := multi.Decrypt(context.Background(), "not-a-jwe"); err == nil {
		t.Error("decrypted a non-JWE input")
	}
}
