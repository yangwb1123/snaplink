package defaultimpl_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"testing"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
)

// ecJWK builds a recipient JWK from an EC public key (use:"enc").
func ecJWK(t *testing.T, pub *ecdsa.PublicKey, crv string) core.JWK {
	t.Helper()
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xb := make([]byte, byteLen)
	yb := make([]byte, byteLen)
	pub.X.FillBytes(xb)
	pub.Y.FillBytes(yb)
	return core.JWK{
		Kty: "EC", Crv: crv, Use: "enc", Kid: "ec-1",
		X: base64.RawURLEncoding.EncodeToString(xb),
		Y: base64.RawURLEncoding.EncodeToString(yb),
	}
}

func TestECDHJWEResponseEncrypter_RoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	jwks := []core.JWK{ecJWK(t, &priv.PublicKey, "P-256")}
	enc := defaultimpl.NewECDHJWEResponseEncrypter()
	plaintext := []byte(`{"sub":"u1","aud":"c1"}`)

	for _, alg := range []string{"ECDH-ES", "ECDH-ES+A256KW"} {
		t.Run(alg, func(t *testing.T) {
			compact, err := enc.Encrypt(context.Background(), plaintext, jwks, alg, "A256GCM")
			if err != nil {
				t.Fatalf("encrypt: %v", err)
			}
			obj, err := jose.ParseEncryptedCompact(compact,
				[]jose.KeyAlgorithm{jose.ECDH_ES, jose.ECDH_ES_A256KW},
				[]jose.ContentEncryption{jose.A256GCM})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			got, err := obj.Decrypt(priv)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if string(got) != string(plaintext) {
				t.Errorf("round-trip mismatch: %s", got)
			}
		})
	}
}

func TestECDHJWEResponseEncrypter_Rejects(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := []core.JWK{ecJWK(t, &priv.PublicKey, "P-256")}
	enc := defaultimpl.NewECDHJWEResponseEncrypter()

	if _, err := enc.Encrypt(context.Background(), []byte("x"), jwks, "RSA-OAEP-256", "A256GCM"); err == nil {
		t.Error("accepted non-ECDH alg")
	}
	if _, err := enc.Encrypt(context.Background(), []byte("x"), jwks, "ECDH-ES", "A128GCM"); err == nil {
		t.Error("accepted unsupported enc")
	}
	// Signing-only key must not be selected for encryption.
	sigOnly := ecJWK(t, &priv.PublicKey, "P-256")
	sigOnly.Use = "sig"
	if _, err := enc.Encrypt(context.Background(), []byte("x"), []core.JWK{sigOnly}, "ECDH-ES", "A256GCM"); err == nil {
		t.Error("encrypted to a use:sig key")
	}
}

func TestMultiJWEResponseEncrypter_Routing(t *testing.T) {
	multi := defaultimpl.NewMultiJWEResponseEncrypter(
		defaultimpl.NewRSAJWEResponseEncrypter(),
		defaultimpl.NewECDHJWEResponseEncrypter(),
	)
	algs := map[string]bool{}
	for _, a := range multi.SupportedAlgs() {
		algs[a] = true
	}
	for _, want := range []string{"RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A256KW"} {
		if !algs[want] {
			t.Errorf("SupportedAlgs missing %q", want)
		}
	}

	// ECDH alg routes to the EC encrypter and round-trips.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := []core.JWK{ecJWK(t, &priv.PublicKey, "P-256")}
	if _, err := multi.Encrypt(context.Background(), []byte("x"), jwks, "ECDH-ES", "A256GCM"); err != nil {
		t.Errorf("multi ECDH route: %v", err)
	}
	// Unknown alg has no route.
	if _, err := multi.Encrypt(context.Background(), []byte("x"), jwks, "dir", "A256GCM"); err == nil {
		t.Error("routed an unsupported alg")
	}
}

func TestMultiJWEResponseEncrypter_DuplicateAlgPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate alg across encrypters")
		}
	}()
	defaultimpl.NewMultiJWEResponseEncrypter(
		defaultimpl.NewECDHJWEResponseEncrypter(),
		defaultimpl.NewECDHJWEResponseEncrypter(),
	)
}
