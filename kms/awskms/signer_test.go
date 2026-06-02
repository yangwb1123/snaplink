package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/defaultimpl/cryptosigner"
)

// fakeKMS is an in-process stand-in for the AWS KMS client. It holds a
// locally generated private key and answers GetPublicKey / Sign EXACTLY as
// the real service would: GetPublicKey returns the DER SubjectPublicKeyInfo
// + key spec; Sign signs the supplied digest with the local key and
// returns ASN.1 DER for ECC, raw bytes for RSA. No mocking framework and
// no real AWS — this is the §2 "real impl, no mocks" discipline applied to
// the KMS boundary.
type fakeKMS struct {
	ecKey   *ecdsa.PrivateKey
	rsaKey  *rsa.PrivateKey
	keySpec kmstypes.KeySpec

	getPubCalls atomic.Int32
	signErr     error // when set, Sign returns this (fail-closed test)
}

func newFakeECKMS(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	return &fakeKMS{ecKey: k, keySpec: kmstypes.KeySpecEccNistP256}
}

func newFakeRSAKMS(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return &fakeKMS{rsaKey: k, keySpec: kmstypes.KeySpecRsa2048}
}

func (f *fakeKMS) publicKey() crypto.PublicKey {
	if f.ecKey != nil {
		return &f.ecKey.PublicKey
	}
	return &f.rsaKey.PublicKey
}

func (f *fakeKMS) GetPublicKey(_ context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
	f.getPubCalls.Add(1)
	der, err := x509.MarshalPKIXPublicKey(f.publicKey())
	if err != nil {
		return nil, err
	}
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.keySpec}, nil
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	if in.MessageType != kmstypes.MessageTypeDigest {
		return nil, errors.New("fakeKMS: expected MessageType=DIGEST")
	}
	switch in.SigningAlgorithm {
	case kmstypes.SigningAlgorithmSpecEcdsaSha256:
		// KMS returns ASN.1 DER for ECC — SignASN1 produces exactly that.
		return &kms.SignOutput{Signature: mustECSignASN1(f.ecKey, in.Message)}, nil
	case kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256:
		sig, err := rsa.SignPKCS1v15(rand.Reader, f.rsaKey, crypto.SHA256, in.Message)
		if err != nil {
			return nil, err
		}
		return &kms.SignOutput{Signature: sig}, nil
	case kmstypes.SigningAlgorithmSpecRsassaPssSha256:
		sig, err := rsa.SignPSS(rand.Reader, f.rsaKey, crypto.SHA256, in.Message, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			return nil, err
		}
		return &kms.SignOutput{Signature: sig}, nil
	default:
		return nil, errors.New("fakeKMS: unsupported signing algorithm " + string(in.SigningAlgorithm))
	}
}

func mustECSignASN1(k *ecdsa.PrivateKey, digest []byte) []byte {
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		panic(err)
	}
	return sig
}

const testKeyID = "arn:aws:kms:us-east-1:000000000000:key/test"

// TestPublicKeyParsesAndCaches verifies Public() parses the DER SPKI into
// the right key type and that GetPublicKey is hit only once (the cache).
func TestPublicKeyParsesAndCaches(t *testing.T) {
	f := newFakeECKMS(t)
	s, err := New(f, testKeyID)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pub := s.Public()
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", pub)
	}
	// Second + third calls must NOT re-fetch.
	_ = s.Public()
	if _, err := s.PublicKey(context.Background()); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if got := f.getPubCalls.Load(); got != 1 {
		t.Fatalf("GetPublicKey called %d times, want 1 (cache)", got)
	}
}

// TestSignECDSARoundTrip verifies the crypto.Signer contract for ECDSA:
// Sign returns ASN.1 DER that verifies against the public key via
// ecdsa.VerifyASN1 (the stdlib contract the cryptosigner bridge relies on).
func TestSignECDSARoundTrip(t *testing.T) {
	f := newFakeECKMS(t)
	s, err := New(f, testKeyID)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub := s.Public().(*ecdsa.PublicKey)

	digest := sha256.Sum256([]byte("header.payload"))
	der, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], der) {
		t.Fatal("ECDSA DER signature did not verify against the public key")
	}
}

// TestSignRSARoundTrip verifies RS256 + PS256 raw signatures round-trip.
func TestSignRSARoundTrip(t *testing.T) {
	f := newFakeRSAKMS(t)
	s, err := New(f, testKeyID)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pub := s.Public().(*rsa.PublicKey)
	digest := sha256.Sum256([]byte("header.payload"))

	t.Run("RS256/PKCS1v15", func(t *testing.T) {
		sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			t.Fatalf("RS256 verify: %v", err)
		}
	})

	t.Run("PS256/PSS", func(t *testing.T) {
		sig, err := s.Sign(rand.Reader, digest[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}); err != nil {
			t.Fatalf("PS256 verify: %v", err)
		}
	})
}

// TestEdDSARejected confirms an EdDSA request (HashFunc()==0) is rejected
// clearly — AWS KMS has no Ed25519 signing key spec.
func TestEdDSARejected(t *testing.T) {
	f := newFakeECKMS(t)
	s, err := New(f, testKeyID)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.Sign(rand.Reader, []byte("msg"), crypto.Hash(0)); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("EdDSA Sign error = %v, want ErrUnsupportedKey", err)
	}
}

// TestSignFailsClosed confirms a KMS Sign error propagates (no unsigned
// token ever leaves the signer).
func TestSignFailsClosed(t *testing.T) {
	f := newFakeECKMS(t)
	f.signErr = errors.New("kms throttled")
	s, err := New(f, testKeyID)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("Sign succeeded despite KMS error, want fail-closed error")
	}
}

// TestEndToEndECDSAIssuer is the headline test: a token minted through the
// REAL ECDSAJWTIssuer wired with WithECDSAExternalSigner over the
// cryptosigner bridge over the fake KMS signer must Validate. This proves
// the full chain — KMS DER -> cryptosigner R||S -> JWS ES256 -> Validate.
func TestEndToEndECDSAIssuer(t *testing.T) {
	f := newFakeECKMS(t)
	signer, err := New(f, testKeyID)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bridge, pub, err := cryptosigner.ECDSA(signer)
	if err != nil {
		t.Fatalf("cryptosigner.ECDSA: %v", err)
	}

	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAExternalSigner(bridge, pub, "kms-test-kid"),
	)

	ctx := context.Background()
	tok, err := iss.Issue(ctx, &sso.Subject{ID: "user-1", ClientID: "client-1"}, []string{"openid"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := iss.Validate(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("subject = %q, want user-1", claims.Subject)
	}
	if claims.ClientID != "client-1" {
		t.Fatalf("client_id = %q, want client-1", claims.ClientID)
	}
}

// TestEndToEndRSAIssuer mirrors the ECDSA end-to-end test for RS256 + PS256
// through the REAL RSAJWTIssuer + cryptosigner.RSA bridge over fake KMS.
func TestEndToEndRSAIssuer(t *testing.T) {
	// cryptosigner.AlgRS256/AlgPS256 ("RS256"/"PS256") are string-equal to
	// what defaultimpl.WithRSAAlg expects, so they double as the issuer alg.
	for _, tc := range []struct {
		name string
		alg  string
	}{
		{"RS256", cryptosigner.AlgRS256},
		{"PS256", cryptosigner.AlgPS256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRSAKMS(t)
			signer, err := New(f, testKeyID)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			bridge, pub, err := cryptosigner.RSA(signer, tc.alg)
			if err != nil {
				t.Fatalf("cryptosigner.RSA: %v", err)
			}
			iss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAAlg(tc.alg),
				defaultimpl.WithRSAExternalSigner(bridge, pub, "kms-rsa-kid"),
			)
			ctx := context.Background()
			tok, err := iss.Issue(ctx, &sso.Subject{ID: "user-2", ClientID: "client-2"}, []string{"openid"})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			claims, err := iss.Validate(ctx, tok.AccessToken)
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if claims.Subject != "user-2" {
				t.Fatalf("subject = %q, want user-2", claims.Subject)
			}
		})
	}
}

// TestNewRejectsBadArgs covers the cheap construction guards.
func TestNewRejectsBadArgs(t *testing.T) {
	if _, err := New(nil, testKeyID); err == nil {
		t.Fatal("New(nil client) should error")
	}
	if _, err := New(newFakeECKMS(t), ""); err == nil {
		t.Fatal("New(empty keyID) should error")
	}
}
