package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/cryptosigner"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

// fakeKMS is an in-process stand-in for the GCP Cloud KMS
// KeyManagementClient. It holds a locally generated private key and answers
// GetPublicKey / AsymmetricSign EXACTLY as the real service would:
// GetPublicKey returns the PEM SubjectPublicKeyInfo + the key-version
// algorithm; AsymmetricSign signs the supplied Digest (EC/RSA) or Data
// (Ed25519) with the local key and returns ASN.1 DER for ECC, raw bytes
// for RSA, raw 64-byte for Ed25519. No mocking framework and no real GCP —
// this is the §2 "real impl, no mocks" discipline applied to the KMS
// boundary (the cloud client is genuinely external, so a programmable test
// fake is the right tool, exactly as kms/awskms does).
type fakeKMS struct {
	ecKey  *ecdsa.PrivateKey
	rsaKey *rsa.PrivateKey
	edPub  ed25519.PublicKey
	edPriv ed25519.PrivateKey
	alg    kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm

	// protectionLevel is echoed on the GetPublicKey response, driving
	// KeyOrigin's protectionLevelToOrigin mapping. The zero value
	// (PROTECTION_LEVEL_UNSPECIFIED) maps to core.OriginUnknown.
	protectionLevel kmspb.ProtectionLevel

	getPubCalls atomic.Int32
	signErr     error // when set, AsymmetricSign returns this (fail-closed test)

	// failPubN: the first failPubN GetPublicKey calls return a transient
	// error, the rest succeed. Models a KMS outage at startup that clears
	// (drives the concurrency/retry test). Read atomically so many
	// goroutines can race on it safely.
	failPubN atomic.Int32

	// getPubBlock / signBlock, when non-nil, are received from before the
	// respective op returns — the test sends to/closes them to simulate a
	// KMS call that hangs longer than WithCallTimeout (drives the
	// call-timeout test).
	getPubBlock <-chan struct{}
	signBlock   <-chan struct{}
}

func newFakeECKMS(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	return &fakeKMS{ecKey: k, alg: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256}
}

func newFakeEC384KMS(t *testing.T) *fakeKMS {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec384 key: %v", err)
	}
	return &fakeKMS{ecKey: k, alg: kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384}
}

func newFakeRSAKMS(t *testing.T, alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm) *fakeKMS {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return &fakeKMS{rsaKey: k, alg: alg}
}

func newFakeEd25519KMS(t *testing.T) *fakeKMS {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return &fakeKMS{edPub: pub, edPriv: priv, alg: kmspb.CryptoKeyVersion_EC_SIGN_ED25519}
}

func (f *fakeKMS) publicKey() crypto.PublicKey {
	switch {
	case f.ecKey != nil:
		return &f.ecKey.PublicKey
	case f.rsaKey != nil:
		return &f.rsaKey.PublicKey
	default:
		return f.edPub
	}
}

func (f *fakeKMS) GetPublicKey(ctx context.Context, _ *kmspb.GetPublicKeyRequest, _ ...gax.CallOption) (*kmspb.PublicKey, error) {
	f.getPubCalls.Add(1)
	// Fail the first failPubN calls to model a transient KMS outage that
	// later clears. Decrement so retries eventually break through; once the
	// counter is exhausted Load() stays <= 0 and every call succeeds.
	if f.failPubN.Load() > 0 && f.failPubN.Add(-1) >= 0 {
		return nil, errors.New("fakeKMS: transient GetPublicKey outage")
	}
	if f.getPubBlock != nil {
		// Honor cancellation so a WithCallTimeout deadline fires.
		select {
		case <-f.getPubBlock:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	der, err := x509.MarshalPKIXPublicKey(f.publicKey())
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return &kmspb.PublicKey{Pem: string(pemBytes), Algorithm: f.alg, ProtectionLevel: f.protectionLevel}, nil
}

func (f *fakeKMS) AsymmetricSign(ctx context.Context, in *kmspb.AsymmetricSignRequest, _ ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	if f.signErr != nil {
		return nil, f.signErr
	}
	if f.signBlock != nil {
		select {
		case <-f.signBlock:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	switch f.alg {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		d := in.GetDigest().GetSha256()
		if len(d) == 0 {
			return nil, errors.New("fakeKMS: expected Digest.Sha256 for P-256")
		}
		// KMS returns ASN.1 DER for ECC — SignASN1 produces exactly that.
		return &kmspb.AsymmetricSignResponse{Signature: mustECSignASN1(f.ecKey, d)}, nil
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		d := in.GetDigest().GetSha384()
		if len(d) == 0 {
			return nil, errors.New("fakeKMS: expected Digest.Sha384 for P-384")
		}
		return &kmspb.AsymmetricSignResponse{Signature: mustECSignASN1(f.ecKey, d)}, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256:
		d := in.GetDigest().GetSha256()
		if len(d) == 0 {
			return nil, errors.New("fakeKMS: expected Digest.Sha256 for RSA PKCS1")
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, f.rsaKey, crypto.SHA256, d)
		if err != nil {
			return nil, err
		}
		return &kmspb.AsymmetricSignResponse{Signature: sig}, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256:
		d := in.GetDigest().GetSha256()
		if len(d) == 0 {
			return nil, errors.New("fakeKMS: expected Digest.Sha256 for RSA PSS")
		}
		sig, err := rsa.SignPSS(rand.Reader, f.rsaKey, crypto.SHA256, d, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			return nil, err
		}
		return &kmspb.AsymmetricSignResponse{Signature: sig}, nil
	case kmspb.CryptoKeyVersion_EC_SIGN_ED25519:
		// Ed25519 is NOT prehashed: GCP receives the RAW message in Data.
		msg := in.GetData()
		if len(msg) == 0 {
			return nil, errors.New("fakeKMS: expected Data (raw message) for Ed25519")
		}
		if in.GetDigest() != nil {
			return nil, errors.New("fakeKMS: Ed25519 request must NOT set Digest")
		}
		return &kmspb.AsymmetricSignResponse{Signature: ed25519.Sign(f.edPriv, msg)}, nil
	default:
		return nil, errors.New("fakeKMS: unsupported algorithm")
	}
}

func mustECSignASN1(k *ecdsa.PrivateKey, digest []byte) []byte {
	sig, err := ecdsa.SignASN1(rand.Reader, k, digest)
	if err != nil {
		panic(err)
	}
	return sig
}

const testKeyName = "projects/p/locations/global/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1"

// TestPublicKeyParsesAndCaches verifies Public() parses the PEM SPKI into
// the right key type and that GetPublicKey is hit only once (the cache).
func TestPublicKeyParsesAndCaches(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	s, err := New(f, testKeyName)
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

// TestSignVerifyTable is the per-alg round-trip table: Sign maps to the
// right request shape (Digest oneof for EC/RSA, Data for Ed25519) and
// returns bytes that verify against the public key with the stdlib verifier
// the cryptosigner bridge relies on.
func TestSignVerifyTable(t *testing.T) {
	t.Parallel()
	msg := []byte("header.payload")
	sum256 := sha256.Sum256(msg)
	sum384 := sha512.Sum384(msg)

	t.Run("ES256", func(t *testing.T) {
		f := newFakeECKMS(t)
		s, err := New(f, testKeyName)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		pub := s.Public().(*ecdsa.PublicKey)
		der, err := s.Sign(rand.Reader, sum256[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !ecdsa.VerifyASN1(pub, sum256[:], der) {
			t.Fatal("ES256 DER signature did not verify")
		}
	})

	t.Run("ES384", func(t *testing.T) {
		f := newFakeEC384KMS(t)
		s, err := New(f, testKeyName)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		pub := s.Public().(*ecdsa.PublicKey)
		der, err := s.Sign(rand.Reader, sum384[:], crypto.SHA384)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !ecdsa.VerifyASN1(pub, sum384[:], der) {
			t.Fatal("ES384 DER signature did not verify")
		}
	})

	t.Run("RS256", func(t *testing.T) {
		f := newFakeRSAKMS(t, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256)
		s, err := New(f, testKeyName)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		pub := s.Public().(*rsa.PublicKey)
		sig, err := s.Sign(rand.Reader, sum256[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum256[:], sig); err != nil {
			t.Fatalf("RS256 verify: %v", err)
		}
	})

	t.Run("PS256", func(t *testing.T) {
		f := newFakeRSAKMS(t, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256)
		s, err := New(f, testKeyName)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		pub := s.Public().(*rsa.PublicKey)
		sig, err := s.Sign(rand.Reader, sum256[:], &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, sum256[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}); err != nil {
			t.Fatalf("PS256 verify: %v", err)
		}
	})

	t.Run("EdDSA", func(t *testing.T) {
		f := newFakeEd25519KMS(t)
		s, err := New(f, testKeyName)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		pub := s.Public().(ed25519.PublicKey)
		// Ed25519's crypto.Signer contract: pass the RAW message as digest
		// with opts.HashFunc()==0.
		sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if len(sig) != ed25519.SignatureSize {
			t.Fatalf("Ed25519 signature length %d, want %d", len(sig), ed25519.SignatureSize)
		}
		if !ed25519.Verify(pub, msg, sig) {
			t.Fatal("EdDSA signature did not verify")
		}
	})
}

// TestSignFailsClosed confirms a KMS AsymmetricSign error propagates (no
// unsigned token ever leaves the signer).
func TestSignFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	f.signErr = errors.New("kms permission denied")
	s, err := New(f, testKeyName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("Sign succeeded despite KMS error, want fail-closed error")
	}
}

// TestSignHashMismatchRejected confirms a hash/padding inconsistent with
// the key version's algorithm is rejected (fail-closed alg-confusion
// guard), never sent to KMS as a mis-shaped request.
func TestSignHashMismatchRejected(t *testing.T) {
	t.Parallel()
	digest := sha256.Sum256([]byte("x"))

	t.Run("P256 with SHA-384", func(t *testing.T) {
		f := newFakeECKMS(t) // EC_SIGN_P256_SHA256
		s, _ := New(f, testKeyName)
		if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA384); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v, want ErrUnsupportedKey", err)
		}
	})

	t.Run("PKCS1 key with PSS opts", func(t *testing.T) {
		f := newFakeRSAKMS(t, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256)
		s, _ := New(f, testKeyName)
		_, err := s.Sign(rand.Reader, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
		if !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v, want ErrUnsupportedKey", err)
		}
	})

	t.Run("Ed25519 with a hash", func(t *testing.T) {
		f := newFakeEd25519KMS(t)
		s, _ := New(f, testKeyName)
		if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v, want ErrUnsupportedKey", err)
		}
	})
}

// TestSignNilOptsRejected: crypto.SignerOpts MAY be nil per the stdlib
// contract; this signer needs the hash it carries, so a nil must yield a
// clear error, never a nil-interface panic on opts.HashFunc().
func TestSignNilOptsRejected(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	s, err := New(f, testKeyName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	digest := sha256.Sum256([]byte("x"))

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Sign panicked on nil opts: %v", r)
		}
	}()

	if _, err := s.Sign(rand.Reader, digest[:], nil); err == nil {
		t.Fatal("Sign(nil opts) succeeded, want a clear error")
	} else if !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("Sign(nil opts) error = %v, want ErrUnsupportedKey", err)
	}
}

// TestEndToEndECDSAIssuer is the headline test: a token minted through the
// REAL ECDSAJWTIssuer wired with WithECDSAExternalSigner over the
// cryptosigner bridge over the fake KMS signer must Validate. This proves
// the full chain — KMS DER -> cryptosigner R||S -> JWS ES256 -> Validate.
func TestEndToEndECDSAIssuer(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	signer, err := New(f, testKeyName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bridge, pub, err := cryptosigner.ECDSA(signer)
	if err != nil {
		t.Fatalf("cryptosigner.ECDSA: %v", err)
	}

	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAExternalSigner(bridge, pub, "gcpkms-test-kid"),
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
	t.Parallel()
	for _, tc := range []struct {
		name string
		alg  string
		kalg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	}{
		{"RS256", cryptosigner.AlgRS256, kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256},
		{"PS256", cryptosigner.AlgPS256, kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRSAKMS(t, tc.kalg)
			signer, err := New(f, testKeyName)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			bridge, pub, err := cryptosigner.RSA(signer, tc.alg)
			if err != nil {
				t.Fatalf("cryptosigner.RSA: %v", err)
			}
			iss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAAlg(tc.alg),
				defaultimpl.WithRSAExternalSigner(bridge, pub, "gcpkms-rsa-kid"),
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

// TestEndToEndEd25519Issuer is the GCP-specific headline test (no AWS KMS
// equivalent — AWS has no EdDSA key spec): a token minted through the REAL
// Ed25519JWTIssuer wired with WithEd25519ExternalSigner over the
// cryptosigner.Ed25519 bridge over the fake KMS Ed25519 signer must
// Validate. Proves the unhashed-Data path end to end.
func TestEndToEndEd25519Issuer(t *testing.T) {
	t.Parallel()
	f := newFakeEd25519KMS(t)
	signer, err := New(f, testKeyName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	bridge, pub, err := cryptosigner.Ed25519(signer)
	if err != nil {
		t.Fatalf("cryptosigner.Ed25519: %v", err)
	}

	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519ExternalSigner(bridge, pub, "gcpkms-ed25519-kid"),
	)

	ctx := context.Background()
	tok, err := iss.Issue(ctx, &sso.Subject{ID: "user-3", ClientID: "client-3"}, []string{"openid"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	claims, err := iss.Validate(ctx, tok.AccessToken)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.Subject != "user-3" {
		t.Fatalf("subject = %q, want user-3", claims.Subject)
	}
	if claims.ClientID != "client-3" {
		t.Fatalf("client_id = %q, want client-3", claims.ClientID)
	}
}

// TestNewRejectsBadArgs covers the cheap construction guards.
func TestNewRejectsBadArgs(t *testing.T) {
	t.Parallel()
	if _, err := New(nil, testKeyName); err == nil {
		t.Fatal("New(nil client) should error")
	}
	if _, err := New(newFakeECKMS(t), ""); err == nil {
		t.Fatal("New(empty keyName) should error")
	}
}

// TestConcurrentLoadPublicRetriesTransientError exercises the public-key
// cache: it must be mutex-guarded, not sync.Once-reset. Many goroutines
// hammer Public()/Sign() concurrently while the fake KMS errors the first
// few GetPublicKey calls (a transient startup outage) before succeeding.
//
// With a sync.Once reset inside Do this test data-races (the reset writes a
// sync.Once while peer goroutines call .Do on it) so `go test -race` would
// FAIL. With the mutex the fetches serialize, the transient error is
// retried (not poisoned), and once it clears every signer caches the same
// immutable key and signs successfully.
func TestConcurrentLoadPublicRetriesTransientError(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	// First 5 GetPublicKey attempts fail; the rest succeed. With the cache
	// only populated on success, concurrent callers retry past the outage.
	f.failPubN.Store(5)

	s, err := New(f, testKeyName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	digest := sha256.Sum256([]byte("header.payload"))

	const goroutines = 64
	var wg sync.WaitGroup
	var signOK atomic.Int32
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 8; j++ {
				_ = s.Public() // may be nil during the outage window
				if sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
					if !ecdsa.VerifyASN1(&f.ecKey.PublicKey, digest[:], sig) {
						t.Errorf("signature from cached key did not verify")
						return
					}
					signOK.Add(1)
				}
			}
		}()
	}
	wg.Wait()

	if signOK.Load() == 0 {
		t.Fatal("no goroutine ever signed successfully; transient error was not retried")
	}

	// After the outage cleared the key is cached: a fresh Sign must succeed
	// and verify, proving the cached success is stable.
	sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("post-outage Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&f.ecKey.PublicKey, digest[:], sig) {
		t.Fatal("post-outage signature did not verify")
	}
}

// TestSignCallTimeout: a KMS round-trip that blocks longer than
// WithCallTimeout must return a context-deadline error promptly rather than
// hanging the signing goroutine past any handler deadline.
func TestSignCallTimeout(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	// Pre-load the public key (no block) so the timeout we measure is the
	// AsymmetricSign round-trip itself.
	never := make(chan struct{})
	f.signBlock = never // AsymmetricSign blocks forever (until ctx deadline)

	s, err := New(f, testKeyName, WithCallTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := s.PublicKey(context.Background()); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}

	digest := sha256.Sum256([]byte("header.payload"))
	done := make(chan error, 1)
	go func() {
		_, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Sign returned nil despite a KMS call that never completes")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Sign error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sign hung past the configured call timeout")
	}
}

// TestKeyOrigin_MapsProtectionLevel proves KeyOrigin translates each GCP
// KMS ProtectionLevel to the correct core.KeyOrigin. Regression guard for a
// self-deadlock: KeyOrigin must call loadPublic WITHOUT holding s.mu itself
// (loadPublic acquires it), since Go's sync.Mutex is not reentrant.
func TestKeyOrigin_MapsProtectionLevel(t *testing.T) {
	cases := []struct {
		name  string
		level kmspb.ProtectionLevel
		want  core.KeyOrigin
	}{
		{"hsm", kmspb.ProtectionLevel_HSM, core.OriginHSMGenerated},
		{"software", kmspb.ProtectionLevel_SOFTWARE, core.OriginUnattested},
		{"external", kmspb.ProtectionLevel_EXTERNAL, core.OriginImported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeECKMS(t)
			f.protectionLevel = c.level
			s, err := New(f, testKeyName)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, err := s.KeyOrigin(context.Background(), testKeyName)
			if err != nil {
				t.Fatalf("KeyOrigin: %v", err)
			}
			if got != c.want {
				t.Errorf("KeyOrigin = %v, want %v", got, c.want)
			}
		})
	}
}

// TestKeyOrigin_UnknownKidReturnsUnknown proves a kid that doesn't match
// this per-key signer's own keyName reports OriginUnknown.
func TestKeyOrigin_UnknownKidReturnsUnknown(t *testing.T) {
	f := newFakeECKMS(t)
	f.protectionLevel = kmspb.ProtectionLevel_HSM
	s, err := New(f, testKeyName)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got, err := s.KeyOrigin(context.Background(), "some-other-key")
	if err != nil {
		t.Fatalf("KeyOrigin: %v", err)
	}
	if got != core.OriginUnknown {
		t.Errorf("KeyOrigin(mismatched kid) = %v, want OriginUnknown", got)
	}
}
