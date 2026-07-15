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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/cryptosigner"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
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

	// describeOrigin is the KeyMetadata.Origin DescribeKey reports. The zero
	// value ("") is treated the same as an unrecognized origin by
	// resolveOrigin (falls through to OriginUnknown) — tests that care about
	// a specific origin set this explicitly.
	describeOrigin kmstypes.OriginType
	describeErr    error // when set, DescribeKey returns this

	getPubCalls atomic.Int32
	signErr     error // when set, Sign returns this (fail-closed test)

	// failPubN: the first failPubN GetPublicKey calls return a transient
	// error, the rest succeed. Models a KMS outage at startup that clears
	// (drives the FIX 1 concurrency/retry test). Read atomically so many
	// goroutines can race on it safely.
	failPubN atomic.Int32

	// getPubBlock / signBlock, when non-nil, are received from before the
	// respective op returns — the test closes/sends to simulate a KMS call
	// that hangs longer than WithCallTimeout (drives the FIX 2 test).
	getPubBlock <-chan struct{}
	signBlock   <-chan struct{}
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

func (f *fakeKMS) GetPublicKey(ctx context.Context, _ *kms.GetPublicKeyInput, _ ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error) {
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
	return &kms.GetPublicKeyOutput{PublicKey: der, KeySpec: f.keySpec}, nil
}

// DescribeKey answers the key-origin auto-detection Signer.resolveOrigin
// calls at loadPublic time, mirroring GetPublicKey's real-response-shape
// discipline: tests set describeOrigin/describeErr to drive each origin
// (or failure) case rather than mocking resolveOrigin directly.
func (f *fakeKMS) DescribeKey(_ context.Context, _ *kms.DescribeKeyInput, _ ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{Origin: f.describeOrigin}}, nil
}

func (f *fakeKMS) Sign(ctx context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	if _, err := New(nil, testKeyID); err == nil {
		t.Fatal("New(nil client) should error")
	}
	if _, err := New(newFakeECKMS(t), ""); err == nil {
		t.Fatal("New(empty keyID) should error")
	}
}

// TestConcurrentLoadPublicRetriesTransientError exercises FIX 1: the
// public-key cache must be mutex-guarded, not sync.Once-reset. Many
// goroutines hammer Public()/Sign() concurrently while the fake KMS errors
// the first few GetPublicKey calls (a transient startup outage) before
// succeeding.
//
// Pre-fix (sync.Once reset inside Do) this test data-races — the reset
// writes a sync.Once while peer goroutines call .Do on it — so `go test
// -race` FAILS pre-fix. Post-fix the mutex serializes fetches, the
// transient error is retried (not poisoned), and once it clears every
// signer caches the same immutable key and signs successfully.
func TestConcurrentLoadPublicRetriesTransientError(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	// First 5 GetPublicKey attempts fail; the rest succeed. With the cache
	// only populated on success, concurrent callers retry past the outage.
	f.failPubN.Store(5)

	s, err := New(f, testKeyID)
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
			// Loop a few times so every goroutine eventually races past the
			// transient-error window and proves the cached success is stable.
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

// TestSignNilOptsRejected exercises FIX 3: crypto.SignerOpts MAY be nil per
// the stdlib contract; this signer needs the hash it carries, so a nil must
// yield a clear error, never a nil-interface panic on opts.HashFunc().
func TestSignNilOptsRejected(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	s, err := New(f, testKeyID)
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

// TestSignCallTimeout exercises FIX 2: a KMS round-trip that blocks longer
// than WithCallTimeout must return a context-deadline error promptly rather
// than hanging the signing goroutine past any handler deadline.
func TestSignCallTimeout(t *testing.T) {
	t.Parallel()
	f := newFakeECKMS(t)
	// Pre-load the public key (no block) so the timeout we measure is the
	// Sign round-trip itself, isolating the FIX-2 behavior.
	never := make(chan struct{})
	f.signBlock = never // Sign blocks forever (until ctx deadline)

	s, err := New(f, testKeyID, WithCallTimeout(20*time.Millisecond))
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
		t.Fatal("Sign hung past the configured call timeout (FIX 2 regression)")
	}
}

// TestKeyOrigin_MapsDescribeKeyResponse proves KeyOrigin translates each
// KMS Origin value to the correct core.KeyOrigin, and that a DescribeKey
// failure fails OPEN to OriginUnknown rather than propagating the error
// (attestation is best-effort metadata, never load-bearing for signing).
func TestKeyOrigin_MapsDescribeKeyResponse(t *testing.T) {
	cases := []struct {
		name    string
		origin  kmstypes.OriginType
		descErr error
		want    core.KeyOrigin
	}{
		{"aws kms generated", kmstypes.OriginTypeAwsKms, nil, core.OriginHSMGenerated},
		{"externally imported", kmstypes.OriginTypeExternal, nil, core.OriginImported},
		{"describe key error fails open", kmstypes.OriginTypeAwsKms, errors.New("kms: access denied"), core.OriginUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeECKMS(t)
			f.describeOrigin = c.origin
			f.describeErr = c.descErr
			s, err := New(f, "test-key")
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			got, err := s.KeyOrigin(context.Background(), "test-key")
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
// this per-key signer's own keyID reports OriginUnknown rather than this
// signer's own key's origin — KeyOrigin must not answer for a kid it
// doesn't own.
func TestKeyOrigin_UnknownKidReturnsUnknown(t *testing.T) {
	f := newFakeECKMS(t)
	f.describeOrigin = kmstypes.OriginTypeAwsKms
	s, err := New(f, "test-key")
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
