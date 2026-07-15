//go:build !no_pkcs11

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/cryptosigner"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/core"
)

// fakeSession is an in-process stand-in for a PKCS#11 token. It holds a
// locally generated key and answers Sign / PublicKeyDER EXACTLY as a real
// token would — crucially, for CKM_ECDSA it returns the RAW fixed-width R||S
// (PKCS#11 v2.40 §2.3.1), NOT DER, so the test proves Signer's R||S -> DER
// conversion is correct. No mocking framework, no real HSM, no SoftHSM: this
// is the §2 "real impl, no mocks" discipline applied to the token boundary.
type fakeSession struct {
	ecKey  *ecdsa.PrivateKey
	rsaKey *rsa.PrivateKey
	edPub  ed25519.PublicKey
	edPriv ed25519.PrivateKey

	pubCalls atomic.Int32
	pubErr   error // when set, PublicKeyDER returns this (transient/outage)
	signErr  error // when set, Sign returns this (fail-closed test)

	// failPubN: the first failPubN PublicKeyDER calls return a transient
	// error, the rest succeed — models a token outage at startup that clears,
	// driving the concurrency/retry test. Atomic so goroutines race safely.
	failPubN atomic.Int32

	// lastMech records the mechanism the last Sign was asked for, so a test
	// can assert opts -> mechanism mapping.
	lastMech atomic.Int32

	// originAttrs / originErr drive KeyOriginAttrs: originErr, when set,
	// models a token that cannot answer the CKA_LOCAL/CKA_NEVER_EXTRACTABLE
	// query (fail-open test); otherwise originAttrs is returned verbatim.
	originAttrs KeyOriginAttrs
	originErr   error
	// originCalls counts KeyOriginAttrs invocations, so a test can assert
	// the result is cached (queried once) rather than re-fetched.
	originCalls atomic.Int32
}

// KeyOriginAttrs implements [Session] for tests: it returns the configured
// synthetic attributes (or originErr), never touching a real token —
// exactly the seam that lets keyOriginFromAttrs be exercised without SoftHSM
// or a physical HSM.
func (f *fakeSession) KeyOriginAttrs(_ uint) (KeyOriginAttrs, error) {
	f.originCalls.Add(1)
	if f.originErr != nil {
		return KeyOriginAttrs{}, f.originErr
	}
	return f.originAttrs, nil
}

func newFakeEC(t *testing.T, curve elliptic.Curve) *fakeSession {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	return &fakeSession{ecKey: k}
}

func newFakeRSA(t *testing.T) *fakeSession {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return &fakeSession{rsaKey: k}
}

func newFakeEd25519(t *testing.T) *fakeSession {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return &fakeSession{edPub: pub, edPriv: priv}
}

func (f *fakeSession) publicKey() crypto.PublicKey {
	switch {
	case f.ecKey != nil:
		return &f.ecKey.PublicKey
	case f.rsaKey != nil:
		return &f.rsaKey.PublicKey
	default:
		return f.edPub
	}
}

func (f *fakeSession) PublicKeyDER() ([]byte, error) {
	f.pubCalls.Add(1)
	if f.failPubN.Load() > 0 && f.failPubN.Add(-1) >= 0 {
		return nil, errors.New("fakeSession: transient token outage")
	}
	if f.pubErr != nil {
		return nil, f.pubErr
	}
	return x509.MarshalPKIXPublicKey(f.publicKey())
}

func (f *fakeSession) Sign(mech Mechanism, _ uint, data []byte) ([]byte, error) {
	f.lastMech.Store(int32(mech))
	if f.signErr != nil {
		return nil, f.signErr
	}
	switch mech {
	case MechECDSA:
		// A real token returns RAW R||S, NOT DER. Produce exactly that so the
		// test exercises Signer's R||S -> DER conversion.
		return rawECSign(f.ecKey, data)
	case MechRSAPKCS1v15:
		// The token signs the DigestInfo bytes Signer handed it. Re-derive the
		// SHA-256 digest from the DigestInfo to feed rsa.SignPKCS1v15 (which
		// re-wraps it identically) — and assert the prefix matches so a broken
		// DigestInfo is caught here.
		digest, err := digestFromInfo(data)
		if err != nil {
			return nil, err
		}
		return rsa.SignPKCS1v15(rand.Reader, f.rsaKey, crypto.SHA256, digest)
	case MechRSAPSS:
		return rsa.SignPSS(rand.Reader, f.rsaKey, crypto.SHA256, data, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
	case MechEdDSA:
		return ed25519.Sign(f.edPriv, data), nil
	default:
		return nil, errors.New("fakeSession: unsupported mechanism " + mech.String())
	}
}

// rawECSign signs the digest and returns the RAW fixed-width R||S a PKCS#11
// CKM_ECDSA operation produces (NOT DER).
func rawECSign(k *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, k, digest)
	if err != nil {
		return nil, err
	}
	coordLen := (k.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*coordLen)
	r.FillBytes(out[:coordLen])
	s.FillBytes(out[coordLen:])
	return out, nil
}

// digestFromInfo strips the SHA-256 DigestInfo prefix Signer prepends for
// CKM_RSA_PKCS, returning the bare 32-byte digest (and asserting the prefix).
func digestFromInfo(di []byte) ([]byte, error) {
	if len(di) != len(sha256DigestInfoPrefix)+32 {
		return nil, errors.New("fakeSession: DigestInfo wrong length")
	}
	for i := range sha256DigestInfoPrefix {
		if di[i] != sha256DigestInfoPrefix[i] {
			return nil, errors.New("fakeSession: DigestInfo prefix mismatch")
		}
	}
	return di[len(sha256DigestInfoPrefix):], nil
}

func mustSigner(t *testing.T, f *fakeSession, pub crypto.PublicKey, opts ...Option) *Signer {
	t.Helper()
	s, err := NewSigner(f, 42, pub, opts...)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return s
}

// TestSignECDSAHashCurveMismatchRejected proves the signer fails closed when the
// requested hash does not match the curve's JWS pairing -- a direct crypto.Signer
// caller must not be able to sign a digest that would verify under a different
// hash than the published ES* alg (mirrors the awskms/gcpkms peers, which both
// enforce the curve->hash pairing).
func TestSignECDSAHashCurveMismatchRejected(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s := mustSigner(t, f, nil)

	// P-256 requires SHA-256; any other hash (incl. the zero hash) fails closed
	// BEFORE the token is asked to sign, so it never receives a mismatched digest.
	for _, h := range []crypto.Hash{crypto.SHA384, crypto.SHA512, crypto.Hash(0)} {
		if _, err := s.Sign(rand.Reader, make([]byte, 48), h); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("P-256 key + hash %v = %v, want ErrUnsupportedKey", h, err)
		}
	}
	// The correct pairing still signs.
	d := sha256.Sum256([]byte("ok"))
	if _, err := s.Sign(rand.Reader, d[:], crypto.SHA256); err != nil {
		t.Fatalf("P-256 + SHA-256 happy path: %v", err)
	}
}

// TestPublicKeyParsesAndCaches verifies Public() parses the SPKI DER into the
// right key type and reads the token public key only once (the cache).
func TestPublicKeyParsesAndCaches(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s := mustSigner(t, f, nil)

	pub := s.Public()
	if _, ok := pub.(*ecdsa.PublicKey); !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", pub)
	}
	_ = s.Public()
	if _, err := s.PublicKey(); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if got := f.pubCalls.Load(); got != 1 {
		t.Fatalf("PublicKeyDER called %d times, want 1 (cache)", got)
	}
}

// TestSuppliedPublicKeySkipsTokenRead verifies that a supplied public key is
// served without any token read.
func TestSuppliedPublicKeySkipsTokenRead(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s := mustSigner(t, f, &f.ecKey.PublicKey)
	if _, ok := s.Public().(*ecdsa.PublicKey); !ok {
		t.Fatal("Public() did not return the supplied key")
	}
	if got := f.pubCalls.Load(); got != 0 {
		t.Fatalf("PublicKeyDER called %d times with a supplied key, want 0", got)
	}
}

// TestSignECDSARoundTrip is the headline PKCS#11 test: the fake token returns
// RAW R||S; Signer must convert it to ASN.1 DER that (a) parses back to the
// SAME r,s and (b) verifies via ecdsa.VerifyASN1 (the stdlib contract the
// cryptosigner bridge relies on). Covers P-256 (ES256) and P-384 (ES384).
func TestSignECDSARoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
		hash  crypto.Hash
	}{
		{"P256/ES256", elliptic.P256(), crypto.SHA256},
		{"P384/ES384", elliptic.P384(), crypto.SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeEC(t, tc.curve)
			s := mustSigner(t, f, nil)
			pub := s.Public().(*ecdsa.PublicKey)

			var digest []byte
			switch tc.hash {
			case crypto.SHA256:
				d := sha256.Sum256([]byte("header.payload"))
				digest = d[:]
			default:
				h := tc.hash.New()
				h.Write([]byte("header.payload"))
				digest = h.Sum(nil)
			}

			der, err := s.Sign(rand.Reader, digest, tc.hash)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if Mechanism(f.lastMech.Load()) != MechECDSA {
				t.Fatalf("mechanism = %s, want CKM_ECDSA", Mechanism(f.lastMech.Load()))
			}

			// (a) The DER parses back to a valid SEQUENCE{r,s} with positive,
			//     in-range scalars (proves the conversion produced real DER).
			var parsed ecdsaDERSignature
			rest, err := asn1.Unmarshal(der, &parsed)
			if err != nil {
				t.Fatalf("converted signature is not valid DER: %v", err)
			}
			if len(rest) != 0 {
				t.Fatal("trailing bytes after DER signature")
			}
			coordLen := (tc.curve.Params().BitSize + 7) / 8
			if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 {
				t.Fatal("parsed R or S is non-positive")
			}
			if parsed.R.BitLen() > coordLen*8 || parsed.S.BitLen() > coordLen*8 {
				t.Fatal("parsed R or S exceeds the curve coordinate size")
			}

			// (b) The DER verifies against the public key.
			if !ecdsa.VerifyASN1(pub, digest, der) {
				t.Fatal("converted ECDSA DER signature did not verify")
			}
		})
	}
}

// TestRawToDERExactRoundTrip proves rawECDSAToDER is the exact inverse of the
// raw R||S split: a known (r,s) -> R||S -> DER parses back to the SAME r,s.
func TestRawToDERExactRoundTrip(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256()
	coordLen := (curve.Params().BitSize + 7) / 8
	r := new(big.Int).SetBytes([]byte{0x01, 0x02, 0x03, 0xab, 0xcd})
	sv := new(big.Int).SetBytes([]byte{0xfe, 0xed, 0xfa, 0xce})
	raw := make([]byte, 2*coordLen)
	r.FillBytes(raw[:coordLen])
	sv.FillBytes(raw[coordLen:])

	der, err := rawECDSAToDER(raw, curve)
	if err != nil {
		t.Fatalf("rawECDSAToDER: %v", err)
	}
	var parsed ecdsaDERSignature
	if _, err := asn1.Unmarshal(der, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.R.Cmp(r) != 0 || parsed.S.Cmp(sv) != 0 {
		t.Fatalf("round-trip mismatch: got (r=%x, s=%x), want (r=%x, s=%x)", parsed.R, parsed.S, r, sv)
	}
}

// TestRawToDERRejectsBadLength confirms a raw signature whose length doesn't
// match the curve is rejected rather than mis-split.
func TestRawToDERRejectsBadLength(t *testing.T) {
	t.Parallel()
	if _, err := rawECDSAToDER([]byte{0x01, 0x02, 0x03}, elliptic.P256()); err == nil {
		t.Fatal("rawECDSAToDER accepted a wrong-length raw signature")
	}
}

// TestSignRSARoundTrip verifies RS256 (DigestInfo path) + PS256 round-trip and
// map to the right mechanism.
func TestSignRSARoundTrip(t *testing.T) {
	t.Parallel()
	f := newFakeRSA(t)
	s := mustSigner(t, f, nil)
	pub := s.Public().(*rsa.PublicKey)
	digest := sha256.Sum256([]byte("header.payload"))

	t.Run("RS256/PKCS1v15", func(t *testing.T) {
		sig, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if Mechanism(f.lastMech.Load()) != MechRSAPKCS1v15 {
			t.Fatalf("mechanism = %s, want CKM_RSA_PKCS", Mechanism(f.lastMech.Load()))
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
		if Mechanism(f.lastMech.Load()) != MechRSAPSS {
			t.Fatalf("mechanism = %s, want CKM_RSA_PKCS_PSS", Mechanism(f.lastMech.Load()))
		}
		if err := rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		}); err != nil {
			t.Fatalf("PS256 verify: %v", err)
		}
	})
}

// TestSignEd25519RoundTrip verifies the EdDSA path: HashFunc()==0, the raw
// message is signed via CKM_EDDSA, and the 64-byte signature verifies.
func TestSignEd25519RoundTrip(t *testing.T) {
	t.Parallel()
	f := newFakeEd25519(t)
	s := mustSigner(t, f, nil)
	pub := s.Public().(ed25519.PublicKey)

	msg := []byte("header.payload.ed25519")
	sig, err := s.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if Mechanism(f.lastMech.Load()) != MechEdDSA {
		t.Fatalf("mechanism = %s, want CKM_EDDSA", Mechanism(f.lastMech.Load()))
	}
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("Ed25519 signature did not verify")
	}
}

// TestECDSARejectsZeroHash confirms an ECDSA key with HashFunc()==0 (EdDSA-
// style call) is rejected — EC keys need a pre-hash.
func TestECDSARejectsZeroHash(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s := mustSigner(t, f, nil)
	if _, err := s.Sign(rand.Reader, []byte("x"), crypto.Hash(0)); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("ECDSA Sign(hash=0) error = %v, want ErrUnsupportedKey", err)
	}
}

// TestEd25519RejectsPreHash confirms an Ed25519 key with a non-zero hash is
// rejected — the JWS EdDSA issuer signs the raw message.
func TestEd25519RejectsPreHash(t *testing.T) {
	t.Parallel()
	f := newFakeEd25519(t)
	s := mustSigner(t, f, nil)
	if _, err := s.Sign(rand.Reader, []byte("x"), crypto.SHA256); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("Ed25519 Sign(SHA256) error = %v, want ErrUnsupportedKey", err)
	}
}

// TestRSARejectsNonSHA256 confirms an RSA key with a non-SHA-256 hash is
// rejected (the JWS RSA issuers are SHA-256 only).
func TestRSARejectsNonSHA256(t *testing.T) {
	t.Parallel()
	f := newFakeRSA(t)
	s := mustSigner(t, f, nil)
	digest := make([]byte, 48)
	if _, err := s.Sign(rand.Reader, digest, crypto.SHA384); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("RSA Sign(SHA384) error = %v, want ErrUnsupportedKey", err)
	}
}

// TestSignFailsClosed confirms a token Sign error propagates (no unsigned
// token ever leaves the signer).
func TestSignFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.signErr = errors.New("token: CKR_DEVICE_ERROR")
	s := mustSigner(t, f, nil)
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("Sign succeeded despite a token error, want fail-closed")
	}
}

// TestSignNilOptsRejected: crypto.SignerOpts MAY be nil per the stdlib
// contract; this signer needs the hash it carries, so a nil must yield a clear
// error, never a nil-interface panic on opts.HashFunc().
func TestSignNilOptsRejected(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s := mustSigner(t, f, nil)
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

// TestPublicKeyFailsClosed confirms a token public-key read error surfaces
// from PublicKey() (and Public() returns nil).
func TestPublicKeyFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.pubErr = errors.New("token: CKR_TOKEN_NOT_PRESENT")
	s := mustSigner(t, f, nil)
	if _, err := s.PublicKey(); err == nil {
		t.Fatal("PublicKey() succeeded despite a token error")
	}
	if s.Public() != nil {
		t.Fatal("Public() returned non-nil despite a token error")
	}
}

// TestNewSignerRejectsNilSession covers the construction guard.
func TestNewSignerRejectsNilSession(t *testing.T) {
	t.Parallel()
	if _, err := NewSigner(nil, 1, nil); err == nil {
		t.Fatal("NewSigner(nil session) should error")
	}
}

// TestCloseOnFakeIsNoop confirms Close() is a safe no-op for a non-token
// (fake) session — Close only acts on the real miekg-backed session.
func TestCloseOnFakeIsNoop(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s := mustSigner(t, f, nil)
	if err := s.Close(); err != nil {
		t.Fatalf("Close() on fake session = %v, want nil", err)
	}
}

// TestConcurrentLoadPublicRetriesTransientError mirrors awskms: the public-key
// cache must be mutex-guarded (not sync.Once-reset). Many goroutines hammer
// Public()/Sign() while the fake errors the first few reads (a transient
// startup outage) before succeeding. Pre-fix (Once-reset) this data-races
// under -race; post-fix the mutex serializes reads, the error is retried (not
// poisoned), and once it clears every call caches the same key and signs.
func TestConcurrentLoadPublicRetriesTransientError(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.failPubN.Store(5) // first 5 reads fail, then succeed

	s := mustSigner(t, f, nil)
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
				if der, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
					if !ecdsa.VerifyASN1(&f.ecKey.PublicKey, digest[:], der) {
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
		t.Fatal("no goroutine ever signed; transient error was not retried")
	}
	der, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("post-outage Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&f.ecKey.PublicKey, digest[:], der) {
		t.Fatal("post-outage signature did not verify")
	}
}

// TestEndToEndECDSAIssuer is the integration headline: a token minted through
// the REAL ECDSAJWTIssuer wired with WithECDSAExternalSigner over the
// cryptosigner bridge over the fake PKCS#11 signer must Validate. This proves
// the full chain — token RAW R||S -> Signer DER -> cryptosigner JWS R||S ->
// JWS ES256 -> Validate.
func TestEndToEndECDSAIssuer(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	signer := mustSigner(t, f, nil)

	bridge, pub, err := cryptosigner.ECDSA(signer)
	if err != nil {
		t.Fatalf("cryptosigner.ECDSA: %v", err)
	}
	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAExternalSigner(bridge, pub, "pkcs11-test-kid"),
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
// through the REAL RSAJWTIssuer + cryptosigner.RSA bridge over the fake token.
func TestEndToEndRSAIssuer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		alg  string
	}{
		{"RS256", cryptosigner.AlgRS256},
		{"PS256", cryptosigner.AlgPS256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeRSA(t)
			signer := mustSigner(t, f, nil)
			bridge, pub, err := cryptosigner.RSA(signer, tc.alg)
			if err != nil {
				t.Fatalf("cryptosigner.RSA: %v", err)
			}
			iss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAAlg(tc.alg),
				defaultimpl.WithRSAExternalSigner(bridge, pub, "pkcs11-rsa-kid"),
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

// TestEndToEndEd25519Issuer proves the EdDSA chain through the REAL
// Ed25519JWTIssuer + cryptosigner.Ed25519 bridge over the fake token (the
// CKM_EDDSA path awskms cannot offer).
func TestEndToEndEd25519Issuer(t *testing.T) {
	t.Parallel()
	f := newFakeEd25519(t)
	signer := mustSigner(t, f, nil)

	bridge, pub, err := cryptosigner.Ed25519(signer)
	if err != nil {
		t.Fatalf("cryptosigner.Ed25519: %v", err)
	}
	iss := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519ExternalSigner(bridge, pub, "pkcs11-eddsa-kid"),
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
}

// TestKeyOriginFromAttrs is the pure, no-token-required unit test for the
// CKA_LOCAL/CKA_NEVER_EXTRACTABLE -> core.KeyOrigin interpretation
// (keyOriginFromAttrs, origin.go). This is the ONLY part of the origin
// classification exercised against synthetic inputs rather than a live
// token: this environment has neither a real HSM nor SoftHSM2 installed
// (confirmed: no pkcs11-tool/softhsm2-util binary and no libsofthsm2.so on
// this machine), so the actual C_GetAttributeValue round-trip
// (session_origin.go's realSession.KeyOriginAttrs) cannot be integration-
// tested here. Splitting the byte-interpretation into this pure function is
// what makes it testable anyway.
func TestKeyOriginFromAttrs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   KeyOriginAttrs
		want core.KeyOrigin
	}{
		{
			name: "not local -> imported (key material arrived from outside the token)",
			in:   KeyOriginAttrs{Local: false, NeverExtractable: true},
			want: core.OriginImported,
		},
		{
			name: "local and never-extractable -> HSM generated (strongest attestation)",
			in:   KeyOriginAttrs{Local: true, NeverExtractable: true},
			want: core.OriginHSMGenerated,
		},
		{
			name: "local but extractable at some point -> unknown (cannot overclaim HSM)",
			in:   KeyOriginAttrs{Local: true, NeverExtractable: false},
			want: core.OriginUnknown,
		},
		{
			name: "zero value (neither attribute readable) -> imported, not a silent HSM claim",
			in:   KeyOriginAttrs{},
			want: core.OriginImported,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := keyOriginFromAttrs(tc.in); got != tc.want {
				t.Errorf("keyOriginFromAttrs(%+v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestKeyOriginAutoDetectsAndCaches proves the no-WithKeyOrigin path queries
// the token's attributes through the Session (fakeSession here, standing in
// for realSession.KeyOriginAttrs) exactly once and caches the classification
// for the process lifetime, mirroring the awskms/gcpkms/azurekeyvault
// "resolve once at first use, cache forever" pattern.
func TestKeyOriginAutoDetectsAndCaches(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.originAttrs = KeyOriginAttrs{Local: true, NeverExtractable: true}
	s := mustSigner(t, f, nil)

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		origin, err := s.KeyOrigin(ctx, "")
		if err != nil {
			t.Fatalf("KeyOrigin call %d: %v", i, err)
		}
		if origin != core.OriginHSMGenerated {
			t.Fatalf("KeyOrigin call %d = %v, want OriginHSMGenerated", i, origin)
		}
	}
	if calls := f.originCalls.Load(); calls != 1 {
		t.Fatalf("KeyOriginAttrs called %d times, want 1 (result must be cached)", calls)
	}
}

// TestKeyOriginQueryErrorFailsOpenAndRetries proves a token attribute-read
// failure fails OPEN to core.OriginUnknown (never an error surfaced to the
// caller — this is an audit-attestation gap, not a signing-path failure)
// and is NOT permanently cached, so a transient outage clears on the next
// call instead of poisoning the origin to Unknown forever (same retry
// discipline as loadPublic's public-key cache).
func TestKeyOriginQueryErrorFailsOpenAndRetries(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.originErr = errors.New("token: CKR_ATTRIBUTE_TYPE_INVALID")
	s := mustSigner(t, f, nil)
	ctx := context.Background()

	origin, err := s.KeyOrigin(ctx, "")
	if err != nil {
		t.Fatalf("KeyOrigin (query error) returned an error, want fail-open nil: %v", err)
	}
	if origin != core.OriginUnknown {
		t.Fatalf("KeyOrigin (query error) = %v, want OriginUnknown", origin)
	}

	// The outage clears; the NEXT call must retry (not stay poisoned).
	f.originErr = nil
	f.originAttrs = KeyOriginAttrs{Local: true, NeverExtractable: true}
	origin, err = s.KeyOrigin(ctx, "")
	if err != nil {
		t.Fatalf("KeyOrigin (post-outage): %v", err)
	}
	if origin != core.OriginHSMGenerated {
		t.Fatalf("KeyOrigin (post-outage) = %v, want OriginHSMGenerated (retry, not poisoned)", origin)
	}
	if calls := f.originCalls.Load(); calls != 2 {
		t.Fatalf("KeyOriginAttrs called %d times, want 2 (one failed attempt, one retry)", calls)
	}
}

// TestWithKeyOriginOverridesAutoDetection proves the explicit WithKeyOrigin
// Option wins unconditionally over auto-detection: the fake token is
// configured to auto-detect as OriginImported, but the caller's explicit
// override must be returned instead, AND the token must never even be
// queried (no wasted round-trip once the operator has already answered the
// question out-of-band).
func TestWithKeyOriginOverridesAutoDetection(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.originAttrs = KeyOriginAttrs{Local: false} // would auto-detect as Imported
	s := mustSigner(t, f, nil, WithKeyOrigin(core.OriginHSMGenerated))

	origin, err := s.KeyOrigin(context.Background(), "")
	if err != nil {
		t.Fatalf("KeyOrigin: %v", err)
	}
	if origin != core.OriginHSMGenerated {
		t.Fatalf("KeyOrigin = %v, want the WithKeyOrigin override (OriginHSMGenerated), auto-detection must not win", origin)
	}
	if calls := f.originCalls.Load(); calls != 0 {
		t.Fatalf("KeyOriginAttrs called %d times, want 0 -- an explicit override must skip the token round-trip entirely", calls)
	}
}

// TestKeyOrigin_UnknownKidReturnsUnknown proves a kid that doesn't match
// this signer's own configured kid (WithKeyID) reports OriginUnknown
// without touching the token -- mirroring the awskms/gcpkms/azurekeyvault
// peers, all of which reject a foreign kid the same way. Backend-drift
// regression: this signer previously ignored kid entirely and would
// misattribute a query about a DIFFERENT key to its own token's origin.
func TestKeyOrigin_UnknownKidReturnsUnknown(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.originAttrs = KeyOriginAttrs{Local: true, NeverExtractable: true}
	s := mustSigner(t, f, nil, WithKeyID("my-key"))

	got, err := s.KeyOrigin(context.Background(), "some-other-key")
	if err != nil {
		t.Fatalf("KeyOrigin: %v", err)
	}
	if got != core.OriginUnknown {
		t.Fatalf("KeyOrigin(mismatched kid) = %v, want OriginUnknown", got)
	}
	if calls := f.originCalls.Load(); calls != 0 {
		t.Fatalf("KeyOriginAttrs called %d times, want 0 -- a mismatched kid must not touch the token", calls)
	}

	// The signer's own kid still resolves normally.
	got, err = s.KeyOrigin(context.Background(), "my-key")
	if err != nil {
		t.Fatalf("KeyOrigin (own kid): %v", err)
	}
	if got != core.OriginHSMGenerated {
		t.Fatalf("KeyOrigin(own kid) = %v, want OriginHSMGenerated", got)
	}
}

// TestKeyOrigin_NoKeyIDConfiguredAnswersAnyKid proves that when no WithKeyID
// was supplied (the pre-existing NewSigner call shape, and any construction
// where only CKA_ID bytes -- not a KeyLabel string -- located the key), kid
// validation stays permissive: there is nothing to compare a caller's kid
// against, so KeyOrigin answers for any kid rather than false-rejecting
// every call. Backward-compatibility guard alongside the kid-mismatch test
// above.
func TestKeyOrigin_NoKeyIDConfiguredAnswersAnyKid(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.originAttrs = KeyOriginAttrs{Local: true, NeverExtractable: true}
	s := mustSigner(t, f, nil) // no WithKeyID

	got, err := s.KeyOrigin(context.Background(), "whatever-kid-a-caller-passes")
	if err != nil {
		t.Fatalf("KeyOrigin: %v", err)
	}
	if got != core.OriginHSMGenerated {
		t.Fatalf("KeyOrigin (no keyID configured) = %v, want OriginHSMGenerated (unconfigured kid must not reject)", got)
	}
}
