package azurekeyvault

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
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/fake"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/cryptosigner"
	"github.com/snaplink/sso/interfaces/sso"
)

// fakeVault is an in-process stand-in for the azkeys.Client. It holds a
// locally generated private key and answers GetKey / Sign EXACTLY as the real
// Key Vault would: GetKey returns the JSON Web Key (RSA n/e or EC x/y/crv);
// Sign signs the supplied digest with the local key and returns Azure's WIRE
// format — RAW fixed-width R||S for ECDSA (NOT ASN.1 DER), raw bytes for RSA.
// This is the critical fixture: returning R||S forces the Signer's R||S->DER
// conversion to be exercised and round-tripped against ecdsa.VerifyASN1. No
// mocking framework and no real Azure — the §2 "real impl, no mocks"
// discipline applied to the cloud boundary, exactly as kms/awskms + kms/gcpkms.
type fakeVault struct {
	ecKey  *ecdsa.PrivateKey
	rsaKey *rsa.PrivateKey
	edPub  ed25519.PublicKey // for the "vault somehow returns an OKP key" guard

	getKeyCalls atomic.Int32
	signErr     error // when set, Sign returns this (fail-closed test)

	// failGetN: the first failGetN GetKey calls return a transient error, the
	// rest succeed. Models a vault outage at startup that clears (drives the
	// concurrency/retry test). Read atomically so many goroutines race safely.
	failGetN atomic.Int32

	// getBlock / signBlock, when non-nil, are received from before the
	// respective op returns — the test sends to/closes them to simulate a
	// vault call that hangs longer than WithCallTimeout (drives the
	// call-timeout test).
	getBlock  <-chan struct{}
	signBlock <-chan struct{}
}

// fakeVaultJWK is a minimal keyVaultAPI that returns a CRAFTED JSON Web Key
// verbatim from GetKey — used to drive jwkToPublic via the Public()/PublicKey()
// path with inputs a live private key cannot produce (e.g. a forged E=1
// exponent a misbehaving vault might return). Sign is unused here.
type fakeVaultJWK struct{ jwk *azkeys.JSONWebKey }

func (f *fakeVaultJWK) GetKey(_ context.Context, _ string, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: f.jwk}}, nil
}

func (f *fakeVaultJWK) Sign(_ context.Context, _ string, _ string, _ azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	return azkeys.SignResponse{}, errors.New("fakeVaultJWK: Sign not supported")
}

func newFakeEC(t *testing.T, curve elliptic.Curve) *fakeVault {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	return &fakeVault{ecKey: k}
}

func newFakeRSA(t *testing.T) *fakeVault {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	return &fakeVault{rsaKey: k}
}

func newFakeEd25519(t *testing.T) *fakeVault {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	return &fakeVault{edPub: pub}
}

// jwk builds the JSON Web Key the real vault would return for this key,
// mirroring Azure's raw big-endian octet-string encoding of each component.
func (f *fakeVault) jwk() *azkeys.JSONWebKey {
	switch {
	case f.ecKey != nil:
		curveName, coordLen := ecParams(f.ecKey.Curve)
		x := make([]byte, coordLen)
		y := make([]byte, coordLen)
		f.ecKey.X.FillBytes(x)
		f.ecKey.Y.FillBytes(y)
		return &azkeys.JSONWebKey{
			Kty: to.Ptr(azkeys.KeyTypeEC),
			Crv: to.Ptr(curveName),
			X:   x,
			Y:   y,
		}
	case f.rsaKey != nil:
		return &azkeys.JSONWebKey{
			Kty: to.Ptr(azkeys.KeyTypeRSA),
			N:   f.rsaKey.N.Bytes(),
			E:   big.NewInt(int64(f.rsaKey.E)).Bytes(),
		}
	default:
		// An OKP/Ed25519 JWK as Azure would NOT actually return (it has no
		// EdDSA key type) — used only to prove jwkToPublic rejects it.
		return &azkeys.JSONWebKey{
			Kty: to.Ptr(azkeys.KeyType("OKP")),
			Crv: to.Ptr(azkeys.CurveName("Ed25519")),
			X:   f.edPub,
		}
	}
}

func ecParams(c elliptic.Curve) (azkeys.CurveName, int) {
	switch c {
	case elliptic.P256():
		return azkeys.CurveNameP256, 32
	case elliptic.P384():
		return azkeys.CurveNameP384, 48
	case elliptic.P521():
		return azkeys.CurveNameP521, 66
	default:
		return azkeys.CurveName("?"), 0
	}
}

func (f *fakeVault) GetKey(ctx context.Context, _ string, _ string, _ *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error) {
	f.getKeyCalls.Add(1)
	// Fail the first failGetN calls to model a transient vault outage that
	// later clears. Decrement so retries eventually break through; once the
	// counter is exhausted Load() stays <= 0 and every call succeeds.
	if f.failGetN.Load() > 0 && f.failGetN.Add(-1) >= 0 {
		return azkeys.GetKeyResponse{}, errors.New("fakeVault: transient GetKey outage")
	}
	if f.getBlock != nil {
		select {
		case <-f.getBlock:
		case <-ctx.Done():
			return azkeys.GetKeyResponse{}, ctx.Err()
		}
	}
	return azkeys.GetKeyResponse{KeyBundle: azkeys.KeyBundle{Key: f.jwk()}}, nil
}

func (f *fakeVault) Sign(ctx context.Context, _ string, _ string, params azkeys.SignParameters, _ *azkeys.SignOptions) (azkeys.SignResponse, error) {
	if f.signErr != nil {
		return azkeys.SignResponse{}, f.signErr
	}
	if f.signBlock != nil {
		select {
		case <-f.signBlock:
		case <-ctx.Done():
			return azkeys.SignResponse{}, ctx.Err()
		}
	}
	if params.Algorithm == nil {
		return azkeys.SignResponse{}, errors.New("fakeVault: nil algorithm")
	}
	digest := params.Value
	var result []byte
	switch *params.Algorithm {
	case azkeys.SignatureAlgorithmES256, azkeys.SignatureAlgorithmES384, azkeys.SignatureAlgorithmES512:
		// Azure returns ECDSA signatures as RAW R||S (RFC 7518 §3.4), fixed
		// width per curve — NOT ASN.1 DER. Reproduce that exactly so the
		// Signer's R||S->DER conversion is the thing under test.
		r, sv, err := ecdsa.Sign(rand.Reader, f.ecKey, digest)
		if err != nil {
			return azkeys.SignResponse{}, err
		}
		_, coordLen := ecParams(f.ecKey.Curve)
		result = make([]byte, 2*coordLen)
		r.FillBytes(result[:coordLen])
		sv.FillBytes(result[coordLen:])
	case azkeys.SignatureAlgorithmRS256:
		sig, err := rsa.SignPKCS1v15(rand.Reader, f.rsaKey, crypto.SHA256, digest)
		if err != nil {
			return azkeys.SignResponse{}, err
		}
		result = sig
	case azkeys.SignatureAlgorithmPS256:
		sig, err := rsa.SignPSS(rand.Reader, f.rsaKey, crypto.SHA256, digest, &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthEqualsHash,
			Hash:       crypto.SHA256,
		})
		if err != nil {
			return azkeys.SignResponse{}, err
		}
		result = sig
	default:
		return azkeys.SignResponse{}, errors.New("fakeVault: unsupported algorithm " + string(*params.Algorithm))
	}
	return azkeys.SignResponse{KeyOperationResult: azkeys.KeyOperationResult{Result: result}}, nil
}

const (
	testKeyName    = "signing-key"
	testKeyVersion = "abc123"
)

// TestPublicKeyParsesAndCaches verifies Public() builds the right key type
// from the JWK and that GetKey is hit only once (the cache).
func TestPublicKeyParsesAndCaches(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s, err := NewSigner(f, testKeyName, testKeyVersion)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	pub, ok := s.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *ecdsa.PublicKey", s.Public())
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("curve = %s, want P-256", pub.Curve.Params().Name)
	}
	// The reconstructed public key must equal the fake's real key.
	if !pub.Equal(&f.ecKey.PublicKey) {
		t.Fatal("reconstructed EC public point does not match the source key")
	}
	// Second + third calls must NOT re-fetch.
	_ = s.Public()
	if _, err := s.PublicKey(context.Background()); err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if got := f.getKeyCalls.Load(); got != 1 {
		t.Fatalf("GetKey called %d times, want 1 (cache)", got)
	}
}

// TestPublicKeyRSA verifies the RSA JWK (n/e) reconstructs the right key.
func TestPublicKeyRSA(t *testing.T) {
	t.Parallel()
	f := newFakeRSA(t)
	s, err := NewSigner(f, testKeyName, testKeyVersion)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	pub, ok := s.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("Public() = %T, want *rsa.PublicKey", s.Public())
	}
	if pub.N.Cmp(f.rsaKey.N) != 0 || pub.E != f.rsaKey.E {
		t.Fatal("reconstructed RSA public key does not match the source key")
	}
}

// TestSignVerifyTable is the headline test: Sign maps to the right Azure
// algorithm, the fake returns Azure's WIRE format (raw R||S for EC, raw for
// RSA), and the Signer's output verifies against the public key with the
// stdlib verifier the cryptosigner bridge relies on. For EC this proves the
// raw-R||S -> ASN.1 DER conversion is byte-exact across all three curves (a
// wrong split would fail ecdsa.VerifyASN1).
func TestSignVerifyTable(t *testing.T) {
	t.Parallel()
	msg := []byte("header.payload")
	sum256 := sha256.Sum256(msg)
	sum384 := sha512.Sum384(msg)
	sum512 := sha512.Sum512(msg)

	t.Run("ES256/P-256", func(t *testing.T) {
		f := newFakeEC(t, elliptic.P256())
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		pub := s.Public().(*ecdsa.PublicKey)
		der, err := s.Sign(rand.Reader, sum256[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !ecdsa.VerifyASN1(pub, sum256[:], der) {
			t.Fatal("ES256 DER signature (converted from raw R||S) did not verify")
		}
	})

	t.Run("ES384/P-384", func(t *testing.T) {
		f := newFakeEC(t, elliptic.P384())
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		pub := s.Public().(*ecdsa.PublicKey)
		der, err := s.Sign(rand.Reader, sum384[:], crypto.SHA384)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !ecdsa.VerifyASN1(pub, sum384[:], der) {
			t.Fatal("ES384 DER signature (converted from raw R||S) did not verify")
		}
	})

	t.Run("ES512/P-521", func(t *testing.T) {
		// P-521 is the sharpest test of the per-curve width: 66-byte
		// coordinates with a leading byte that is frequently zero, so a
		// length-agnostic split would silently corrupt R or S.
		f := newFakeEC(t, elliptic.P521())
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		pub := s.Public().(*ecdsa.PublicKey)
		der, err := s.Sign(rand.Reader, sum512[:], crypto.SHA512)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if !ecdsa.VerifyASN1(pub, sum512[:], der) {
			t.Fatal("ES512 DER signature (converted from raw R||S) did not verify")
		}
	})

	t.Run("RS256", func(t *testing.T) {
		f := newFakeRSA(t)
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
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
		f := newFakeRSA(t)
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
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
}

// TestSignRepeatedVerifies signs many times: ECDSA is randomized, so a
// borderline R/S (a high coordinate byte that lands on zero) must still
// convert + verify every time. Catches an off-by-one in the width handling
// that a single-shot test could miss.
func TestSignRepeatedVerifies(t *testing.T) {
	t.Parallel()
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		f := newFakeEC(t, curve)
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		pub := s.Public().(*ecdsa.PublicKey)
		hash := map[elliptic.Curve]crypto.Hash{
			elliptic.P256(): crypto.SHA256,
			elliptic.P384(): crypto.SHA384,
			elliptic.P521(): crypto.SHA512,
		}[curve]
		for i := 0; i < 200; i++ {
			h := sha512.Sum512([]byte{byte(i), byte(i >> 8)})
			digest := h[:hash.Size()]
			der, err := s.Sign(rand.Reader, digest, hash)
			if err != nil {
				t.Fatalf("%s Sign[%d]: %v", curve.Params().Name, i, err)
			}
			if !ecdsa.VerifyASN1(pub, digest, der) {
				t.Fatalf("%s signature[%d] did not verify (R||S split corruption?)", curve.Params().Name, i)
			}
		}
	}
}

// TestEdDSARejected confirms an EdDSA request (HashFunc()==0) is rejected
// clearly — Azure Key Vault has no Ed25519/EdDSA key type. Driven against an
// EC key (the realistic case: a caller mistakenly passes HashFunc()==0).
func TestEdDSARejected(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s, _ := NewSigner(f, testKeyName, testKeyVersion)
	if _, err := s.Sign(rand.Reader, []byte("msg"), crypto.Hash(0)); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("EdDSA Sign error = %v, want ErrUnsupportedKey", err)
	}
}

// TestEd25519JWKRejected confirms that even if the vault somehow returned an
// OKP/Ed25519 JWK, jwkToPublic rejects it (Azure has no such key, but the
// public-key parse must fail loud rather than build a bogus key).
func TestEd25519JWKRejected(t *testing.T) {
	t.Parallel()
	f := newFakeEd25519(t)
	s, _ := NewSigner(f, testKeyName, testKeyVersion)
	if _, err := s.PublicKey(context.Background()); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("PublicKey for OKP JWK error = %v, want ErrUnsupportedKey", err)
	}
}

// TestSignHashCurveMismatchRejected confirms the fail-closed hash<->curve
// pairing: a digest hashed under the wrong function for the key's curve is
// rejected BEFORE any vault call, so a direct crypto.Signer caller cannot mint
// a signature that disagrees with the JWKS-published ES* alg.
func TestSignHashCurveMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Run("P-256 with SHA-384", func(t *testing.T) {
		f := newFakeEC(t, elliptic.P256())
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		h := sha512.Sum384([]byte("x"))
		if _, err := s.Sign(rand.Reader, h[:], crypto.SHA384); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v, want ErrUnsupportedKey", err)
		}
		if f.signErr == nil && f.getKeyCalls.Load() == 0 {
			t.Fatal("expected GetKey to have been consulted")
		}
	})

	t.Run("P-384 with SHA-256", func(t *testing.T) {
		f := newFakeEC(t, elliptic.P384())
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		h := sha256.Sum256([]byte("x"))
		if _, err := s.Sign(rand.Reader, h[:], crypto.SHA256); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v, want ErrUnsupportedKey", err)
		}
	})

	t.Run("P-256 with hash 0", func(t *testing.T) {
		f := newFakeEC(t, elliptic.P256())
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		if _, err := s.Sign(rand.Reader, []byte("x"), crypto.Hash(0)); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v, want ErrUnsupportedKey", err)
		}
	})

	t.Run("RSA with SHA-512", func(t *testing.T) {
		f := newFakeRSA(t)
		s, _ := NewSigner(f, testKeyName, testKeyVersion)
		h := sha512.Sum512([]byte("x"))
		if _, err := s.Sign(rand.Reader, h[:], crypto.SHA512); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v, want ErrUnsupportedKey", err)
		}
	})
}

// TestSignFailsClosed confirms a vault Sign error propagates (no unsigned
// token ever leaves the signer).
func TestSignFailsClosed(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.signErr = errors.New("vault forbidden")
	s, _ := NewSigner(f, testKeyName, testKeyVersion)
	digest := sha256.Sum256([]byte("x"))
	if _, err := s.Sign(rand.Reader, digest[:], crypto.SHA256); err == nil {
		t.Fatal("Sign succeeded despite vault error, want fail-closed error")
	}
}

// TestSignNilOptsRejected: crypto.SignerOpts MAY be nil per the stdlib
// contract; this signer needs the hash it carries, so a nil must yield a clear
// error, never a nil-interface panic on opts.HashFunc().
func TestSignNilOptsRejected(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	s, _ := NewSigner(f, testKeyName, testKeyVersion)
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

// TestEndToEndECDSAIssuer is the integration headline: a token minted through
// the REAL ECDSAJWTIssuer wired with WithECDSAExternalSigner over the
// cryptosigner bridge over the fake-vault signer must Validate. This proves
// the full chain — Azure raw R||S -> azurekeyvault DER -> cryptosigner R||S ->
// JWS ES256 -> Validate.
func TestEndToEndECDSAIssuer(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	signer, err := NewSigner(f, testKeyName, testKeyVersion)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}

	bridge, pub, err := cryptosigner.ECDSA(signer)
	if err != nil {
		t.Fatalf("cryptosigner.ECDSA: %v", err)
	}

	iss := defaultimpl.NewECDSAJWTIssuer(
		defaultimpl.WithECDSAExternalSigner(bridge, pub, "azurekeyvault-test-kid"),
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
// through the REAL RSAJWTIssuer + cryptosigner.RSA bridge over the fake vault.
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
			signer, err := NewSigner(f, testKeyName, testKeyVersion)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			bridge, pub, err := cryptosigner.RSA(signer, tc.alg)
			if err != nil {
				t.Fatalf("cryptosigner.RSA: %v", err)
			}
			iss := defaultimpl.NewRSAJWTIssuer(
				defaultimpl.WithRSAAlg(tc.alg),
				defaultimpl.WithRSAExternalSigner(bridge, pub, "azurekeyvault-rsa-kid"),
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
	if _, err := NewSigner(nil, testKeyName, testKeyVersion); err == nil {
		t.Fatal("NewSigner(nil client) should error")
	}
	if _, err := NewSigner(newFakeEC(t, elliptic.P256()), "", testKeyVersion); err == nil {
		t.Fatal("NewSigner(empty keyName) should error")
	}
	// Empty version is VALID (signs the current version) — must NOT error.
	if _, err := NewSigner(newFakeEC(t, elliptic.P256()), testKeyName, ""); err != nil {
		t.Fatalf("NewSigner(empty version) unexpectedly errored: %v", err)
	}
}

// TestNewSignerFromVaultURLGuards covers the convenience constructor's cheap
// guards (it cannot reach Azure in a unit test, but the arg validation must
// fail loud before any network attempt). It uses the SDK's own fake
// TokenCredential so the real azkeys.NewClient + azcore.TokenCredential seam
// is exercised on the happy-credential path.
func TestNewSignerFromVaultURLGuards(t *testing.T) {
	t.Parallel()
	if _, err := NewSignerFromVaultURL("", testKeyName, testKeyVersion, &fake.TokenCredential{}, nil); err == nil {
		t.Fatal("empty vault URL should error")
	}
	if _, err := NewSignerFromVaultURL("https://v.vault.azure.net", testKeyName, testKeyVersion, nil, nil); err == nil {
		t.Fatal("nil credential should error")
	}
	// Valid args + a fake credential: NewClient succeeds, NewSigner returns a
	// usable *Signer (no Azure call happens until the first Public()/Sign()).
	s, err := NewSignerFromVaultURL("https://v.vault.azure.net", testKeyName, testKeyVersion, &fake.TokenCredential{}, nil)
	if err != nil {
		t.Fatalf("NewSignerFromVaultURL(valid): %v", err)
	}
	if s == nil {
		t.Fatal("NewSignerFromVaultURL returned nil signer")
	}
}

// TestConcurrentLoadPublicRetriesTransientError exercises the public-key
// cache: it must be mutex-guarded, not sync.Once-reset. Many goroutines hammer
// Public()/Sign() concurrently while the fake vault errors the first few
// GetKey calls (a transient startup outage) before succeeding.
//
// With a sync.Once reset inside Do this data-races (the reset writes a
// sync.Once while peers call .Do on it) so `go test -race` would FAIL. With
// the mutex the fetches serialize, the transient error is retried (not
// poisoned), and once it clears every signer caches the same immutable key and
// signs successfully.
func TestConcurrentLoadPublicRetriesTransientError(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	f.failGetN.Store(5)

	s, err := NewSigner(f, testKeyName, testKeyVersion)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
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
		t.Fatal("no goroutine ever signed successfully; transient error was not retried")
	}

	der, err := s.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("post-outage Sign: %v", err)
	}
	if !ecdsa.VerifyASN1(&f.ecKey.PublicKey, digest[:], der) {
		t.Fatal("post-outage signature did not verify")
	}
}

// rsaJWK builds an RSA JSON Web Key from explicit modulus + exponent bytes,
// mirroring Azure's raw big-endian octet-string encoding. Used to feed
// jwkToPublic crafted N/E that a misbehaving vault could return.
func rsaJWK(n, e []byte) *azkeys.JSONWebKey {
	return &azkeys.JSONWebKey{
		Kty: to.Ptr(azkeys.KeyTypeRSA),
		N:   n,
		E:   e,
	}
}

// TestRSAExponentValidation locks the MEDIUM-1 hardening: a raw-JWK RSA public
// exponent below 3, or an even exponent, is rejected (e=1 is the forgeable
// identity exponent; e=2/e=4 are even → never coprime with phi(N)). Legitimate
// small odd exponents (e=3, e=65537) are accepted. A valid >=2048-bit modulus
// is reused throughout so the EXPONENT is the only variable under test.
func TestRSAExponentValidation(t *testing.T) {
	t.Parallel()
	good := newFakeRSA(t) // a real 2048-bit key supplies a valid modulus
	nBytes := good.rsaKey.N.Bytes()

	for _, tc := range []struct {
		name   string
		e      []byte
		accept bool
	}{
		{"e=1 identity (forgeable)", []byte{0x01}, false},
		{"e=2 even", []byte{0x02}, false},
		{"e=4 even", []byte{0x04}, false},
		{"e=0", []byte{0x00}, false}, // already covered by the <=0 guard
		{"e=3 valid odd", []byte{0x03}, true},
		{"e=65537 valid", []byte{0x01, 0x00, 0x01}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, err := jwkToPublic(rsaJWK(nBytes, tc.e))
			if tc.accept {
				if err != nil {
					t.Fatalf("e=%x: jwkToPublic error = %v, want accepted", tc.e, err)
				}
				rp, ok := pub.(*rsa.PublicKey)
				if !ok {
					t.Fatalf("e=%x: got %T, want *rsa.PublicKey", tc.e, pub)
				}
				if rp.E != int(new(big.Int).SetBytes(tc.e).Int64()) {
					t.Fatalf("e=%x: reconstructed E = %d", tc.e, rp.E)
				}
			} else if !errors.Is(err, ErrUnsupportedKey) {
				t.Fatalf("e=%x: error = %v, want ErrUnsupportedKey", tc.e, err)
			}
		})
	}
}

// TestRSAExponentValidationThroughPublic confirms the exponent guard also fires
// on the GetKey-fed Public() path (not just the direct jwkToPublic call): a
// vault returning E=1 yields a nil Public()/erroring PublicKey, never an
// rsa.PublicKey{E:1}.
func TestRSAExponentValidationThroughPublic(t *testing.T) {
	t.Parallel()
	good := newFakeRSA(t)
	f := &fakeVaultJWK{jwk: rsaJWK(good.rsaKey.N.Bytes(), []byte{0x01})}
	s, err := NewSigner(f, testKeyName, testKeyVersion)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := s.PublicKey(context.Background()); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("PublicKey for E=1 JWK error = %v, want ErrUnsupportedKey", err)
	}
	if pub := s.Public(); pub != nil {
		t.Fatalf("Public() for E=1 JWK = %v, want nil (never an rsa.PublicKey{E:1})", pub)
	}
}

// TestRSAModulusFloor locks the LOW-2 hardening: a sub-2048-bit RSA modulus is
// rejected even with a valid exponent, protecting a direct crypto.Signer
// consumer that bypasses cryptosigner.RSA's startup floor. A 2048-bit modulus
// is accepted (and the existing happy-path RSA tests, which use 2048-bit keys,
// stay green).
func TestRSAModulusFloor(t *testing.T) {
	t.Parallel()
	e := []byte{0x01, 0x00, 0x01} // 65537, a valid exponent

	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generate 1024-bit key: %v", err)
	}
	if weak.N.BitLen() >= minRSABits {
		t.Fatalf("1024-bit key reported %d bits, fixture invalid", weak.N.BitLen())
	}
	if _, err := jwkToPublic(rsaJWK(weak.N.Bytes(), e)); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("1024-bit modulus error = %v, want ErrUnsupportedKey", err)
	}

	strong := newFakeRSA(t) // 2048-bit
	if strong.rsaKey.N.BitLen() < minRSABits {
		t.Fatalf("happy-path RSA fixture is %d bits, below the 2048 floor", strong.rsaKey.N.BitLen())
	}
	pub, err := jwkToPublic(rsaJWK(strong.rsaKey.N.Bytes(), e))
	if err != nil {
		t.Fatalf("2048-bit modulus: jwkToPublic error = %v, want accepted", err)
	}
	if _, ok := pub.(*rsa.PublicKey); !ok {
		t.Fatalf("2048-bit modulus: got %T, want *rsa.PublicKey", pub)
	}
}

// TestECPointValidation locks the LOW-1 on-curve guard (whichever
// implementation): a JWK whose X/Y is off-curve, out-of-range ([0,P) violated),
// or the point at infinity (0,0) is rejected — never assembled into a key that
// would sign garbage. All three are fed through jwkToPublic against a real
// curve's coordinate encoding.
func TestECPointValidation(t *testing.T) {
	t.Parallel()
	curve := elliptic.P256()
	curveName, coordLen := ecParams(curve)
	p := curve.Params().P

	// A real on-curve point, to perturb into the off-curve case.
	valid, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	ecJWK := func(x, y *big.Int) *azkeys.JSONWebKey {
		// Left-pad to the curve coordinate width, exactly as Azure encodes the
		// JWK. (An out-of-range coordinate may exceed coordLen; size to fit.)
		xb := x.Bytes()
		yb := y.Bytes()
		if len(xb) < coordLen {
			pad := make([]byte, coordLen)
			x.FillBytes(pad)
			xb = pad
		}
		if len(yb) < coordLen {
			pad := make([]byte, coordLen)
			y.FillBytes(pad)
			yb = pad
		}
		return &azkeys.JSONWebKey{
			Kty: to.Ptr(azkeys.KeyTypeEC),
			Crv: to.Ptr(curveName),
			X:   xb,
			Y:   yb,
		}
	}

	t.Run("off-curve", func(t *testing.T) {
		// Flip Y by 1: overwhelmingly not on the curve for the same X.
		badY := new(big.Int).Add(valid.Y, big.NewInt(1))
		if _, err := jwkToPublic(ecJWK(valid.X, badY)); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("off-curve point error = %v, want ErrUnsupportedKey", err)
		}
	})

	t.Run("out-of-range coordinate (X == P)", func(t *testing.T) {
		// X == field prime P is out of the valid [0, P) range and not on the
		// curve; IsOnCurve rejects it.
		if _, err := jwkToPublic(ecJWK(new(big.Int).Set(p), valid.Y)); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("X==P error = %v, want ErrUnsupportedKey", err)
		}
	})

	t.Run("point at infinity (0,0)", func(t *testing.T) {
		if _, err := jwkToPublic(ecJWK(big.NewInt(0), big.NewInt(0))); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("infinity (0,0) error = %v, want ErrUnsupportedKey", err)
		}
	})

	t.Run("valid point still accepted", func(t *testing.T) {
		pub, err := jwkToPublic(ecJWK(valid.X, valid.Y))
		if err != nil {
			t.Fatalf("valid on-curve point rejected: %v", err)
		}
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("got %T, want *ecdsa.PublicKey", pub)
		}
		if !ep.Equal(&valid.PublicKey) {
			t.Fatal("reconstructed point does not match the source")
		}
	})
}

// TestSignCallTimeout: a vault round-trip that blocks longer than
// WithCallTimeout must return a context-deadline error promptly rather than
// hanging the signing goroutine past any handler deadline.
func TestSignCallTimeout(t *testing.T) {
	t.Parallel()
	f := newFakeEC(t, elliptic.P256())
	never := make(chan struct{})
	f.signBlock = never // Sign blocks forever (until ctx deadline)

	s, err := NewSigner(f, testKeyName, testKeyVersion, WithCallTimeout(20*time.Millisecond))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
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
			t.Fatal("Sign returned nil despite a vault call that never completes")
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Sign error = %v, want context.DeadlineExceeded", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Sign hung past the configured call timeout")
	}
}
