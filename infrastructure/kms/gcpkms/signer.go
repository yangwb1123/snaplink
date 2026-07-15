//go:build !no_kms_gcpkms

package gcpkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"
	gax "github.com/googleapis/gax-go/v2"
	"github.com/snaplink/sso/shared/core"
)

// ErrUnsupportedKey is returned when the GCP Cloud KMS key version (or the
// requested signing scheme) is not one this signer can bridge into the JWS
// issuers. GCP Cloud KMS asymmetric-sign key versions are EC (P-256 /
// P-384 / Ed25519) or RSA (PKCS#1 v1.5 / PSS over 2048/3072/4096) — the
// SECP256K1 spec and any unrecognized algorithm are rejected here rather
// than silently mis-signed.
var ErrUnsupportedKey = errors.New("gcpkms: unsupported key version algorithm or signing scheme")

// kmsClient is the minimal slice of the GCP Cloud KMS apiv1
// KeyManagementClient this signer needs. Declaring our own interface
// (rather than depending on *kms.KeyManagementClient directly) keeps the
// seam test-injectable: the real *kms.KeyManagementClient from
// cloud.google.com/go/kms/apiv1 satisfies it structurally, and
// signer_test.go injects a local-key fake. Only the two operations
// actually used appear here.
type kmsClient interface {
	AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error)
	GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error)
}

// Signer is a [crypto.Signer] backed by a GCP Cloud KMS asymmetric key
// version. The private key never leaves the KMS HSM — this is the #1
// compliance gate (FIPS 140-2/3, PCI-DSS, SOC 2): the process holds only
// the public half and a key-version resource name, and every Sign is a KMS
// round-trip.
//
// It is wired into the SSO issuers through the cryptosigner bridge, NOT
// directly:
//
//	c, err := kms.NewKeyManagementClient(ctx)
//	sgn, err := gcpkms.New(c, keyVersionName)
//	bridge, pub, err := cryptosigner.ECDSA(sgn)      // P-256 / ES256
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, keyVersionName),
//	)
//
// crypto.Signer contract (the seam every cloud-KMS SDK satisfies):
//
//   - Public() returns the parsed public key (*ecdsa.PublicKey /
//     *rsa.PublicKey / ed25519.PublicKey).
//   - Sign(rand, digest, opts) signs the supplied bytes. For EC/RSA the
//     bytes are the ALREADY-HASHED digest and opts.HashFunc() names the
//     hash (and, for *rsa.PSSOptions, selects PSS). For Ed25519 the bytes
//     are the RAW message and opts.HashFunc()==0 (the stdlib Ed25519
//     contract — Ed25519 hashes internally). The rand reader is ignored —
//     KMS owns randomness inside the HSM.
//   - For ECDSA the returned signature is ASN.1 DER (SEQUENCE{r,s}),
//     exactly as crypto/ecdsa.SignASN1 and KMS itself produce; the
//     cryptosigner bridge converts that DER into the fixed-width R||S form
//     JWS ES256 requires (RFC 7518 §3.4). We deliberately do NOT convert
//     here — returning DER keeps this type a faithful, reusable
//     crypto.Signer (it round-trips against x509/tls/ecdsa.VerifyASN1).
//   - For RSA the returned signature is the raw PKCS#1 v1.5 / PSS bytes,
//     which is already the JWS form.
//   - For Ed25519 the returned signature is the raw 64-byte value, the JWS
//     EdDSA form (RFC 8037).
//
// Unlike AWS KMS (which has no EdDSA key spec), GCP Cloud KMS supports
// Ed25519 (EC_SIGN_ED25519), so this signer drives EdDSA end to end via
// the cryptosigner.Ed25519 bridge + WithEd25519ExternalSigner.
//
// Fail-closed: any KMS error (throttling, permission denied, key disabled)
// is returned from Sign, so token issuance fails rather than emitting an
// unsigned or partially-signed token.
type Signer struct {
	client kmsClient
	// keyName is the FULLY-QUALIFIED CryptoKeyVersion resource name, e.g.
	// projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/V.
	// GCP signs against a specific key VERSION (not the key), and the
	// version's algorithm fixes the scheme — there is no per-request alg
	// selector as in AWS KMS.
	keyName string

	// baseCtx + callTimeout bound the KMS round-trip for the context-less
	// stdlib entrypoints (Sign — crypto.Signer.Sign takes no ctx — and the
	// Public()/internal loadPublic default path). Without this, a slow or
	// unavailable KMS would hang a signing goroutine indefinitely, past any
	// HTTP handler deadline. The explicit PublicKey(ctx) form bypasses these
	// and honors the caller's own ctx.
	baseCtx     context.Context
	callTimeout time.Duration

	// mu guards the public-key cache. A KMS key version's public key is
	// immutable, so one successful fetch suffices for the process lifetime
	// and Public() (called on every wiring + JWKS build) stays cheap.
	//
	// We deliberately do NOT use sync.Once here: Once's only retry path is
	// resetting the Once value, and writing a sync.Once while other
	// goroutines call .Do on it is a data race (the race detector flags it,
	// and a real issuer signs concurrently). The mutex distinguishes three
	// states cleanly: not-yet-fetched, cached-success (fetched==true, never
	// re-fetched, immutable once set), and transient-error (fetched stays
	// false → the NEXT call retries, so a startup KMS outage is not
	// permanently poisoned). The lock is held across the GetPublicKey call,
	// which serializes concurrent first-fetches — acceptable, since they
	// would all fetch the same immutable key.
	mu      sync.Mutex
	cached  *publicKey
	fetched bool
}

// publicKey bundles the parsed key with the KMS key-version algorithm and
// protection level it implies, so Sign can shape the AsymmetricSignRequest
// (Digest oneof vs Data) and validate the requested scheme without a second
// round-trip.
type publicKey struct {
	key crypto.PublicKey
	alg kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	// protectionLevel is the HSM/software attestation from the KMS
	// GetPublicKey response, cached at loadPublic time.
	protectionLevel kmspb.ProtectionLevel
}

// Option configures the Signer.
type Option func(*Signer)

// DefaultCallTimeout bounds a single KMS round-trip made from the
// context-less stdlib entrypoints (Sign / Public). A KMS sign is typically
// 5-50ms, so 10s leaves enormous headroom for a slow-but-alive service
// while still capping a hang well under any sane handler deadline.
const DefaultCallTimeout = 10 * time.Second

// WithContext sets the base context the context-less stdlib entrypoints
// (Sign / Public / internal loadPublic) derive their per-call timeout from.
// Default context.Background(). Cancelling this context cancels in-flight
// KMS calls made via those entrypoints (e.g. on server shutdown).
func WithContext(ctx context.Context) Option {
	return func(s *Signer) {
		if ctx != nil {
			s.baseCtx = ctx
		}
	}
}

// WithCallTimeout sets the per-call deadline applied to each KMS round-trip
// made from the context-less stdlib entrypoints. A non-positive value
// leaves the default (DefaultCallTimeout). PublicKey(ctx) is unaffected —
// it honors the caller's own context.
func WithCallTimeout(d time.Duration) Option {
	return func(s *Signer) {
		if d > 0 {
			s.callTimeout = d
		}
	}
}

// New builds a KMS-backed crypto.Signer for the asymmetric-sign key VERSION
// named by keyName (the fully-qualified
// projects/.../cryptoKeyVersions/<v> resource name — GCP signs against a
// specific version). It does NOT call KMS — the first Public() or Sign()
// performs the lazy GetPublicKey. client is typically a
// *kms.KeyManagementClient from kms.NewKeyManagementClient(ctx); tests
// inject a kmsClient fake.
func New(client kmsClient, keyName string, opts ...Option) (*Signer, error) {
	if client == nil {
		return nil, errors.New("gcpkms: nil KMS client")
	}
	if keyName == "" {
		return nil, errors.New("gcpkms: empty key version name")
	}
	s := &Signer{
		client:      client,
		keyName:     keyName,
		baseCtx:     context.Background(),
		callTimeout: DefaultCallTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// callCtx derives a bounded context for one KMS round-trip from the
// signer's base context + configured call timeout. The caller MUST invoke
// the returned cancel (defer cancel()).
func (s *Signer) callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.baseCtx, s.callTimeout)
}

// loadPublic fetches + parses the public key once, caching success for the
// process lifetime. GCP returns the public key as a PEM-encoded
// SubjectPublicKeyInfo in resp.Pem (RFC 5280); we decode the PEM block and
// x509.ParsePKIXPublicKey turns the DER into a *ecdsa.PublicKey /
// *rsa.PublicKey / ed25519.PublicKey.
//
// The mutex (not sync.Once) lets a transient KMS error be retried on the
// next call without the data race a Once-reset would cause (see the Signer
// field doc). A success is cached immutably; an error returns WITHOUT
// setting fetched, so the next caller re-attempts the round-trip.
func (s *Signer) loadPublic(ctx context.Context) (*publicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetched {
		return s.cached, nil
	}
	out, err := s.client.GetPublicKey(ctx, &kmspb.GetPublicKeyRequest{Name: s.keyName})
	if err != nil {
		// Transient (throttle/outage): NOT cached — retried on next call.
		return nil, fmt.Errorf("gcpkms: get public key: %w", err)
	}
	block, _ := pem.Decode([]byte(out.GetPem()))
	if block == nil {
		return nil, errors.New("gcpkms: public key response had no PEM block")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("gcpkms: parse public key PEM: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
		// supported
	default:
		return nil, fmt.Errorf("gcpkms: %w: public key type %T", ErrUnsupportedKey, pub)
	}
	s.cached = &publicKey{
		key:             pub,
		alg:             out.GetAlgorithm(),
		protectionLevel: out.GetProtectionLevel(),
	}
	s.fetched = true
	return s.cached, nil
}

// Public implements crypto.Signer. It returns the parsed *ecdsa.PublicKey
// / *rsa.PublicKey / ed25519.PublicKey, fetching + caching it from KMS on
// first call. On a KMS or parse error it returns nil (the crypto.Signer
// interface has no error return here); the subsequent Sign — or the
// cryptosigner bridge's wiring-time public-key shape check — surfaces the
// failure. Wire through PublicKey(ctx) when an explicit error is needed at
// startup.
func (s *Signer) Public() crypto.PublicKey {
	ctx, cancel := s.callCtx()
	defer cancel()
	pk, err := s.loadPublic(ctx)
	if err != nil {
		return nil
	}
	return pk.key
}

// PublicKey is the error-returning form of Public, for wiring-time use
// (operators SHOULD call this once at startup so a misconfigured key
// version / IAM permission fails loud before the first token issuance).
func (s *Signer) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	pk, err := s.loadPublic(ctx)
	if err != nil {
		return nil, err
	}
	return pk.key, nil
}

// Sign implements crypto.Signer over a GCP Cloud KMS key version.
//
// For EC/RSA, digest is the ALREADY-computed message digest
// (crypto.Signer's contract) and opts.HashFunc() names the hash (and, when
// opts is *rsa.PSSOptions, selects RSA-PSS) — we send it in the request's
// Digest oneof (Sha256/Sha384/Sha512). For Ed25519, digest is the RAW
// message and opts.HashFunc()==0 (the stdlib Ed25519 contract — Ed25519
// hashes internally) — we send it in the request's Data field. The rand
// reader is ignored — the HSM owns signing randomness.
//
// The scheme is NOT chosen per request (as in AWS KMS): it is fixed by the
// key version's algorithm, which we learned from GetPublicKey. We validate
// that the issuer's requested hash/padding is consistent with that
// algorithm, build the request accordingly, and return the KMS signature
// verbatim: ASN.1 DER for ECDSA (the stdlib crypto.Signer ECDSA contract —
// the cryptosigner bridge converts it to JWS R||S), raw bytes for RSA, raw
// 64-byte for Ed25519.
//
// Cancellation: crypto.Signer.Sign carries no context (the stdlib
// contract), so each KMS round-trip (public-key fetch + sign) is bounded by
// the signer's base context + WithCallTimeout deadline. A slow or
// unavailable KMS therefore returns a context-deadline error promptly
// rather than hanging the signing goroutine.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		// crypto.SignerOpts MAY be nil per the contract, but this signer
		// needs the hash (and PSS selection) it carries; guard before any
		// opts use so a nil never panics on opts.HashFunc() below.
		return nil, fmt.Errorf("gcpkms: %w: nil SignerOpts", ErrUnsupportedKey)
	}

	loadCtx, loadCancel := s.callCtx()
	pk, err := s.loadPublic(loadCtx)
	loadCancel()
	if err != nil {
		return nil, err
	}

	_, pss := opts.(*rsa.PSSOptions)
	req, err := s.signRequest(pk, digest, opts.HashFunc(), pss)
	if err != nil {
		return nil, err
	}

	signCtx, signCancel := s.callCtx()
	defer signCancel()
	out, err := s.client.AsymmetricSign(signCtx, req)
	if err != nil {
		// Fail closed: a KMS sign failure must abort issuance, never yield
		// an unsigned token.
		return nil, fmt.Errorf("gcpkms: sign: %w", err)
	}
	sig := out.GetSignature()
	if len(sig) == 0 {
		return nil, errors.New("gcpkms: empty signature from KMS")
	}
	return sig, nil
}

// signRequest shapes an AsymmetricSignRequest for the key version's
// algorithm. For EC/RSA it places the precomputed digest in the Digest
// oneof matching opts.HashFunc(); for Ed25519 it places the raw message in
// Data (Ed25519 is not prehashed). It rejects a hash/padding that the key
// version's algorithm does not support, so an alg-confused issuer fails
// closed rather than emitting a signature no verifier accepts.
//
// Supported algorithm -> JWS:
//
//	EC_SIGN_P256_SHA256          + SHA-256 -> ES256  (Digest.Sha256)
//	EC_SIGN_P384_SHA384          + SHA-384 -> ES384  (Digest.Sha384)
//	EC_SIGN_ED25519              + unhashed -> EdDSA (Data)
//	RSA_SIGN_PKCS1_{2048,3072,4096}_SHA256 + SHA-256, !pss -> RS256 (Digest.Sha256)
//	RSA_SIGN_PSS_{2048,3072,4096}_SHA256   + SHA-256,  pss -> PS256 (Digest.Sha256)
func (s *Signer) signRequest(pk *publicKey, digest []byte, hash crypto.Hash, pss bool) (*kmspb.AsymmetricSignRequest, error) {
	switch pk.alg {
	case kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256:
		if hash != crypto.SHA256 {
			return nil, fmt.Errorf("gcpkms: %w: P-256 key version with hash %v (want SHA-256 / ES256)", ErrUnsupportedKey, hash)
		}
		return &kmspb.AsymmetricSignRequest{
			Name:   s.keyName,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
		}, nil
	case kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384:
		if hash != crypto.SHA384 {
			return nil, fmt.Errorf("gcpkms: %w: P-384 key version with hash %v (want SHA-384 / ES384)", ErrUnsupportedKey, hash)
		}
		return &kmspb.AsymmetricSignRequest{
			Name:   s.keyName,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha384{Sha384: digest}},
		}, nil
	case kmspb.CryptoKeyVersion_EC_SIGN_ED25519:
		// Ed25519 is NOT prehashed: the stdlib crypto.Signer contract passes
		// the raw message as `digest` with opts.HashFunc()==0. GCP wants the
		// raw message in Data, not the Digest oneof.
		if hash != crypto.Hash(0) {
			return nil, fmt.Errorf("gcpkms: %w: Ed25519 key version with hash %v (Ed25519 signs the unhashed message, want HashFunc()==0)", ErrUnsupportedKey, hash)
		}
		return &kmspb.AsymmetricSignRequest{
			Name: s.keyName,
			Data: digest,
		}, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256:
		if hash != crypto.SHA256 {
			return nil, fmt.Errorf("gcpkms: %w: RSA PKCS1 key version with hash %v (only SHA-256 / RS256 supported)", ErrUnsupportedKey, hash)
		}
		if pss {
			return nil, fmt.Errorf("gcpkms: %w: PSS padding requested but key version is RSA_SIGN_PKCS1 (RS256); use a RSA_SIGN_PSS key for PS256", ErrUnsupportedKey)
		}
		return &kmspb.AsymmetricSignRequest{
			Name:   s.keyName,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
		}, nil
	case kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
		kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256:
		if hash != crypto.SHA256 {
			return nil, fmt.Errorf("gcpkms: %w: RSA PSS key version with hash %v (only SHA-256 / PS256 supported)", ErrUnsupportedKey, hash)
		}
		if !pss {
			return nil, fmt.Errorf("gcpkms: %w: PKCS1 padding requested but key version is RSA_SIGN_PSS (PS256); use a RSA_SIGN_PKCS1 key for RS256", ErrUnsupportedKey)
		}
		return &kmspb.AsymmetricSignRequest{
			Name:   s.keyName,
			Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
		}, nil
	default:
		return nil, fmt.Errorf("gcpkms: %w: key version algorithm %v", ErrUnsupportedKey, pk.alg)
	}
}

// KeyOrigin returns the HSM/software attestation for this signer's key.
// The origin is cached from the KMS GetPublicKey response at loadPublic
// time, derived from the ProtectionLevel field. An unknown kid returns
// OriginUnknown, nil. Delegates entirely to loadPublic's own
// locking/caching (loadPublic acquires s.mu itself) rather than taking
// s.mu here too — Go's sync.Mutex is not reentrant, so holding it across a
// loadPublic call would self-deadlock.
func (s *Signer) KeyOrigin(_ context.Context, kid string) (core.KeyOrigin, error) {
	if kid != "" && kid != s.keyName {
		return core.OriginUnknown, nil
	}
	ctx, cancel := s.callCtx()
	defer cancel()
	pk, err := s.loadPublic(ctx)
	if err != nil {
		return core.OriginUnknown, nil // fail-open: can't attest
	}
	return protectionLevelToOrigin(pk.protectionLevel), nil
}

// protectionLevelToOrigin maps a GCP KMS ProtectionLevel to a KeyOrigin.
func protectionLevelToOrigin(pl kmspb.ProtectionLevel) core.KeyOrigin {
	switch pl {
	case kmspb.ProtectionLevel_HSM:
		return core.OriginHSMGenerated
	case kmspb.ProtectionLevel_SOFTWARE:
		return core.OriginUnattested
	case kmspb.ProtectionLevel_EXTERNAL, kmspb.ProtectionLevel_EXTERNAL_VPC:
		return core.OriginImported
	default:
		return core.OriginUnknown
	}
}

// Interface guard: Signer is a stdlib crypto.Signer, the exact seam the
// cryptosigner bridge (and any other crypto.Signer consumer) accepts.
var _ crypto.Signer = (*Signer)(nil)

// Compile-time guard: *Signer implements core.KeyOriginProvider.
var _ core.KeyOriginProvider = (*Signer)(nil)
