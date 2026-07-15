//go:build !no_kms_awskms

package awskms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/snaplink/sso/shared/core"
)

// ErrUnsupportedKey is returned when the KMS key (or the requested signing
// scheme) is not one this signer can bridge into the JWS issuers. AWS KMS
// asymmetric keys are ECC (NIST P-256/384/521) or RSA (2048/3072/4096)
// only — it has no Ed25519/EdDSA signing key spec, so an EdDSA request is
// rejected here rather than silently mis-signed.
var ErrUnsupportedKey = errors.New("awskms: unsupported key spec or signing scheme")

// KMSAPI is the minimal slice of the AWS KMS client this signer needs.
// Declaring our own interface (rather than depending on *kms.Client
// directly) keeps the seam test-injectable: the real *kms.Client from
// aws-sdk-go-v2 satisfies it structurally, and signer_test.go injects a
// local-key fake. Only the operations actually used appear here.
type KMSAPI interface {
	Sign(ctx context.Context, in *kms.SignInput, optFns ...func(*kms.Options)) (*kms.SignOutput, error)
	GetPublicKey(ctx context.Context, in *kms.GetPublicKeyInput, optFns ...func(*kms.Options)) (*kms.GetPublicKeyOutput, error)
	DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error)
}

// Signer is a [crypto.Signer] backed by an AWS KMS asymmetric key. The
// private key never leaves the KMS HSM — this is the #1 compliance gate
// (FIPS 140-2/3, PCI-DSS, SOC 2): the process holds only the public half
// and a key reference, and every Sign is a KMS round-trip.
//
// It is wired into the SSO issuers through the cryptosigner bridge, NOT
// directly:
//
//	c := kms.NewFromConfig(awsCfg)
//	sgn, err := awskms.New(c, keyARN)
//	bridge, pub, err := cryptosigner.ECDSA(sgn)      // P-256 / ES256
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, keyARN),
//	)
//
// crypto.Signer contract (the seam every cloud-KMS SDK satisfies):
//
//   - Public() returns the parsed public key (*ecdsa.PublicKey /
//     *rsa.PublicKey).
//   - Sign(rand, digest, opts) signs the ALREADY-HASHED digest. opts
//     carries the hash (and, for *rsa.PSSOptions, selects PSS). The rand
//     reader is ignored — KMS owns randomness inside the HSM.
//   - For ECDSA the returned signature is ASN.1 DER (SEQUENCE{r,s}),
//     exactly as crypto/ecdsa.SignASN1 and KMS itself produce; the
//     cryptosigner bridge converts that DER into the fixed-width R||S form
//     JWS ES256 requires (RFC 7518 §3.4). We deliberately do NOT convert
//     here — returning DER keeps this type a faithful, reusable
//     crypto.Signer (it round-trips against x509/tls/ecdsa.VerifyASN1).
//   - For RSA the returned signature is the raw PKCS#1 v1.5 / PSS bytes,
//     which is already the JWS form.
//
// Fail-closed: any KMS error (throttling, access denied, key disabled) is
// returned from Sign, so token issuance fails rather than emitting an
// unsigned or partially-signed token.
type Signer struct {
	client KMSAPI
	keyID  string

	// baseCtx + callTimeout bound the KMS round-trip for the context-less
	// stdlib entrypoints (Sign — crypto.Signer.Sign takes no ctx — and the
	// Public()/internal loadPublic default path). Without this, a slow or
	// unavailable KMS would hang a signing goroutine indefinitely, past any
	// HTTP handler deadline. The explicit PublicKey(ctx) form bypasses these
	// and honors the caller's own ctx.
	baseCtx     context.Context
	callTimeout time.Duration

	// mu guards the public-key cache. KMS public keys are immutable for a
	// key id, so one successful fetch suffices for the process lifetime and
	// Public() (called on every wiring + JWKS build) stays cheap.
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

// publicKey bundles the parsed key with the JWS alg its KMS key spec
// implies, and the key origin, so Sign can pick the right
// SigningAlgorithmSpec without a second round-trip.
type publicKey struct {
	key crypto.PublicKey
	// kmsSign* are the KMS SigningAlgorithmSpec values valid for this key
	// spec, indexed by the crypto.Hash the issuer requests.
	keySpec kmstypes.KeySpec
	// origin is the HSM/software attestation from the KMS DescribeKey
	// response, cached at loadPublic time so KeyOrigin is a field read.
	origin core.KeyOrigin
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

// New builds a KMS-backed crypto.Signer for the asymmetric key named by
// keyID (a key ID, ARN, or alias). It does NOT call KMS — the first
// Public() or Sign() performs the lazy GetPublicKey. client is typically
// a *kms.Client from kms.NewFromConfig(cfg); tests inject a KMSAPI fake.
func New(client KMSAPI, keyID string, opts ...Option) (*Signer, error) {
	if client == nil {
		return nil, errors.New("awskms: nil KMS client")
	}
	if keyID == "" {
		return nil, errors.New("awskms: empty key id")
	}
	s := &Signer{
		client:      client,
		keyID:       keyID,
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
// process lifetime. KMS returns the public key as a DER-encoded
// SubjectPublicKeyInfo (RFC 5280), which x509.ParsePKIXPublicKey turns into
// a *ecdsa.PublicKey or *rsa.PublicKey.
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
	out, err := s.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: &s.keyID})
	if err != nil {
		// Transient (throttle/outage): NOT cached — retried on next call.
		return nil, fmt.Errorf("awskms: get public key: %w", err)
	}
	pub, err := x509.ParsePKIXPublicKey(out.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("awskms: parse public key DER: %w", err)
	}
	switch pub.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		// supported
	default:
		return nil, fmt.Errorf("awskms: %w: public key type %T", ErrUnsupportedKey, pub)
	}
	origin, originErr := s.resolveOrigin(ctx)
	if originErr != nil {
		origin = core.OriginUnknown
	}
	s.cached = &publicKey{key: pub, keySpec: out.KeySpec, origin: origin}
	s.fetched = true
	return s.cached, nil
}

// Public implements crypto.Signer. It returns the parsed *ecdsa.PublicKey
// / *rsa.PublicKey, fetching + caching it from KMS on first call. On a KMS
// or parse error it returns nil (the crypto.Signer interface has no error
// return here); the subsequent Sign — or the cryptosigner bridge's
// wiring-time public-key shape check — surfaces the failure. Wire through
// PublicKey(ctx) when an explicit error is needed at startup.
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
// (operators SHOULD call this once at startup so a misconfigured key id /
// IAM permission fails loud before the first token issuance).
func (s *Signer) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	pk, err := s.loadPublic(ctx)
	if err != nil {
		return nil, err
	}
	return pk.key, nil
}

// Sign implements crypto.Signer over a KMS key. digest is the ALREADY
// computed message digest (crypto.Signer's contract); opts.HashFunc()
// names the hash and, when opts is *rsa.PSSOptions, selects RSA-PSS. The
// rand reader is ignored — the HSM owns signing randomness.
//
// We map (key spec, hash, padding) to the KMS SigningAlgorithmSpec, call
// Sign with MessageType=DIGEST and the precomputed digest, and return the
// KMS signature verbatim: ASN.1 DER for ECDSA (the stdlib crypto.Signer
// ECDSA contract — the cryptosigner bridge converts it to JWS R||S), raw
// bytes for RSA. EdDSA/Ed25519 has no KMS key spec and is rejected.
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
		return nil, fmt.Errorf("awskms: %w: nil SignerOpts", ErrUnsupportedKey)
	}
	if opts.HashFunc() == crypto.Hash(0) {
		// HashFunc()==0 means "no pre-hash" — the Ed25519 contract. KMS
		// cannot sign EdDSA, so reject clearly rather than mis-mapping it.
		return nil, fmt.Errorf("awskms: %w: EdDSA / unhashed signing is not supported by AWS KMS (ECDSA + RSA only)", ErrUnsupportedKey)
	}

	loadCtx, loadCancel := s.callCtx()
	pk, err := s.loadPublic(loadCtx)
	loadCancel()
	if err != nil {
		return nil, err
	}

	_, pss := opts.(*rsa.PSSOptions)
	alg, err := signingAlgorithm(pk.keySpec, pk.key, opts.HashFunc(), pss)
	if err != nil {
		return nil, err
	}

	signCtx, signCancel := s.callCtx()
	defer signCancel()
	out, err := s.client.Sign(signCtx, &kms.SignInput{
		KeyId: &s.keyID,
		// MessageType=DIGEST: the JWS issuer already hashed header.payload,
		// so we hand KMS the digest, not the raw message (KMS would
		// otherwise re-hash, producing a signature no verifier accepts).
		Message:          digest,
		MessageType:      kmstypes.MessageTypeDigest,
		SigningAlgorithm: alg,
	})
	if err != nil {
		// Fail closed: a KMS Sign failure must abort issuance, never yield
		// an unsigned token.
		return nil, fmt.Errorf("awskms: sign: %w", err)
	}
	if len(out.Signature) == 0 {
		return nil, errors.New("awskms: empty signature from KMS")
	}
	return out.Signature, nil
}

// signingAlgorithm maps the KMS key spec + the requested hash + padding to
// the matching KMS SigningAlgorithmSpec. Supported:
//
//	ECC_NIST_P256 + SHA-256 -> ECDSA_SHA_256  (ES256)
//	ECC_NIST_P384 + SHA-384 -> ECDSA_SHA_384  (ES384)
//	ECC_NIST_P521 + SHA-512 -> ECDSA_SHA_512  (ES512)
//	RSA_*         + SHA-256, !pss -> RSASSA_PKCS1_V1_5_SHA_256 (RS256)
//	RSA_*         + SHA-256,  pss -> RSASSA_PSS_SHA_256        (PS256)
//
// The hash is taken from the issuer's request (crypto.SignerOpts) rather
// than inferred from the curve, so an ES256 issuer driving a P-256 key and
// a hypothetical mismatch both resolve correctly or error out.
func signingAlgorithm(spec kmstypes.KeySpec, pub crypto.PublicKey, hash crypto.Hash, pss bool) (kmstypes.SigningAlgorithmSpec, error) {
	switch pub.(type) {
	case *ecdsa.PublicKey:
		switch spec {
		case kmstypes.KeySpecEccNistP256:
			if hash == crypto.SHA256 {
				return kmstypes.SigningAlgorithmSpecEcdsaSha256, nil
			}
		case kmstypes.KeySpecEccNistP384:
			if hash == crypto.SHA384 {
				return kmstypes.SigningAlgorithmSpecEcdsaSha384, nil
			}
		case kmstypes.KeySpecEccNistP521:
			if hash == crypto.SHA512 {
				return kmstypes.SigningAlgorithmSpecEcdsaSha512, nil
			}
		}
		return "", fmt.Errorf("awskms: %w: ECDSA key spec %s with hash %v", ErrUnsupportedKey, spec, hash)
	case *rsa.PublicKey:
		// The JWS RSA issuers sign over SHA-256 only (RS256 / PS256). The
		// KMS RSA key spec (2048/3072/4096) is orthogonal to the hash, so
		// any RSA spec is acceptable here.
		if hash != crypto.SHA256 {
			return "", fmt.Errorf("awskms: %w: RSA with hash %v (only SHA-256 / RS256|PS256 supported)", ErrUnsupportedKey, hash)
		}
		if pss {
			return kmstypes.SigningAlgorithmSpecRsassaPssSha256, nil
		}
		return kmstypes.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	default:
		return "", fmt.Errorf("awskms: %w: public key type %T", ErrUnsupportedKey, pub)
	}
}

// KeyOrigin returns the HSM/software attestation for this signer's key.
// The origin is cached from the KMS GetPublicKey response at loadPublic
// time. An unknown kid returns OriginUnknown, nil (the kid is always the
// keyID for this per-key signer). Delegates entirely to loadPublic's own
// locking/caching (loadPublic acquires s.mu itself) rather than taking s.mu
// here too — Go's sync.Mutex is not reentrant, so holding it across a
// loadPublic call would self-deadlock.
func (s *Signer) KeyOrigin(_ context.Context, kid string) (core.KeyOrigin, error) {
	if kid != "" && kid != s.keyID {
		return core.OriginUnknown, nil
	}
	ctx, cancel := s.callCtx()
	defer cancel()
	pk, err := s.loadPublic(ctx)
	if err != nil {
		return core.OriginUnknown, nil // fail-open: can't attest
	}
	return pk.origin, nil
}

// resolveOrigin calls DescribeKey to determine the key's origin. Errors are
// fail-open: the signer returns OriginUnknown when DescribeKey is unavailable.
func (s *Signer) resolveOrigin(ctx context.Context) (core.KeyOrigin, error) {
	out, err := s.client.DescribeKey(ctx, &kms.DescribeKeyInput{KeyId: &s.keyID})
	if err != nil {
		return core.OriginUnknown, fmt.Errorf("awskms: describe key: %w", err)
	}
	if out.KeyMetadata == nil {
		return core.OriginUnknown, nil
	}
	switch out.KeyMetadata.Origin {
	case kmstypes.OriginTypeAwsKms:
		return core.OriginHSMGenerated, nil
	case kmstypes.OriginTypeExternal:
		return core.OriginImported, nil
	case kmstypes.OriginTypeAwsCloudhsm:
		return core.OriginHSMGenerated, nil
	default:
		return core.OriginUnknown, nil
	}
}

// Interface guard: Signer is a stdlib crypto.Signer, the exact seam the
// cryptosigner bridge (and any other crypto.Signer consumer) accepts.
var _ crypto.Signer = (*Signer)(nil)

// Compile-time guard: *Signer implements core.KeyOriginProvider.
var _ core.KeyOriginProvider = (*Signer)(nil)
