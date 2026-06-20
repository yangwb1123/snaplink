package azurekeyvault

import (
	"context"
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
)

// ErrUnsupportedKey is returned when the Key Vault key (or the requested
// signing scheme) is not one this signer can bridge into the JWS issuers.
// Azure Key Vault asymmetric keys are EC (NIST P-256/384/521) or RSA
// (2048/3072/4096); it has NO Ed25519/EdDSA key type, so an EdDSA request is
// rejected here rather than silently mis-signed (the same posture as AWS
// KMS; GCP Cloud KMS and PKCS#11 do support EdDSA). The SECG P-256K
// (secp256k1) curve is not a JWS-standard curve and is likewise rejected.
var ErrUnsupportedKey = errors.New("azurekeyvault: unsupported key type or signing scheme")

// minRSABits is the modulus-size floor enforced on a raw-JWK RSA public key.
// RFC 7518 §3.3 requires RSA keys be >= 2048 bits; this mirrors
// defaultimpl/cryptosigner's minRSABits and the spiffe trust-bundle floor so a
// direct crypto.Signer consumer (not routed through cryptosigner's startup
// check) cannot publish a weak modulus in JWKS.
const minRSABits = 2048

// keyVaultAPI is the minimal slice of the azkeys.Client this signer needs.
// Declaring our own interface (rather than depending on *azkeys.Client
// directly) keeps the seam test-injectable: the real *azkeys.Client from
// github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys satisfies
// it structurally, and signer_test.go injects a local-key fake — so the
// crypto logic is unit-tested with NO real Azure. Only the two operations
// actually used appear here, mirroring awskms.KMSAPI / gcpkms.kmsClient.
type keyVaultAPI interface {
	Sign(ctx context.Context, name string, version string, parameters azkeys.SignParameters, options *azkeys.SignOptions) (azkeys.SignResponse, error)
	GetKey(ctx context.Context, name string, version string, options *azkeys.GetKeyOptions) (azkeys.GetKeyResponse, error)
}

// Signer is a [crypto.Signer] backed by an Azure Key Vault asymmetric key.
// The private key never leaves the vault (HSM-protected keys are
// non-exportable by design) — this is the #1 compliance gate (FIPS 140-2/3,
// PCI-DSS, SOC 2): the process holds only the public half and a
// (key-name, key-version) reference, and every Sign is a vault round-trip
// over the DIGEST.
//
// It is wired into the SSO issuers through the cryptosigner bridge, NOT
// directly:
//
//	cred, err := azidentity.NewDefaultAzureCredential(nil)
//	client, err := azkeys.NewClient(vaultURL, cred, nil)
//	sgn, err := azurekeyvault.NewSigner(client, keyName, keyVersion)
//	bridge, pub, err := cryptosigner.ECDSA(sgn)      // P-256 / ES256
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, keyName),
//	)
//
// crypto.Signer contract (the seam every cloud-KMS SDK satisfies):
//
//   - Public() returns the parsed public key (*ecdsa.PublicKey /
//     *rsa.PublicKey), assembled from the vault's GetKey JWK (EC x/y/crv or
//     RSA n/e).
//   - Sign(rand, digest, opts) signs the ALREADY-HASHED digest. opts carries
//     the hash (and, for *rsa.PSSOptions, selects PSS). The rand reader is
//     ignored — the vault owns randomness inside the HSM.
//   - For ECDSA the returned signature is ASN.1 DER (SEQUENCE{r,s}), exactly
//     as crypto/ecdsa.SignASN1 produces. Azure Key Vault, however, returns
//     ECDSA signatures as RAW fixed-width R||S (the JWS / IEEE-P1363 form,
//     RFC 7518 §3.4) — so this signer converts that R||S into ASN.1 DER
//     here, the INVERSE of what the cryptosigner bridge then does (DER ->
//     R||S). The two conversions cancel, but doing R||S->DER here keeps this
//     type a faithful, reusable crypto.Signer (it round-trips against
//     x509/tls/ecdsa.VerifyASN1) and lets it plug into the SAME bridge as
//     awskms/gcpkms with ZERO bridge changes.
//   - For RSA the returned signature is the raw PKCS#1 v1.5 / PSS bytes,
//     which is already the JWS form (Azure returns RSA signatures raw).
//
// Azure Key Vault has NO Ed25519/EdDSA key type. An EdDSA request
// (crypto.Signer with HashFunc()==0) is rejected with [ErrUnsupportedKey]
// rather than mis-signed.
//
// Fail-closed: any vault error (throttling, forbidden, key disabled) is
// returned from Sign, so token issuance fails rather than emitting an
// unsigned or partially-signed token.
type Signer struct {
	client keyVaultAPI
	// keyName + keyVersion address a specific key VERSION in the vault. An
	// empty keyVersion signs against the key's CURRENT version (Azure treats
	// "" as latest) — operators SHOULD pin an explicit version so a key
	// rotation in the vault does not silently change the signing key (and
	// JWKS kid) out from under running replicas.
	keyName    string
	keyVersion string

	// baseCtx + callTimeout bound the vault round-trip for the context-less
	// stdlib entrypoints (Sign — crypto.Signer.Sign takes no ctx — and the
	// Public()/internal loadPublic default path). Without this, a slow or
	// unavailable vault would hang a signing goroutine indefinitely, past any
	// HTTP handler deadline. The explicit PublicKey(ctx) form bypasses these
	// and honors the caller's own ctx.
	baseCtx     context.Context
	callTimeout time.Duration

	// mu guards the public-key cache. A key version's public key is
	// immutable, so one successful fetch suffices for the process lifetime
	// and Public() (called on every wiring + JWKS build) stays cheap.
	//
	// We deliberately do NOT use sync.Once here: Once's only retry path is
	// resetting the Once value, and writing a sync.Once while other
	// goroutines call .Do on it is a data race (the race detector flags it,
	// and a real issuer signs concurrently). The mutex distinguishes three
	// states cleanly: not-yet-fetched, cached-success (fetched==true, never
	// re-fetched, immutable once set), and transient-error (fetched stays
	// false → the NEXT call retries, so a startup vault outage is not
	// permanently poisoned). The lock is held across the GetKey call, which
	// serializes concurrent first-fetches — acceptable, since they would all
	// fetch the same immutable key. Mirrors awskms/gcpkms exactly.
	mu      sync.Mutex
	cached  crypto.PublicKey
	fetched bool
}

// Option configures the Signer.
type Option func(*Signer)

// DefaultCallTimeout bounds a single vault round-trip made from the
// context-less stdlib entrypoints (Sign / Public). A Key Vault sign is
// typically 5-50ms (network), so 10s leaves enormous headroom for a
// slow-but-alive service while still capping a hang well under any sane
// handler deadline.
const DefaultCallTimeout = 10 * time.Second

// WithContext sets the base context the context-less stdlib entrypoints
// (Sign / Public / internal loadPublic) derive their per-call timeout from.
// Default context.Background(). Cancelling this context cancels in-flight
// vault calls made via those entrypoints (e.g. on server shutdown).
func WithContext(ctx context.Context) Option {
	return func(s *Signer) {
		if ctx != nil {
			s.baseCtx = ctx
		}
	}
}

// WithCallTimeout sets the per-call deadline applied to each vault round-trip
// made from the context-less stdlib entrypoints. A non-positive value leaves
// the default (DefaultCallTimeout). PublicKey(ctx) is unaffected — it honors
// the caller's own context.
func WithCallTimeout(d time.Duration) Option {
	return func(s *Signer) {
		if d > 0 {
			s.callTimeout = d
		}
	}
}

// NewSigner builds a Key Vault-backed crypto.Signer for the asymmetric key
// named by keyName at keyVersion. An empty keyVersion signs against the key's
// current version (Azure treats "" as latest); operators SHOULD pass an
// explicit version to pin the signing key across vault-side rotations. It
// does NOT call Azure — the first Public() or Sign() performs the lazy
// GetKey. client is typically a *azkeys.Client from azkeys.NewClient; tests
// inject a keyVaultAPI fake.
func NewSigner(client keyVaultAPI, keyName, keyVersion string, opts ...Option) (*Signer, error) {
	if client == nil {
		return nil, errors.New("azurekeyvault: nil Key Vault client")
	}
	if keyName == "" {
		return nil, errors.New("azurekeyvault: empty key name")
	}
	s := &Signer{
		client:      client,
		keyName:     keyName,
		keyVersion:  keyVersion,
		baseCtx:     context.Background(),
		callTimeout: DefaultCallTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s, nil
}

// NewSignerFromVaultURL is a convenience constructor that builds the
// underlying azkeys.Client from a vault URL + an azcore.TokenCredential
// (typically from azidentity, e.g. azidentity.NewDefaultAzureCredential) and
// wraps it in a Signer. vaultURL is the vault's DNS name, e.g.
// "https://my-vault.vault.azure.net". clientOpts MAY be nil. The remaining
// opts configure the Signer (context / call timeout) exactly as NewSigner.
func NewSignerFromVaultURL(vaultURL, keyName, keyVersion string, cred azcore.TokenCredential, clientOpts *azkeys.ClientOptions, opts ...Option) (*Signer, error) {
	if vaultURL == "" {
		return nil, errors.New("azurekeyvault: empty vault URL")
	}
	if cred == nil {
		return nil, errors.New("azurekeyvault: nil credential")
	}
	client, err := azkeys.NewClient(vaultURL, cred, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("azurekeyvault: build azkeys client: %w", err)
	}
	return NewSigner(client, keyName, keyVersion, opts...)
}

// callCtx derives a bounded context for one vault round-trip from the
// signer's base context + configured call timeout. The caller MUST invoke
// the returned cancel (defer cancel()).
func (s *Signer) callCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.baseCtx, s.callTimeout)
}

// loadPublic fetches + parses the public key once, caching success for the
// process lifetime. Azure returns the public key as a JSON Web Key (raw
// big-endian coordinate bytes: RSA n/e, EC x/y + curve), which jwkToPublic
// assembles into a *rsa.PublicKey / *ecdsa.PublicKey. (This differs from AWS
// KMS / GCP Cloud KMS, which return a DER/PEM SubjectPublicKeyInfo parsed via
// x509.ParsePKIXPublicKey — Azure exposes the JWK fields directly.)
//
// The mutex (not sync.Once) lets a transient vault error be retried on the
// next call without the data race a Once-reset would cause (see the Signer
// field doc). A success is cached immutably; an error returns WITHOUT setting
// fetched, so the next caller re-attempts the round-trip.
func (s *Signer) loadPublic(ctx context.Context) (crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetched {
		return s.cached, nil
	}
	resp, err := s.client.GetKey(ctx, s.keyName, s.keyVersion, nil)
	if err != nil {
		// Transient (throttle/outage): NOT cached — retried on next call.
		return nil, fmt.Errorf("azurekeyvault: get key: %w", err)
	}
	pub, err := jwkToPublic(resp.Key)
	if err != nil {
		return nil, err
	}
	s.cached = pub
	s.fetched = true
	return s.cached, nil
}

// Public implements crypto.Signer. It returns the parsed *ecdsa.PublicKey /
// *rsa.PublicKey, fetching + caching it from the vault on first call. On a
// vault or parse error it returns nil (the crypto.Signer interface has no
// error return here); the subsequent Sign — or the cryptosigner bridge's
// wiring-time public-key shape check — surfaces the failure. Wire through
// PublicKey(ctx) when an explicit error is needed at startup.
func (s *Signer) Public() crypto.PublicKey {
	ctx, cancel := s.callCtx()
	defer cancel()
	pub, err := s.loadPublic(ctx)
	if err != nil {
		return nil
	}
	return pub
}

// PublicKey is the error-returning form of Public, for wiring-time use
// (operators SHOULD call this once at startup so a misconfigured
// vault/key/RBAC role fails loud before the first token issuance).
func (s *Signer) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return s.loadPublic(ctx)
}

// Sign implements crypto.Signer over an Azure Key Vault key. digest is the
// ALREADY computed message digest (crypto.Signer's contract); opts.HashFunc()
// names the hash and, when opts is *rsa.PSSOptions, selects RSA-PSS. The rand
// reader is ignored — the vault owns signing randomness.
//
// We map (key type, hash, padding) to the Azure SignatureAlgorithm, call Sign
// with the precomputed digest in SignParameters.Value, and return the vault
// signature: ASN.1 DER for ECDSA — converted HERE from Azure's raw R||S (the
// stdlib crypto.Signer ECDSA contract is DER; the cryptosigner bridge then
// converts DER back to JWS R||S) — and raw bytes for RSA. EdDSA/Ed25519 has
// no Key Vault key type and is rejected.
//
// The ECDSA hash<->curve pairing is enforced FAIL-CLOSED (P-256 demands
// SHA-256, P-384 SHA-384, P-521 SHA-512) before any vault call, mirroring the
// pkcs11/awskms/gcpkms peers: a direct crypto.Signer caller must not sign a
// digest under a hash that disagrees with the curve's ES* alg the JWKS
// publishes. (The issuer + cryptosigner bridge always pair them; this guards
// the public crypto.Signer contract.)
//
// Cancellation: crypto.Signer.Sign carries no context (the stdlib contract),
// so each vault round-trip (public-key fetch + sign) is bounded by the
// signer's base context + WithCallTimeout deadline. A slow or unavailable
// vault therefore returns a context-deadline error promptly rather than
// hanging the signing goroutine.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		// crypto.SignerOpts MAY be nil per the contract, but this signer needs
		// the hash (and PSS selection) it carries; guard before any opts use
		// so a nil never panics on opts.HashFunc() below.
		return nil, fmt.Errorf("azurekeyvault: %w: nil SignerOpts", ErrUnsupportedKey)
	}

	loadCtx, loadCancel := s.callCtx()
	pub, err := s.loadPublic(loadCtx)
	loadCancel()
	if err != nil {
		return nil, err
	}

	_, pss := opts.(*rsa.PSSOptions)
	alg, curve, err := signatureAlgorithm(pub, opts.HashFunc(), pss)
	if err != nil {
		return nil, err
	}

	signCtx, signCancel := s.callCtx()
	defer signCancel()
	resp, err := s.client.Sign(signCtx, s.keyName, s.keyVersion, azkeys.SignParameters{
		Algorithm: &alg,
		// Value is the precomputed digest: the JWS issuer already hashed
		// header.payload, so we hand the vault the digest, not the raw message.
		Value: digest,
	}, nil)
	if err != nil {
		// Fail closed: a vault Sign failure must abort issuance, never yield an
		// unsigned token.
		return nil, fmt.Errorf("azurekeyvault: sign: %w", err)
	}
	sig := resp.Result
	if len(sig) == 0 {
		return nil, errors.New("azurekeyvault: empty signature from Key Vault")
	}

	// EC keys: Azure returns RAW R||S (RFC 7518 §3.4); the crypto.Signer ECDSA
	// contract is ASN.1 DER. Convert. (curve is non-nil only for EC.)
	if curve != nil {
		return rawECDSAToDER(sig, curve)
	}
	// RSA: Azure returns the raw PKCS#1 v1.5 / PSS signature — already the
	// crypto.Signer (and JWS) form.
	return sig, nil
}

// Interface guards:
//   - Signer is a stdlib crypto.Signer, the exact seam the cryptosigner
//     bridge (and any other crypto.Signer consumer) accepts.
//   - the real *azkeys.Client structurally satisfies the minimal keyVaultAPI
//     seam, so NewSigner accepts it directly (and the fake in tests is a
//     faithful stand-in, not a divergent shape).
var (
	_ crypto.Signer = (*Signer)(nil)
	_ keyVaultAPI   = (*azkeys.Client)(nil)
)
