// Package vaulttransit provides a dependency-free [crypto.Signer] backed by
// a HashiCorp Vault transit secrets engine key, for cloud-agnostic /
// multi-cloud / Vault-standardized deployments — a different operator
// segment than the AWS/GCP/Azure cloud-KMS peers in kms/. See doc.go for
// the wiring example and the design rationale.
package vaulttransit

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrUnsupportedKey is returned when the Vault transit key (or the requested
// signing scheme) is not one this signer can bridge into the JWS issuers.
// Transit asymmetric-sign keys are ecdsa-p256/p384/p521, rsa-2048/3072/4096,
// or ed25519 — any other transit key type (aes*, chacha20-poly1305, hmac,
// the post-quantum types) is rejected here rather than silently mis-signed.
var ErrUnsupportedKey = errors.New("vaulttransit: unsupported key type or signing scheme")

// minRSABits is the modulus-size floor enforced on a transit RSA key. RFC
// 7518 §3.3 requires RSA keys be >= 2048 bits; this mirrors
// defaultimpl/cryptosigner's minRSABits and the cloud-KMS peers so a direct
// crypto.Signer consumer (not routed through cryptosigner's startup check)
// cannot publish a weak modulus in JWKS. (Transit's smallest RSA key is
// already 2048, but a misconfigured/compromised Vault returning a smaller
// modulus must still be rejected.)
const minRSABits = 2048

// DefaultMount is the conventional transit engine mount path. Operators who
// mounted transit elsewhere (`vault secrets enable -path=...`) override it via
// Config.Mount.
const DefaultMount = "transit"

// DefaultRequestTimeout bounds a single Vault round-trip made from the
// context-less stdlib entrypoint (Sign / Public). A transit sign is a small
// HTTPS request typically a few ms; 10s leaves enormous headroom for a
// slow-but-alive Vault while still capping a hang well under any sane handler
// deadline. Mirrors the cloud-KMS peers' DefaultCallTimeout.
const DefaultRequestTimeout = 10 * time.Second

// vaultTokenPrefix is the wrapper Vault prepends to a transit signature:
// "vault:v<N>:<base64-signature>". The version segment lets a verifier select
// the right key version; we strip the whole prefix and base64-decode the tail.
// (The same wrapping is used for transit ciphertext — "vault:v1:...".)
const vaultTokenPrefix = "vault:"

// Config configures a transit-backed Signer. The zero value is not usable —
// NewSigner validates VaultAddr (https), KeyName, and TokenSource.
type Config struct {
	// VaultAddr is the Vault API base URL, e.g. "https://vault.internal:8200".
	// HTTPS is REQUIRED: the Vault token is a bearer secret on every request,
	// and the signature comes back in clear — an http:// address would expose
	// both. NewSigner rejects any non-https scheme.
	VaultAddr string

	// Mount is the transit engine mount path (default DefaultMount, "transit").
	// An empty value uses the default; a value is path-escaped into the request
	// URL.
	Mount string

	// KeyName is the transit key to sign with (required). It is path-escaped
	// into the request URL.
	KeyName string

	// KeyVersion pins the signing key version. 0 (the default) signs with the
	// key's latest version and reads the latest public key — operators SHOULD
	// pin an explicit version so a transit key rotation does not silently change
	// the signing key (and the JWKS kid) out from under running replicas. A
	// non-zero value is sent to transit as `key_version` on sign and selects the
	// matching entry from the read-key response.
	KeyVersion int

	// Namespace is an optional Vault Enterprise / HCP namespace, sent as the
	// X-Vault-Namespace header. Empty omits the header (Community edition).
	Namespace string

	// TokenSource yields the Vault token for a SINGLE request. It is called
	// PER request (never cached here) so the operator owns the token's
	// lifecycle — renewal, re-auth on a 403, rotation — entirely outside this
	// package. A static token is expressible as a closure that returns it, but
	// the per-call contract means a renewing token source (AppRole, Kubernetes
	// auth, an agent sidecar's sink file) just works. Required. The returned
	// token is a secret: it is set as the X-Vault-Token header and is NEVER
	// logged or placed in an error.
	TokenSource func(context.Context) (string, error)

	// HTTPClient is an optional operator-supplied *http.Client, the seam for
	// custom TLS (a private CA root pool, mTLS client certs), proxies, or
	// dialers. When nil, a default client with a bounded timeout and the
	// stdlib's default (verifying) TLS config is used. A supplied client's own
	// Timeout, if set, governs; the per-request context deadline still applies.
	// NOTE: this package never constructs a client with InsecureSkipVerify — if
	// an operator needs to trust a private CA, they supply a client whose
	// tls.Config has the CA in RootCAs (the correct, verifying way).
	HTTPClient *http.Client

	// RequestTimeout bounds each Vault round-trip from the context-less stdlib
	// entrypoints (Sign / Public). Non-positive uses DefaultRequestTimeout.
	// PublicKey(ctx) bypasses this and honors the caller's own context.
	RequestTimeout time.Duration
}

// Signer is a [crypto.Signer] backed by a Vault transit key. The private key
// NEVER leaves Vault — every Sign is a transit/sign HTTPS round-trip, and the
// process holds only the public half (fetched once from transit/keys) plus a
// (mount, key, version) reference. This is the cloud-agnostic analogue of the
// FIPS/PCI/SOC2 compliance gate the cloud-KMS peers provide.
//
// It is wired into the SSO issuers through the cryptosigner bridge, NOT
// directly — see doc.go. The crypto.Signer contract this satisfies:
//
//   - Public() returns the parsed public key (*ecdsa.PublicKey /
//     *rsa.PublicKey / ed25519.PublicKey), assembled from the PEM
//     SubjectPublicKeyInfo transit returns at GET transit/keys/:name.
//   - Sign(rand, digest, opts) signs via transit/sign. For ECDSA we request
//     marshaling_algorithm=asn1 so transit returns ASN.1 DER (the stdlib
//     crypto.Signer ECDSA contract; the cryptosigner bridge re-splits DER ->
//     JWS R||S). For RSA we request signature_algorithm=pss|pkcs1v15 and get
//     raw bytes (already the JWS form). For Ed25519 the `digest` argument is
//     the RAW message (opts.HashFunc()==0 — Ed25519 hashes internally) and we
//     send it un-prehashed. The rand reader is ignored — Vault owns signing
//     randomness.
//
// Fail-closed: any Vault error, non-2xx, malformed "vault:vN:" wrapper, or
// empty signature is returned from Sign, so token issuance fails rather than
// emitting an unsigned or partially-signed token. The Vault token never
// appears in any error.
type Signer struct {
	cfg        Config
	mount      string
	baseURL    string // normalized VaultAddr, no trailing slash
	client     *http.Client
	reqTimeout time.Duration

	// mu guards the public-key cache. A transit key VERSION's public key is
	// immutable, so one successful fetch suffices for the process lifetime and
	// Public() (called on every wiring + JWKS build) stays cheap.
	//
	// We deliberately do NOT use sync.Once: Once's only retry path is resetting
	// the Once value, and writing a sync.Once while other goroutines call .Do on
	// it is a data race (the race detector flags it, and a real issuer signs
	// concurrently). The mutex distinguishes three states cleanly:
	// not-yet-fetched, cached-success (fetched==true, immutable once set), and
	// transient-error (fetched stays false → the NEXT call retries, so a startup
	// Vault outage is not permanently poisoned). Mirrors the awskms/gcpkms/azure
	// peers exactly (the awskms 6bda097 lesson: mutex+fetched bool, not a
	// non-resettable Once that caches a transient error forever).
	mu      sync.Mutex
	cached  crypto.PublicKey
	fetched bool
}

var _ crypto.Signer = (*Signer)(nil)

// NewSigner validates cfg and builds the transit-backed crypto.Signer. It does
// NOT call Vault — the first Public() or Sign() performs the lazy read-key
// fetch. Returns an error if VaultAddr is not an https URL, KeyName is empty,
// or TokenSource is nil.
func NewSigner(cfg Config) (*Signer, error) {
	if cfg.KeyName == "" {
		return nil, errors.New("vaulttransit: empty key name")
	}
	if cfg.TokenSource == nil {
		return nil, errors.New("vaulttransit: nil TokenSource (operator must supply the Vault token per request)")
	}
	if cfg.KeyVersion < 0 {
		return nil, fmt.Errorf("vaulttransit: negative key version %d", cfg.KeyVersion)
	}
	u, err := url.Parse(strings.TrimSpace(cfg.VaultAddr))
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: invalid VaultAddr: %w", err)
	}
	// HTTPS only: the token is a bearer secret and the signature comes back in
	// clear. Reject http:// (and any non-https scheme) loudly at construction
	// rather than leak on the wire at first sign.
	if u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("vaulttransit: VaultAddr must be an https URL with a host, got %q", cfg.VaultAddr)
	}

	mount := cfg.Mount
	if mount == "" {
		mount = DefaultMount
	}

	client := cfg.HTTPClient
	if client == nil {
		// Default client: bounded timeout, stdlib-default (verifying) TLS. We
		// never set InsecureSkipVerify — an operator needing a private CA
		// supplies their own client with the CA in RootCAs.
		client = &http.Client{Timeout: DefaultRequestTimeout}
	}

	reqTimeout := cfg.RequestTimeout
	if reqTimeout <= 0 {
		reqTimeout = DefaultRequestTimeout
	}

	return &Signer{
		cfg:        cfg,
		mount:      mount,
		baseURL:    strings.TrimRight(u.String(), "/"),
		client:     client,
		reqTimeout: reqTimeout,
	}, nil
}

// Public implements crypto.Signer. It returns the parsed *ecdsa.PublicKey /
// *rsa.PublicKey / ed25519.PublicKey, fetching + caching it from transit on
// first call. On a Vault or parse error it returns nil (the crypto.Signer
// interface has no error return here); the subsequent Sign — or the
// cryptosigner bridge's wiring-time public-key shape check — surfaces the
// failure. Wire through PublicKey(ctx) when an explicit error is needed at
// startup.
func (s *Signer) Public() crypto.PublicKey {
	ctx, cancel := context.WithTimeout(context.Background(), s.reqTimeout)
	defer cancel()
	pub, err := s.loadPublic(ctx)
	if err != nil {
		return nil
	}
	return pub
}

// PublicKey is the error-returning form of Public, for wiring-time use
// (operators SHOULD call this once at startup so a misconfigured
// addr/token/key/policy fails loud before the first token issuance).
func (s *Signer) PublicKey(ctx context.Context) (crypto.PublicKey, error) {
	return s.loadPublic(ctx)
}
