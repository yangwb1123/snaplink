// Package vaulttransit provides a dependency-free [crypto.Signer] backed by
// a HashiCorp Vault transit secrets engine key, for cloud-agnostic /
// multi-cloud / Vault-standardized deployments — a different operator
// segment than the AWS/GCP/Azure cloud-KMS peers in kms/. See doc.go for
// the wiring example and the design rationale.
package vaulttransit

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
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

// loadPublic fetches + parses the public key once, caching success for the
// process lifetime. Transit returns the public key as a PEM SubjectPublicKeyInfo
// at GET transit/keys/:name; x509.ParsePKIXPublicKey turns it into a stdlib
// public key. The mutex (not sync.Once) lets a transient error be retried on
// the next call without a data race; a success is cached immutably; an error
// returns WITHOUT setting fetched, so the next caller re-attempts.
func (s *Signer) loadPublic(ctx context.Context) (crypto.PublicKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetched {
		return s.cached, nil
	}
	pub, err := s.fetchPublic(ctx)
	if err != nil {
		// Transient (outage/throttle/seal): NOT cached — retried on next call.
		return nil, err
	}
	s.cached = pub
	s.fetched = true
	return s.cached, nil
}

// readKeyResponse is the relevant slice of GET /v1/{mount}/keys/{name}. Transit
// returns one entry per key version under `keys`, keyed by the version number
// (as a JSON string), each carrying a `public_key` PEM SubjectPublicKeyInfo.
// `type` is the transit key type (ecdsa-p256, rsa-2048, ed25519, ...) and fixes
// the alg; `latest_version` selects the public key when no version is pinned.
type readKeyResponse struct {
	Data struct {
		Type          string                  `json:"type"`
		LatestVersion int                     `json:"latest_version"`
		Keys          map[string]readKeyEntry `json:"keys"`
	} `json:"data"`
}

type readKeyEntry struct {
	PublicKey string `json:"public_key"`
}

// fetchPublic performs the read-key round-trip and parses the PEM public key,
// validating it against the transit key `type` (so a transit key whose type and
// PEM disagree, or an unsupported type, fails closed). It does not lock — the
// caller (loadPublic) holds s.mu.
func (s *Signer) fetchPublic(ctx context.Context) (crypto.PublicKey, error) {
	path := fmt.Sprintf("/v1/%s/keys/%s", url.PathEscape(s.mount), url.PathEscape(s.cfg.KeyName))
	body, err := s.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	var rk readKeyResponse
	if err := json.Unmarshal(body, &rk); err != nil {
		return nil, fmt.Errorf("vaulttransit: decode read-key response: %w", err)
	}
	if len(rk.Data.Keys) == 0 {
		return nil, errors.New("vaulttransit: read-key response has no key versions")
	}

	// Select the configured version, or latest when unpinned.
	version := s.cfg.KeyVersion
	if version == 0 {
		version = rk.Data.LatestVersion
	}
	if version == 0 {
		return nil, errors.New("vaulttransit: read-key response missing latest_version")
	}
	entry, ok := rk.Data.Keys[fmt.Sprintf("%d", version)]
	if !ok {
		// Do not name the available versions — keep the error free of any
		// version-existence oracle and of secrets.
		return nil, fmt.Errorf("vaulttransit: key version %d not present in transit key", version)
	}
	if entry.PublicKey == "" {
		return nil, fmt.Errorf("vaulttransit: key version %d has no public_key", version)
	}

	block, _ := pem.Decode([]byte(entry.PublicKey))
	if block == nil {
		return nil, errors.New("vaulttransit: public_key is not valid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: parse public_key: %w", err)
	}

	// Cross-check the parsed key against the transit key type. This both
	// rejects unsupported types and guards against a key whose declared type
	// and PEM disagree (a malformed/compromised Vault), which would otherwise
	// publish a mismatched key in JWKS.
	if err := validateKeyType(rk.Data.Type, pub); err != nil {
		return nil, err
	}
	return pub, nil
}

// validateKeyType confirms the parsed public key matches the transit key
// `type` string, applying the same defense-in-depth floors as the cloud-KMS
// peers (RSA modulus >= 2048, EC point on the expected curve). Unsupported
// transit types (aes*, chacha, hmac, the PQ types) are rejected.
func validateKeyType(transitType string, pub crypto.PublicKey) error {
	switch transitType {
	case "ecdsa-p256", "ecdsa-p384", "ecdsa-p521":
		want, err := curveForTransitType(transitType)
		if err != nil {
			return err
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("vaulttransit: %w: transit type %s but public key is %T", ErrUnsupportedKey, transitType, pub)
		}
		if ec.Curve != want {
			return fmt.Errorf("vaulttransit: %w: transit type %s but key curve is %s", ErrUnsupportedKey, transitType, ec.Curve.Params().Name)
		}
		return nil
	case "rsa-2048", "rsa-3072", "rsa-4096":
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("vaulttransit: %w: transit type %s but public key is %T", ErrUnsupportedKey, transitType, pub)
		}
		if rk.N.BitLen() < minRSABits {
			return fmt.Errorf("vaulttransit: %w: RSA modulus is %d bits, want >= %d", ErrUnsupportedKey, rk.N.BitLen(), minRSABits)
		}
		return nil
	case "ed25519":
		if _, ok := pub.(ed25519.PublicKey); !ok {
			return fmt.Errorf("vaulttransit: %w: transit type ed25519 but public key is %T", ErrUnsupportedKey, pub)
		}
		return nil
	default:
		return fmt.Errorf("vaulttransit: %w: transit key type %q", ErrUnsupportedKey, transitType)
	}
}

// curveForTransitType maps the transit ECDSA key type to the stdlib curve.
func curveForTransitType(transitType string) (elliptic.Curve, error) {
	switch transitType {
	case "ecdsa-p256":
		return elliptic.P256(), nil
	case "ecdsa-p384":
		return elliptic.P384(), nil
	case "ecdsa-p521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("vaulttransit: %w: ECDSA transit type %q", ErrUnsupportedKey, transitType)
	}
}

// signRequest is the transit/sign request body. Fields are omitempty so each
// alg sends only what it needs (Ed25519 sends neither prehashed nor
// hash_algorithm nor signature/marshaling algorithm).
type signRequest struct {
	Input               string `json:"input"`                          // base64(digest-or-message)
	KeyVersion          int    `json:"key_version,omitempty"`          // 0 → transit default (latest)
	Prehashed           bool   `json:"prehashed,omitempty"`            // EC/RSA: input is the digest
	HashAlgorithm       string `json:"hash_algorithm,omitempty"`       // sha2-256/384/512
	SignatureAlgorithm  string `json:"signature_algorithm,omitempty"`  // pss | pkcs1v15 (RSA)
	MarshalingAlgorithm string `json:"marshaling_algorithm,omitempty"` // asn1 | jws (ECDSA)
}

// signResponse is the relevant slice of transit/sign's reply.
type signResponse struct {
	Data struct {
		Signature string `json:"signature"` // "vault:vN:<base64>"
	} `json:"data"`
}

// Sign implements crypto.Signer over a Vault transit key.
//
// For ECDSA/RSA, digest is the ALREADY-computed message digest (the JWS issuer
// hashed header.payload); we send it with prehashed=true and the matching
// hash_algorithm. For ECDSA we set marshaling_algorithm=asn1 so transit returns
// ASN.1 DER — the stdlib crypto.Signer ECDSA contract — which the cryptosigner
// bridge then re-splits into the fixed-width JWS R||S. For RSA we set
// signature_algorithm=pss when opts is *rsa.PSSOptions, else pkcs1v15, and
// return the raw signature (already the JWS form). For Ed25519, digest is the
// RAW message (opts.HashFunc()==0 — Ed25519 hashes internally); we send it
// un-prehashed with no hash_algorithm and return the raw 64-byte signature.
//
// The ECDSA hash<->curve pairing is enforced FAIL-CLOSED (P-256 demands
// SHA-256, P-384 SHA-384, P-521 SHA-512) BEFORE any Vault call, mirroring the
// pkcs11/awskms/gcpkms/azure peers: a direct crypto.Signer caller must not sign
// a digest under a hash that disagrees with the curve's ES* alg the JWKS
// publishes. (The issuer + bridge always pair them; this guards the public
// crypto.Signer contract.)
//
// Cancellation: crypto.Signer.Sign carries no context (the stdlib contract), so
// each Vault round-trip (public-key fetch + sign) is bounded by RequestTimeout.
// A slow or unavailable Vault returns a deadline error promptly rather than
// hanging the signing goroutine. The rand reader is ignored — Vault owns
// signing randomness.
func (s *Signer) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		// crypto.SignerOpts MAY be nil per the contract, but this signer needs
		// the hash (and PSS selection) it carries; guard before any opts use so
		// a nil never panics on opts.HashFunc() below.
		return nil, fmt.Errorf("vaulttransit: %w: nil SignerOpts", ErrUnsupportedKey)
	}

	loadCtx, loadCancel := context.WithTimeout(context.Background(), s.reqTimeout)
	pub, err := s.loadPublic(loadCtx)
	loadCancel()
	if err != nil {
		return nil, err
	}

	_, pss := opts.(*rsa.PSSOptions)
	req, isECDSA, err := buildSignRequest(pub, digest, opts.HashFunc(), pss, s.cfg.KeyVersion)
	if err != nil {
		// hash<->curve mismatch / unsupported scheme: fail closed BEFORE any
		// Vault round-trip (no HTTP call is made).
		return nil, err
	}

	signCtx, signCancel := context.WithTimeout(context.Background(), s.reqTimeout)
	defer signCancel()
	path := fmt.Sprintf("/v1/%s/sign/%s", url.PathEscape(s.mount), url.PathEscape(s.cfg.KeyName))
	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: marshal sign request: %w", err)
	}
	respBody, err := s.doRequest(signCtx, http.MethodPost, path, reqBody)
	if err != nil {
		// Fail closed: a transit sign failure must abort issuance, never yield
		// an unsigned token.
		return nil, err
	}

	var sr signResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, fmt.Errorf("vaulttransit: decode sign response: %w", err)
	}
	sig, err := parseVaultSignature(sr.Data.Signature)
	if err != nil {
		return nil, err
	}
	// ECDSA with marshaling_algorithm=asn1 yields DER (SEQUENCE{r,s}) — exactly
	// the stdlib crypto.Signer ECDSA contract the bridge expects. RSA/Ed25519
	// return the raw signature, already the JWS form. We do NO conversion here:
	// returning what transit gives keeps this a faithful crypto.Signer.
	_ = isECDSA
	return sig, nil
}

// buildSignRequest shapes the transit/sign body for the public key type +
// requested hash/padding. It enforces the ECDSA hash<->curve pairing and the
// RSA SHA-256-only / Ed25519-unhashed constraints fail-closed, returning an
// error (and making NO Vault call) on any mismatch. The bool return reports
// whether the key is ECDSA (asn1 marshaling, DER out).
func buildSignRequest(pub crypto.PublicKey, digest []byte, hash crypto.Hash, pss bool, keyVersion int) (signRequest, bool, error) {
	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		// The curve fixes the JWS hash. Reject any other pairing fail-closed —
		// matching the pkcs11/awskms/gcpkms/azure peers — so a direct
		// crypto.Signer caller cannot sign a digest under a hash that disagrees
		// with the ES* alg the JWKS publishes. The !=want check also subsumes
		// the HashFunc()==0 (Ed25519-shaped) rejection for EC keys.
		hashAlg, err := ecdsaHashAlg(pk.Curve, hash)
		if err != nil {
			return signRequest{}, false, err
		}
		return signRequest{
			Input:      base64.StdEncoding.EncodeToString(digest),
			KeyVersion: keyVersion,
			Prehashed:  true,
			// asn1 → transit returns ASN.1 DER (the crypto.Signer ECDSA
			// contract; the cryptosigner bridge re-splits DER -> JWS R||S). jws
			// would return raw R||S, but then this type would NOT be a faithful
			// crypto.Signer (it would not round-trip ecdsa.VerifyASN1).
			MarshalingAlgorithm: "asn1",
			HashAlgorithm:       hashAlg,
		}, true, nil
	case *rsa.PublicKey:
		// The JWS RSA issuers sign over SHA-256 only (RS256 / PS256). Key size
		// (2048/3072/4096) is orthogonal to the hash.
		if hash != crypto.SHA256 {
			return signRequest{}, false, fmt.Errorf("vaulttransit: %w: RSA with hash %v (only SHA-256 / RS256|PS256 supported)", ErrUnsupportedKey, hash)
		}
		sigAlg := "pkcs1v15"
		if pss {
			sigAlg = "pss"
		}
		return signRequest{
			Input:              base64.StdEncoding.EncodeToString(digest),
			KeyVersion:         keyVersion,
			Prehashed:          true,
			HashAlgorithm:      "sha2-256",
			SignatureAlgorithm: sigAlg,
		}, false, nil
	case ed25519.PublicKey:
		// Ed25519 is NOT prehashed: the stdlib crypto.Signer contract passes the
		// RAW message as `digest` with opts.HashFunc()==0. Transit signs the raw
		// input (no prehashed, no hash_algorithm) and hashes internally.
		if hash != crypto.Hash(0) {
			return signRequest{}, false, fmt.Errorf("vaulttransit: %w: Ed25519 signs the unhashed message (want HashFunc()==0, got %v)", ErrUnsupportedKey, hash)
		}
		return signRequest{
			Input:      base64.StdEncoding.EncodeToString(digest),
			KeyVersion: keyVersion,
			// prehashed omitted (false), hash_algorithm omitted, signature/
			// marshaling algorithm omitted — Ed25519 needs none of them.
		}, false, nil
	default:
		return signRequest{}, false, fmt.Errorf("vaulttransit: %w: public key type %T", ErrUnsupportedKey, pub)
	}
}

// ecdsaHashAlg returns the transit hash_algorithm string for an ECDSA curve,
// enforcing the curve<->hash pairing fail-closed.
func ecdsaHashAlg(curve elliptic.Curve, hash crypto.Hash) (string, error) {
	switch curve {
	case elliptic.P256():
		if hash != crypto.SHA256 {
			return "", fmt.Errorf("vaulttransit: %w: P-256 key requires SHA-256 (ES256), got %v", ErrUnsupportedKey, hash)
		}
		return "sha2-256", nil
	case elliptic.P384():
		if hash != crypto.SHA384 {
			return "", fmt.Errorf("vaulttransit: %w: P-384 key requires SHA-384 (ES384), got %v", ErrUnsupportedKey, hash)
		}
		return "sha2-384", nil
	case elliptic.P521():
		if hash != crypto.SHA512 {
			return "", fmt.Errorf("vaulttransit: %w: P-521 key requires SHA-512 (ES512), got %v", ErrUnsupportedKey, hash)
		}
		return "sha2-512", nil
	default:
		return "", fmt.Errorf("vaulttransit: %w: unsupported ECDSA curve %s", ErrUnsupportedKey, curve.Params().Name)
	}
}

// parseVaultSignature strips the "vault:vN:" wrapper and base64-decodes the
// signature tail. A missing/short prefix, a non-numeric version, or an empty/
// undecodable tail is a fail-closed error (never a silent wrong/empty sig).
func parseVaultSignature(wrapped string) ([]byte, error) {
	if !strings.HasPrefix(wrapped, vaultTokenPrefix) {
		return nil, errors.New("vaulttransit: signature missing vault: prefix")
	}
	// "vault:" + "vN" + ":" + "<b64>". Split into at most 3 parts on ':' so a
	// base64 tail containing no ':' stays intact (standard base64 has none).
	parts := strings.SplitN(wrapped, ":", 3)
	if len(parts) != 3 {
		return nil, errors.New("vaulttransit: malformed vault: signature wrapper")
	}
	ver := parts[1]
	if len(ver) < 2 || ver[0] != 'v' {
		return nil, errors.New("vaulttransit: malformed vault: signature version segment")
	}
	// The version digits must be numeric (defense against a malformed wrapper).
	for _, c := range ver[1:] {
		if c < '0' || c > '9' {
			return nil, errors.New("vaulttransit: non-numeric vault: signature version")
		}
	}
	b64 := parts[2]
	if b64 == "" {
		return nil, errors.New("vaulttransit: empty signature from Vault")
	}
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: decode signature: %w", err)
	}
	if len(sig) == 0 {
		return nil, errors.New("vaulttransit: empty signature from Vault")
	}
	return sig, nil
}

// vaultError is the relevant slice of a Vault error response body
// ({"errors":["..."]}). Vault's own error strings are operational (policy
// denied, key not found) and carry no secret, so surfacing the FIRST one aids
// diagnosis — but we never echo the request body or the token.
type vaultError struct {
	Errors []string `json:"errors"`
}

// doRequest performs one bounded Vault round-trip, setting the per-request
// X-Vault-Token (from TokenSource) and optional X-Vault-Namespace, and reads +
// closes the body. A non-2xx status maps to a fail-closed error carrying the
// status and Vault's own error message(s) — but NEVER the token (it is only
// ever a request header, never read back or logged). reqBody nil sends no body.
func (s *Signer) doRequest(ctx context.Context, method, path string, reqBody []byte) ([]byte, error) {
	// Per-request token: the operator owns lifecycle/renewal. Called every
	// request so a renewing source (AppRole, k8s auth, agent sink) is honored.
	token, err := s.cfg.TokenSource(ctx)
	if err != nil {
		// Do not wrap-print the token-source internals beyond its own error;
		// the error must not carry the token itself (it does not — TokenSource
		// returns (token, err) separately, and we discard token on err).
		return nil, fmt.Errorf("vaulttransit: obtain Vault token: %w", err)
	}
	if token == "" {
		return nil, errors.New("vaulttransit: TokenSource returned an empty token")
	}

	var bodyReader io.Reader
	if reqBody != nil {
		bodyReader = bytes.NewReader(reqBody)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, s.baseURL+path, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: build request: %w", err)
	}
	httpReq.Header.Set("X-Vault-Token", token)
	if s.cfg.Namespace != "" {
		httpReq.Header.Set("X-Vault-Namespace", s.cfg.Namespace)
	}
	if reqBody != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.client.Do(httpReq)
	if err != nil {
		// Transport error (DNS, TLS verify failure, connection refused,
		// deadline). The url.Error here wraps the request URL, NOT the headers,
		// so the token is not exposed.
		return nil, fmt.Errorf("vaulttransit: %s %s: %w", method, vaultTransitOpName(path), err)
	}
	defer resp.Body.Close()
	// Bound the body read so a misbehaving/hostile endpoint can't stream
	// unbounded data into the signing goroutine. Transit replies are small
	// (a public-key PEM or a base64 signature); 1 MiB is generous headroom.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("vaulttransit: read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Fail closed. Surface Vault's own error message(s) (operational, not
		// secret) but NEVER the token or the request body.
		msg := vaultErrorMessage(body)
		if msg != "" {
			return nil, fmt.Errorf("vaulttransit: %s %s: status %d: %s", method, vaultTransitOpName(path), resp.StatusCode, msg)
		}
		return nil, fmt.Errorf("vaulttransit: %s %s: status %d", method, vaultTransitOpName(path), resp.StatusCode)
	}
	return body, nil
}

// vaultErrorMessage extracts the first error string from a Vault error body, or
// "" if the body is not the expected shape. Used only for diagnostics.
func vaultErrorMessage(body []byte) string {
	var ve vaultError
	if err := json.Unmarshal(body, &ve); err != nil {
		return ""
	}
	if len(ve.Errors) == 0 {
		return ""
	}
	return ve.Errors[0]
}

// vaultTransitOpName reduces a request path to a coarse operation name
// ("sign"/"read-key"/"transit") for error messages, so the key NAME (the last
// path segment) is not echoed into logs/errors. The key name is not secret, but
// keeping it out of errors avoids leaking which key a failing replica targets.
func vaultTransitOpName(path string) string {
	switch {
	case strings.Contains(path, "/sign/"):
		return "transit sign"
	case strings.Contains(path, "/keys/"):
		return "transit read-key"
	default:
		return "transit"
	}
}
