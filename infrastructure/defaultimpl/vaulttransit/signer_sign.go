package vaulttransit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

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

	sig, err := decodeSignResponse(respBody)
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

// decodeSignResponse unmarshals transit/sign's reply and extracts the raw
// signature bytes, stripping the "vault:vN:" wrapper. A decode or wrapper
// failure is fail-closed (never a silent wrong/empty sig).
func decodeSignResponse(respBody []byte) ([]byte, error) {
	var sr signResponse
	if err := json.Unmarshal(respBody, &sr); err != nil {
		return nil, fmt.Errorf("vaulttransit: decode sign response: %w", err)
	}
	return parseVaultSignature(sr.Data.Signature)
}

// buildSignRequest shapes the transit/sign body for the public key type +
// requested hash/padding. It enforces the ECDSA hash<->curve pairing and the
// RSA SHA-256-only / Ed25519-unhashed constraints fail-closed, returning an
// error (and making NO Vault call) on any mismatch. The bool return reports
// whether the key is ECDSA (asn1 marshaling, DER out).
func buildSignRequest(pub crypto.PublicKey, digest []byte, hash crypto.Hash, pss bool, keyVersion int) (signRequest, bool, error) {
	switch pk := pub.(type) {
	case *ecdsa.PublicKey:
		return ecdsaSignRequest(pk, digest, hash, keyVersion)
	case *rsa.PublicKey:
		return rsaSignRequest(digest, hash, pss, keyVersion)
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

// ecdsaSignRequest shapes the transit/sign body for an ECDSA key, enforcing the
// curve<->hash pairing fail-closed and pinning marshaling_algorithm=asn1 (DER
// out). The bool return is always true (ECDSA).
func ecdsaSignRequest(pk *ecdsa.PublicKey, digest []byte, hash crypto.Hash, keyVersion int) (signRequest, bool, error) {
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
}

// rsaSignRequest shapes the transit/sign body for an RSA key (SHA-256 only,
// pss when opts is *rsa.PSSOptions else pkcs1v15), fail-closed on any other
// hash. The bool return is always false (not ECDSA).
func rsaSignRequest(digest []byte, hash crypto.Hash, pss bool, keyVersion int) (signRequest, bool, error) {
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
