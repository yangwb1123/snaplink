package vaulttransit

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

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
