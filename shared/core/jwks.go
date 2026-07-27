package core

import (
	"context"
	"time"
)

// PathJWKS is the standard discovery endpoint for the issuer's signing keys.
const PathJWKS = "/.well-known/jwks.json"

// JWK is a single JSON Web Key entry. Fields follow RFC 7517; only the
// subset relevant to the issuers shipped in this SDK is exposed. Issuers can
// emit additional fields by embedding extra json tags in their own structs.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	Kid string `json:"kid,omitempty"`

	// OKP (Ed25519): Crv + X
	// EC (P-256/ES256): Crv + X + Y
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`

	// RSA: N + E
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// Origin is the HSM/software attestation of where this key was
	// generated (see KeyOrigin). Populated only when the TokenIssuer
	// that published this key implements KeyOriginProvider and the
	// origin differs from OriginUnattested. Omitted from JSON when
	// absent (zero value), so JWK consumers that don't understand
	// this field are unaffected.
	Origin KeyOrigin `json:"origin,omitempty,omitzero"`
}

// JWKSProvider is implemented by TokenIssuer types whose tokens are publicly
// verifiable. The Server's JWKS endpoint aggregates JWKs from every
// registered issuer that satisfies this interface; symmetric issuers (HMAC,
// opaque session) simply skip the assertion and are excluded.
type JWKSProvider interface {
	JWKS(ctx context.Context) ([]JWK, error)
}

// DefaultJWKSCacheMaxAge is the freshness window advertised in
// Cache-Control for the JWKS response. 5 minutes balances key-
// rotation responsiveness against avoiding per-request hits from
// heavily-deployed RPs.
//
// Operators who rotate keys faster MUST lower this AND set
// `kid` rotation expectations on RPs — JWKS caches stick around in
// libraries past this timeout in some cases.
const DefaultJWKSCacheMaxAge = 5 * time.Minute

// KeyOrigin classifies where a cryptographic signing key was generated,
// for compliance attestation (FIPS 140-2/3, PCI-DSS, SOC 2). It answers
// the audit question "was this key generated inside an HSM?"
type KeyOrigin int8

const (
	// OriginUnattested is the default — the key was generated in software
	// with no hardware-backed attestation. Every issuer that does not
	// explicitly implement KeyOriginProvider reports this value.
	OriginUnattested KeyOrigin = 0
	// OriginHSMGenerated means the key was generated inside an HSM and
	// the private key material never left the hardware boundary (or, for
	// cloud KMS, was generated within the KMS service's FIPS boundary).
	OriginHSMGenerated KeyOrigin = 1
	// OriginImported means the key was generated outside the HSM (e.g.
	// in software or an on-premises PKI) and then imported into the HSM
	// or KMS service. The private key material was at some point outside
	// the hardware boundary.
	OriginImported KeyOrigin = 2
	// OriginUnknown means the KMS backend or the key's metadata does not
	// support origin attestation. This signals an inability to answer the
	// audit question rather than a verdict.
	OriginUnknown KeyOrigin = 3
)

// String returns a human-readable label for the origin. Used in JWKS
// extension metadata and audit events.
func (o KeyOrigin) String() string {
	switch o {
	case OriginHSMGenerated:
		return "hsm_generated"
	case OriginImported:
		return "imported"
	case OriginUnknown:
		return "unknown"
	default:
		return "unattested"
	}
}

// KeyOriginProvider is an OPTIONAL extension a TokenIssuer MAY implement
// to report the cryptographic origin of each signing key by key ID (kid).
// This is a PER-KEY method so rotation events (two keys, same issuer,
// different origins) produce correct per-kid attestation.
//
// Callers type-assert the TokenIssuer to KeyOriginProvider; a non-nil
// result indicates the issuer can attest origins. Implementations MUST be
// concurrency-safe and SHOULD cache the result (origin never changes for
// a key's lifetime).
type KeyOriginProvider interface {
	// KeyOrigin returns the origin of the key identified by kid. An
	// unknown kid returns OriginUnknown, nil.
	KeyOrigin(ctx context.Context, kid string) (KeyOrigin, error)
}
