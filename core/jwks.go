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
