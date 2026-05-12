package sso

import (
	"context"
	"net/http"
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
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`

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

func (s *Server) handleJWKS(ctx HandlerContext) {
	keys := make([]JWK, 0)
	for _, ti := range s.tokenIssuers {
		jp, ok := ti.(JWKSProvider)
		if !ok {
			continue
		}
		ks, err := jp.JWKS(ctx.Request().Context())
		if err != nil {
			s.logger.Error("jwks provider failed", "error", err)
			continue
		}
		keys = append(keys, ks...)
	}
	ctx.JSON(http.StatusOK, map[string]any{"keys": keys})
}
