package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
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

// jwksCacheMaxAge is the freshness window advertised in Cache-Control
// for the JWKS response. 5 minutes balances key-rotation responsiveness
// against avoiding per-request hits from heavily-deployed RPs.
//
// Operators who rotate keys faster MUST lower this AND set
// `kid` rotation expectations on RPs — JWKS caches stick around in
// libraries past this timeout in some cases.
const jwksCacheMaxAge = 5 * time.Minute

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

	body, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		s.logger.Error("jwks marshal failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// ETag = strong validator. RP libraries can send If-None-Match on
	// poll-style fetches to short-circuit when keys haven't rotated.
	// Weak validator semantics ("W/") would be wrong here — the JSON
	// is byte-exact (json.Marshal is deterministic for the same input
	// modulo map iteration; the keys slice ordering is stable across
	// one process lifetime, so any change means real key rotation).
	sum := sha256.Sum256(body)
	etag := `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`

	w := ctx.ResponseWriter()
	r := ctx.Request()
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(jwksCacheMaxAge.Seconds())))
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
