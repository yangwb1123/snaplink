package rs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// ValidateToken verifies an access token LOCALLY: JWS signature against the
// cached JWKS plus the full claim gates (iss / aud / exp / nbf / iat with
// skew). The AS is not on the request path — revocation before natural expiry
// is NOT visible in this mode; use ValidateTokenWithIntrospect when it must
// be.
//
// Gate order is load-bearing: typ and alg are checked BEFORE any signature
// work (RFC 9068 §4 — `alg: none` and symmetric algs can never reach the
// verifier), and claims are read only from a payload whose signature already
// verified.
func ValidateToken(ctx context.Context, token string, cfg Config) (*Claims, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("%w: Issuer required", ErrConfig)
	}
	if cfg.JWKSCache == nil {
		return nil, fmt.Errorf("%w: JWKSCache required for local validation", ErrConfig)
	}
	hdr, err := parseTokenHeader(token)
	if err != nil {
		return nil, err
	}
	if err := checkAccessTokenTyp(hdr.Typ); err != nil {
		return nil, err
	}
	jwk, err := cfg.JWKSCache.GetJWK(ctx, hdr.Kid)
	if err != nil {
		// Unknown kid collapses into the signature-failure class: whether
		// the key is absent or the signature is wrong must look identical
		// to a token holder.
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	// Verify against ONLY the kid-selected key so a token cannot validate
	// against a different published key than its header names. The alg
	// allowlist gate runs inside VerifyCompactJWS before signature work.
	payload, err := security.VerifyCompactJWS(token, []core.JWK{jwk}, cfg.allowedAlgSet())
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignatureInvalid, err)
	}
	claims, err := parseClaims(payload)
	if err != nil {
		return nil, err
	}
	if err := validateClaims(claims, cfg, time.Now()); err != nil {
		return nil, err
	}
	return claims, nil
}

// tokenHeader is the minimal JOSE header projection needed for routing:
// typ for the misrouted-token gate, kid for JWKS lookup. alg is deliberately
// NOT read here — the allowlist gate lives inside security.VerifyCompactJWS
// so it can never be skipped.
type tokenHeader struct {
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// parseTokenHeader decodes the first JWS segment. All failures are
// ErrTokenMalformed — the token never reached cryptographic evaluation.
func parseTokenHeader(token string) (tokenHeader, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[2] == "" {
		return tokenHeader{}, fmt.Errorf("%w: not a compact JWS", ErrTokenMalformed)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return tokenHeader{}, fmt.Errorf("%w: header decode: %v", ErrTokenMalformed, err)
	}
	var h tokenHeader
	if err := json.Unmarshal(raw, &h); err != nil {
		return tokenHeader{}, fmt.Errorf("%w: header parse: %v", ErrTokenMalformed, err)
	}
	return h, nil
}

// checkAccessTokenTyp enforces RFC 9068 §4: only the at+jwt typ (short or
// full media-type form, case-insensitive per RFC 7515 §4.1.9) may pass. This
// AS always stamps at+jwt on access tokens, so the strict gate costs nothing
// and rejects a misrouted ID token / logout token / SET before signature
// work.
func checkAccessTokenTyp(typ string) error {
	if strings.EqualFold(typ, accessTokenTyp) || strings.EqualFold(typ, accessTokenTypFull) {
		return nil
	}
	return fmt.Errorf("%w: typ %q", ErrTokenTypeMismatch, typ)
}

// validateByMode routes to remote introspection when configured, else local
// signature validation — the shared entry point for DPoP validation and the
// middleware.
func validateByMode(ctx context.Context, token string, cfg Config) (*Claims, error) {
	if cfg.IntrospectURL != "" {
		return ValidateTokenWithIntrospect(ctx, token, cfg)
	}
	return ValidateToken(ctx, token, cfg)
}
