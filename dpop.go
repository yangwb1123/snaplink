package sso

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/snaplink/sso/security"
	"net/http"
	"strings"
	"time"
)

// RFC 9449 — DPoP (Demonstration of Proof-of-Possession).
//
// Lets a client cryptographically bind its access (and refresh)
// tokens to a public key it controls. Each protected-resource
// request then carries a fresh `DPoP` header — a short-lived JWT
// signed by the bound key — proving the caller still possesses
// the private key. A stolen bearer token alone is useless to an
// attacker who doesn't also have the corresponding private key.
//
// Scope of THIS implementation (issuance side only):
//   - Accept the `DPoP: <jwt>` HTTP header on /token requests.
//   - Verify the proof JWT: typ=dpop+jwt, alg=EdDSA, jwk in
//     header, htm=POST, htu=/token, iat in window, jti present.
//   - Compute the JWK thumbprint (RFC 7638) and stamp it into
//     the issued access token's `cnf.jkt` claim (RFC 7800).
//   - Change the response token_type from "Bearer" to "DPoP".
//   - Reuse security.JTIReplayStore (when wired) for jti replay defense.
//
// Resource-side verification (a downstream service confirming a
// DPoP proof matches the bearer's cnf.jkt) is INTENTIONALLY NOT
// shipped in this commit — it changes the /userinfo path enough
// to deserve its own focused change.

// HeaderDPoP is the HTTP request header carrying a DPoP proof JWT.
const HeaderDPoP = "DPoP"

// dpopProofTyp is the JOSE header `typ` value RFC 9449 §4 mandates
// for DPoP proofs. Distinguishes them from access tokens, ID
// tokens, JAR request objects, etc.
const dpopProofTyp = "dpop+jwt"

// dpopProofMaxAge bounds how stale a proof JWT may be. RFC 9449
// §4.3 mandates a "reasonable" iat window; 60 seconds matches
// the conventional value across the FAPI 2.0 + RFC 9449 ecosystem.
const dpopProofMaxAge = 60 * time.Second

// dpopProofClockSkew tolerates clients whose clocks are slightly
// ahead of the AS. Same bound as iat staleness on the other side.
const dpopProofClockSkew = 60 * time.Second

// DPoPBinding is the verified outcome of a DPoP proof check. The
// caller proved possession of the key whose thumbprint is `JKT`;
// every token minted in response MUST carry this binding in its
// `cnf.jkt` claim so a resource server can later challenge the
// caller with another DPoP proof and reject mismatches.
type DPoPBinding struct {
	// JKT is the base64url-encoded SHA-256 JWK thumbprint per
	// RFC 7638 §3 — the canonical-JSON-of-required-members hash
	// every DPoP-aware AS / RS computes the same way.
	JKT string
}

// verifyDPoPProof validates an inbound DPoP proof JWT against the
// request that carried it. Returns the JWK thumbprint on success,
// or an error mapped to invalid_dpop_proof on the wire.
//
// Validation gates per RFC 9449 §4.2:
//   - header typ MUST be "dpop+jwt"
//   - header alg MUST be EdDSA (this server's only signer today)
//   - header jwk MUST be a public JWK whose private counterpart
//     signed the proof
//   - payload htm MUST equal the request method
//   - payload htu MUST equal the request URL (sans query/fragment)
//   - payload iat MUST be within dpopProofMaxAge / clock-skew
//   - payload jti MUST be present (replay-defense token)
func verifyDPoPProof(
	ctx context.Context,
	proof string,
	requestMethod string,
	requestURL string,
	replay security.JTIReplayStore,
	nonceProvider DPoPNonceProvider,
) (*DPoPBinding, error) {
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, errors.New("dpop: malformed proof JWT")
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("dpop: header decode: %w", err)
	}
	var h struct {
		Alg string          `json:"alg"`
		Typ string          `json:"typ"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(hraw, &h); err != nil {
		return nil, fmt.Errorf("dpop: header parse: %w", err)
	}
	if h.Typ != dpopProofTyp {
		return nil, fmt.Errorf("dpop: typ %q not %q", h.Typ, dpopProofTyp)
	}
	if h.Alg != "EdDSA" {
		return nil, fmt.Errorf("dpop: alg %q not supported", h.Alg)
	}
	if len(h.JWK) == 0 {
		return nil, errors.New("dpop: header missing jwk")
	}
	var jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
	}
	if err := json.Unmarshal(h.JWK, &jwk); err != nil {
		return nil, fmt.Errorf("dpop: jwk parse: %w", err)
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		return nil, errors.New("dpop: only OKP/Ed25519 JWKs supported")
	}
	pub, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("dpop: jwk x is not a valid Ed25519 public key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("dpop: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(signingInput), sig) {
		return nil, errors.New("dpop: signature invalid")
	}
	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("dpop: payload decode: %w", err)
	}
	var p struct {
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		JTI   string `json:"jti"`
		Nonce string `json:"nonce,omitempty"`
	}
	if err := json.Unmarshal(praw, &p); err != nil {
		return nil, fmt.Errorf("dpop: payload parse: %w", err)
	}
	if !strings.EqualFold(p.HTM, requestMethod) {
		return nil, fmt.Errorf("dpop: htm %q != request method %q", p.HTM, requestMethod)
	}
	if normalizeDPoPHTU(p.HTU) != normalizeDPoPHTU(requestURL) {
		return nil, fmt.Errorf("dpop: htu %q != request URL %q", p.HTU, requestURL)
	}
	now := time.Now().Unix()
	if p.IAT == 0 {
		return nil, errors.New("dpop: missing iat")
	}
	if p.IAT > now+int64(dpopProofClockSkew.Seconds()) {
		return nil, errors.New("dpop: iat in the future beyond clock skew")
	}
	if p.IAT < now-int64(dpopProofMaxAge.Seconds()) {
		return nil, errors.New("dpop: proof too old")
	}
	if p.JTI == "" {
		return nil, errors.New("dpop: missing jti")
	}
	// RFC 9449 §8 — when a nonce provider is wired, the proof MUST
	// carry a `nonce` claim that Verify accepts. A missing or invalid
	// nonce returns the ErrDPoPNonceRequired sentinel so handlers
	// can stamp a fresh `DPoP-Nonce` header and respond with
	// `use_dpop_nonce`. We do NOT distinguish missing-vs-invalid on
	// the wire — both shapes look identical to the client, who just
	// reads the new nonce header and retries.
	if nonceProvider != nil {
		if p.Nonce == "" {
			return nil, ErrDPoPNonceRequired
		}
		if err := nonceProvider.Verify(p.Nonce); err != nil {
			return nil, ErrDPoPNonceRequired
		}
	}
	// Replay defense — when wired, refuse a second sighting of the
	// same jti within the proof's max age. Without a store the
	// iat-window check is the only protection (acceptable for
	// single-replica deployments; production should wire the
	// store).
	if replay != nil {
		first, err := replay.MarkSeen(ctx, "dpop:"+p.JTI, time.Now().Add(dpopProofMaxAge))
		if err == nil && !first {
			return nil, errors.New("dpop: jti replay detected")
		}
	}

	jkt, err := jwkThumbprintEd25519(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("dpop: thumbprint: %w", err)
	}
	return &DPoPBinding{JKT: jkt}, nil
}

// jwkThumbprintEd25519 computes the RFC 7638 §3.2 thumbprint of an
// Ed25519 public JWK. The canonical JSON form for OKP keys is
// `{"crv":"Ed25519","kty":"OKP","x":"<base64url-no-pad>"}`
// — members sorted lexically with no whitespace. Returns the
// base64url-no-pad encoding of the SHA-256 hash of that string.
func jwkThumbprintEd25519(x string) (string, error) {
	if x == "" {
		return "", errors.New("dpop: empty jwk x")
	}
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + x + `"}`
	h := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(h[:]), nil
}

// normalizeDPoPHTU strips the query + fragment from a URL for htu
// comparison per RFC 9449 §4.3: "The htu MUST be one of the
// acceptable values without query and fragment parts." Trailing
// slash is preserved (the AS endpoint paths are fixed).
func normalizeDPoPHTU(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		return raw[:i]
	}
	return raw
}

// verifyDPoPBearer enforces the resource-side half of RFC 9449.
// Called on bearer-protected endpoints (/userinfo today; future
// protected paths can adopt the same helper):
//
//   - If the access token has no cnf.jkt (legacy bearer), DPoP
//     is irrelevant — return success with the existing claims.
//   - If the access token has cnf.jkt:
//   - the request MUST carry a DPoP proof header
//   - the proof MUST validate against the request method + URL
//   - the proof's JWK thumbprint MUST equal the token's cnf.jkt
//
// Returns an error mapped to invalid_token on the wire (matches the
// existing bearer-token error shape; RFC 9449 §7.1 also allows
// invalid_dpop_proof — collapsing to invalid_token keeps the
// wire surface stable for legacy bearer clients).
func (s *Server) verifyDPoPBearer(ctx HandlerContext, claims *TokenClaims) error {
	if claims == nil {
		return errors.New("dpop: nil claims")
	}
	if claims.ConfirmationJKT == "" {
		// Token isn't DPoP-bound — legacy bearer flow continues.
		return nil
	}
	proof := ctx.Request().Header.Get(HeaderDPoP)
	if proof == "" {
		return errors.New("dpop: token requires DPoP proof header")
	}
	binding, err := verifyDPoPProof(
		ctx.Request().Context(),
		proof,
		ctx.Request().Method,
		requestURLForDPoP(ctx.Request()),
		s.jtiReplayStore,
		s.dpopNonceProvider,
	)
	if err != nil {
		return fmt.Errorf("dpop: proof verification: %w", err)
	}
	if binding.JKT != claims.ConfirmationJKT {
		return errors.New("dpop: proof JKT does not match token cnf.jkt")
	}
	return nil
}

// dpopTokenTypeOr returns "DPoP" when the issued token carries a
// DPoP key binding, else the issuer's default token_type (typically
// "Bearer"). RFC 9449 §4 + RFC 6750 §6.1.1 — sender-constrained
// tokens MUST advertise the DPoP type so a resource server knows
// to expect a DPoP proof on every protected-resource request.
func dpopTokenTypeOr(defaultType, jkt string) string {
	if jkt != "" {
		return TokenTypeNameDPoP
	}
	return defaultType
}

// requestURLForDPoP rebuilds the absolute URL the AS exposes on
// the wire, suitable for htu comparison. Uses the same X-Forwarded-*
// chain as requestBaseURL so deployments behind a trusted edge
// proxy compute the public URL even when the local socket
// terminates HTTP without TLS.
func requestURLForDPoP(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if h := r.Header.Get("X-Forwarded-Proto"); h != "" {
		scheme = h
	}
	host := r.Host
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		host = h
	}
	path := r.URL.Path
	return scheme + "://" + host + path
}
