package sso

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/security"
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
// DefaultDPoPNonceTTL is the validity window of an HMAC-signed nonce.
// Long enough that a client's natural retry cadence reuses the same
// nonce; short enough that a stolen nonce expires before it could be
// pre-computed at scale.
const DefaultDPoPNonceTTL = 5 * time.Minute

// HeaderDPoPNonce is the RFC 9449 §8 response header carrying a
// fresh server-issued nonce to a client. Clients read this from a
// `use_dpop_nonce` challenge response and copy it into the `nonce`
// claim of the next DPoP proof JWT.
const HeaderDPoPNonce = "DPoP-Nonce"

// DPoPNonceProvider issues and verifies short-lived nonces used in
// RFC 9449 §8 nonce-bound DPoP proofs. Stateless implementations
// (HMAC-signed) are recommended; stateful (random + store) is also
// valid but pays a lookup per verify.
//
// Issue returns a fresh nonce suitable for emission via the
// `DPoP-Nonce` header. Verify returns nil when the nonce is valid
// and within its freshness window; the returned error is opaque to
// the caller, which only branches on nil / non-nil.
type DPoPNonceProvider interface {
	Issue() (string, error)
	Verify(nonce string) error
}

// HMACNonceProvider is the default stateless DPoPNonceProvider.
// Nonces encode `random[16] || timestamp_unix_seconds[8 big-endian]`
// followed by a `HMAC-SHA256(key, payload)` tag, base64url-encoded
// without padding. Verify recomputes the tag with constant-time
// compare and checks the timestamp window.
//
// Stateless = no store, no replay defense (DPoP's `jti` already
// covers replay). The key is process-local; restart rotates it, which
// invalidates all outstanding nonces but is harmless — clients just
// see a fresh challenge on their next request.
type HMACNonceProvider struct {
	key []byte
	ttl time.Duration
}

// NewHMACNonceProvider builds a provider keyed by a process-local
// 32-byte secret derived from crypto/rand. ttl <= 0 falls back to
// DefaultDPoPNonceTTL.
func NewHMACNonceProvider(ttl time.Duration) (*HMACNonceProvider, error) {
	if ttl <= 0 {
		ttl = DefaultDPoPNonceTTL
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return &HMACNonceProvider{key: key, ttl: ttl}, nil
}

// NewHMACNonceProviderWithKey is the same as NewHMACNonceProvider but
// uses the supplied secret. Use in multi-replica deployments so
// nonces issued by one replica are verifiable by every other; key
// MUST be >= 16 bytes.
func NewHMACNonceProviderWithKey(key []byte, ttl time.Duration) (*HMACNonceProvider, error) {
	if len(key) < 16 {
		return nil, errors.New("dpop nonce: key must be >= 16 bytes")
	}
	if ttl <= 0 {
		ttl = DefaultDPoPNonceTTL
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &HMACNonceProvider{key: dup, ttl: ttl}, nil
}

const (
	dpopNonceRandomLen = 16
	dpopNonceTSLen     = 8
	dpopNonceMACLen    = 32
	dpopNonceTotalLen  = dpopNonceRandomLen + dpopNonceTSLen + dpopNonceMACLen
)

// Issue generates a fresh nonce with the current timestamp
// (nanosecond resolution so sub-second TTLs work for tests; real
// deployments use minute-scale TTLs and don't care about precision).
func (p *HMACNonceProvider) Issue() (string, error) {
	var payload [dpopNonceRandomLen + dpopNonceTSLen]byte
	if _, err := rand.Read(payload[:dpopNonceRandomLen]); err != nil {
		return "", err
	}
	binary.BigEndian.PutUint64(payload[dpopNonceRandomLen:], uint64(time.Now().UnixNano()))
	mac := hmac.New(sha256.New, p.key)
	mac.Write(payload[:])
	tag := mac.Sum(nil)
	out := make([]byte, 0, dpopNonceTotalLen)
	out = append(out, payload[:]...)
	out = append(out, tag...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}

// Verify rejects a nonce that is malformed, tag-invalid, or expired.
// Returned errors are descriptive for logs but the wire response only
// cares whether the call returned nil.
//
// Strict() decoding rejects encodings whose trailing 2 unused bits
// of the final base64 char are non-zero. The standard encoder always
// emits zero there, so issued nonces decode fine; the strictness
// blocks the trivial mutation where a tamperer flips only the unused
// bits of the last char — that would decode to the same payload and
// pass the MAC check, breaking the one-string-one-nonce invariant
// this primitive depends on.
func (p *HMACNonceProvider) Verify(nonce string) error {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(nonce)
	if err != nil {
		return errors.New("dpop nonce: base64 decode")
	}
	if len(raw) != dpopNonceTotalLen {
		return errors.New("dpop nonce: wrong length")
	}
	payload := raw[:dpopNonceRandomLen+dpopNonceTSLen]
	tag := raw[dpopNonceRandomLen+dpopNonceTSLen:]
	mac := hmac.New(sha256.New, p.key)
	mac.Write(payload)
	want := mac.Sum(nil)
	if !hmac.Equal(want, tag) {
		return errors.New("dpop nonce: tag mismatch")
	}
	ts := int64(binary.BigEndian.Uint64(payload[dpopNonceRandomLen:]))
	now := time.Now().UnixNano()
	if ts > now+int64(dpopProofClockSkew) {
		return errors.New("dpop nonce: issued in the future")
	}
	if ts < now-int64(p.ttl) {
		return errors.New("dpop nonce: expired")
	}
	return nil
}

// ErrDPoPNonceRequired is returned by verifyDPoPProof when a nonce
// provider is wired and the proof either lacks a `nonce` claim or
// carries one Verify rejects. Handlers MUST detect this sentinel
// (via errors.Is) and respond with a fresh `DPoP-Nonce` header +
// `use_dpop_nonce` error code at the appropriate HTTP status.
var ErrDPoPNonceRequired = errors.New("dpop: nonce required")

// WithJWKSCacheTTL overrides the Cache-Control max-age advertised
// on /.well-known/jwks.json. Default is [DefaultJWKSCacheMaxAge]
// (5 minutes). Lower this when key rotation must propagate faster;
// raise it when RP traffic strains the JWKS endpoint.
//
// Note: many RP libraries cache the JWKS in-process past the
// max-age signal, so the practical lower bound depends on the RP
// fleet's behavior. Validating-side ETag + 304 keeps the round
// trips cheap, so an aggressive low value (30s-60s) is usually
// safe without flooding origins.
func WithJWKSCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.jwksCacheTTL = ttl }
}

// WithMetadataSigner enables RFC 8414 §2.1 signed_metadata on the
// discovery document. When wired, every /.well-known/openid-configuration
// response carries a `signed_metadata` field whose value is a JWS over
// the same claims as the surrounding document; RPs verify the
// signature against JWKS before trusting any endpoint. Defends
// against a tampering proxy substituting endpoints — a security
// improvement that's a one-line opt-in.
//
// Both the default Ed25519JWTIssuer and oidc.IDTokenIssuer satisfy
// oidc.MetadataSigner — pass either, typically the same instance already
// wired as TokenIssuer / oidc.IDTokenIssuer so JWKS continues to cover
// metadata signing with one key.
func WithMetadataSigner(s oidc.MetadataSigner) Option {
	return func(srv *Server) { srv.metadataSigner = s }
}

// WithDPoPNonceProvider enables RFC 9449 §8 nonce-bound DPoP proofs.
// When set, /token rejects DPoP-bearing requests that lack a fresh
// `nonce` claim with 400 `use_dpop_nonce` + a `DPoP-Nonce` response
// header carrying a server-issued nonce the client must echo on
// retry. /userinfo applies the same gate with 401 instead of 400.
//
// Trade-off: every DPoP request now requires a prior nonce
// challenge, which adds one round-trip the first time. Clients
// SHOULD cache and rotate the nonce per server's freshness window.
// Skip this option to keep the original two-step flow.
func WithDPoPNonceProvider(p DPoPNonceProvider) Option {
	return func(s *Server) { s.dpopNonceProvider = p }
}

// stampDPoPNonce writes a fresh DPoP-Nonce header on the current
// response. Silently no-ops when no provider is wired (which also
// means the caller should never have invoked stamp in the first
// place — defensive).
func (s *Server) stampDPoPNonce(ctx HandlerContext) {
	if s.dpopNonceProvider == nil {
		return
	}
	n, err := s.dpopNonceProvider.Issue()
	if err != nil {
		s.logger.Error("dpop nonce issue failed", "error", err)
		return
	}
	ctx.ResponseWriter().Header().Set(HeaderDPoPNonce, n)
}
