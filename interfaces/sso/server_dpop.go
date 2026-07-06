package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/security"
)

func verifyDPoPProof(
	ctx context.Context,
	proof string,
	requestMethod string,
	requestURL string,
	replay security.JTIReplayStore,
	replayFailClosed bool,
	nonceProvider DPoPNonceProvider,
	maxAge time.Duration,
	clockSkew time.Duration,
	accessToken string,
) (*DPoPBinding, error) {
	// Gate ORDER is load-bearing (DENY ladder): header+jwk parse → JWS
	// verify → payload bind (htm/htu/iat) → nonce → replay → thumbprint.
	// Each step short-circuits with its own DPoP-shaped error.
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		return nil, errors.New("dpop: malformed proof JWT")
	}
	proofJWK, err := parseDPoPProofHeader(parts[0])
	if err != nil {
		return nil, err
	}
	if _, err := security.VerifyCompactJWS(proof, []JWK{proofJWK}, security.AsymmetricJWSAlgs()); err != nil {
		return nil, fmt.Errorf("dpop: %w", err)
	}
	p, err := parseAndCheckDPoPPayload(parts[1], requestMethod, requestURL, maxAge, clockSkew)
	if err != nil {
		return nil, err
	}
	if err := enforceDPoPNonce(nonceProvider, p.Nonce); err != nil {
		return nil, err
	}
	if err := enforceDPoPReplay(ctx, replay, replayFailClosed, p.JTI, p.IAT, maxAge); err != nil {
		return nil, err
	}
	if err := checkDPoPAth(p.Ath, accessToken); err != nil {
		return nil, err
	}

	jkt, err := jwkThumbprintRFC7638(proofJWK)
	if err != nil {
		return nil, fmt.Errorf("dpop: thumbprint: %w", err)
	}
	return &DPoPBinding{JKT: jkt}, nil
}

// parseDPoPProofHeader decodes the first JWS segment, enforces the DPoP
// proof `typ`, and parses the embedded ephemeral `jwk` into a core.JWK.
//
// The DPoP proof carries its OWN ephemeral public key in the header `jwk`
// (unlike JAR / private_key_jwt, which verify against the client's
// REGISTERED JWKS). Parsing it into a core.JWK lets the SAME
// alg-confusion-safe verifier check it: alg gated against the asymmetric
// allowlist BEFORE verify, kty/crv↔alg consistency (an EC jwk with
// alg=RS256, or alg=none/HS*, fails closed), EC on-curve, RSA>=2048. The
// proof JWK has no kid; passed as the sole key, VerifyCompactJWS selects
// it for the empty-kid case.
func parseDPoPProofHeader(headerSegment string) (JWK, error) {
	hraw, err := base64.RawURLEncoding.DecodeString(headerSegment)
	if err != nil {
		return JWK{}, fmt.Errorf("dpop: header decode: %w", err)
	}
	var h struct {
		Typ string          `json:"typ"`
		JWK json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(hraw, &h); err != nil {
		return JWK{}, fmt.Errorf("dpop: header parse: %w", err)
	}
	if h.Typ != dpopProofTyp {
		return JWK{}, fmt.Errorf("dpop: typ %q not %q", h.Typ, dpopProofTyp)
	}
	if len(h.JWK) == 0 {
		return JWK{}, errors.New("dpop: header missing jwk")
	}
	return parseDPoPHeaderJWK(h.JWK)
}

// dpopProofPayload mirrors the RFC 9449 §4.2 proof claims this verifier
// binds against the live request.
type dpopProofPayload struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	IAT   int64  `json:"iat"`
	JTI   string `json:"jti"`
	Nonce string `json:"nonce,omitempty"`
	// Ath = base64url(SHA-256(access_token)) — RFC 9449 §4.3. REQUIRED when the
	// proof is presented at a protected resource alongside an access token, and
	// verified there (§7.1) so a proof is bound to the SPECIFIC token, not just
	// the key. Absent/unused on the /token issuance path (no token exists yet).
	Ath string `json:"ath,omitempty"`
}

// parseAndCheckDPoPPayload decodes the second JWS segment and binds the
// proof to the live request: htm == method, normalized htu == URL, iat
// present and within [now-maxAge, now+clockSkew], and a non-empty jti.
// Each failure keeps its original DPoP-shaped error verbatim.
func parseAndCheckDPoPPayload(
	payloadSegment string,
	requestMethod string,
	requestURL string,
	maxAge time.Duration,
	clockSkew time.Duration,
) (dpopProofPayload, error) {
	praw, err := base64.RawURLEncoding.DecodeString(payloadSegment)
	if err != nil {
		return dpopProofPayload{}, fmt.Errorf("dpop: payload decode: %w", err)
	}
	var p dpopProofPayload
	if err := json.Unmarshal(praw, &p); err != nil {
		return dpopProofPayload{}, fmt.Errorf("dpop: payload parse: %w", err)
	}
	if !strings.EqualFold(p.HTM, requestMethod) {
		return dpopProofPayload{}, fmt.Errorf("dpop: htm %q != request method %q", p.HTM, requestMethod)
	}
	if normalizeDPoPHTU(p.HTU) != normalizeDPoPHTU(requestURL) {
		return dpopProofPayload{}, fmt.Errorf("dpop: htu %q != request URL %q", p.HTU, requestURL)
	}
	now := time.Now().Unix()
	if p.IAT == 0 {
		return dpopProofPayload{}, errors.New("dpop: missing iat")
	}
	if p.IAT > now+int64(clockSkew.Seconds()) {
		return dpopProofPayload{}, errors.New("dpop: iat in the future beyond clock skew")
	}
	if p.IAT < now-int64(maxAge.Seconds()) {
		return dpopProofPayload{}, errors.New("dpop: proof too old")
	}
	if p.JTI == "" {
		return dpopProofPayload{}, errors.New("dpop: missing jti")
	}
	return p, nil
}

// enforceDPoPNonce applies RFC 9449 §8 — when a nonce provider is wired,
// the proof MUST carry a `nonce` claim that Verify accepts. A missing or
// invalid nonce returns the ErrDPoPNonceRequired sentinel so handlers can
// stamp a fresh `DPoP-Nonce` header and respond with `use_dpop_nonce`. We
// do NOT distinguish missing-vs-invalid on the wire — both shapes look
// identical to the client, who just reads the new nonce header and retries.
func enforceDPoPNonce(nonceProvider DPoPNonceProvider, nonce string) error {
	if nonceProvider == nil {
		return nil
	}
	if nonce == "" {
		return ErrDPoPNonceRequired
	}
	if err := nonceProvider.Verify(nonce); err != nil {
		return ErrDPoPNonceRequired
	}
	return nil
}

// enforceDPoPReplay applies replay defense — when wired, refuse a second
// sighting of the same jti within the proof's FULL acceptance horizon. Without a
// store the iat-window check is the only protection (acceptable for
// single-replica deployments; production should wire the store).
//
// The jti is remembered until iat+maxAge — the LATEST time the iat-window still
// accepts this proof (parseAndCheckDPoPPayload rejects only iat < now-maxAge).
// Anchoring to now+maxAge instead would expire the jti up to clockSkew seconds
// before the proof itself stops being accepted (when first sighted early, as a
// clock-skewed future iat allows), leaving a replay gap. Mirrors the JAR path,
// which anchors the replay TTL to the JWT's own time bound.
func enforceDPoPReplay(
	ctx context.Context,
	replay security.JTIReplayStore,
	replayFailClosed bool,
	jti string,
	iat int64,
	maxAge time.Duration,
) error {
	if replay == nil {
		return nil
	}
	first, err := replay.MarkSeen(ctx, "dpop:"+jti, time.Unix(iat, 0).Add(maxAge))
	switch {
	case err != nil:
		// Store error — default fail-OPEN (continue). Fail-CLOSED
		// (opt-in) rejects with the detected-replay error so the
		// wire shape is identical (no store-health oracle).
		if replayFailClosed {
			return errors.New("dpop: jti replay detected")
		}
	case !first:
		return errors.New("dpop: jti replay detected")
	}
	return nil
}

// parseDPoPHeaderJWK decodes the DPoP proof header's `jwk` member into a
// core.JWK, carrying ONLY the public members each key type needs (so a
// proof can never smuggle a private key component). The result is fed to
// security.VerifyCompactJWS (which enforces kty/crv↔alg consistency, EC
// on-curve, RSA>=2048) AND to the RFC 7638 thumbprint. Supported types:
// OKP/Ed25519, EC (P-256/384/521), RSA. A type-specific required-member
// presence check here gives a clear DPoP-shaped error before the verifier
// runs.
func parseDPoPHeaderJWK(raw json.RawMessage) (JWK, error) {
	var j struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		X   string `json:"x"`
		Y   string `json:"y"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return JWK{}, fmt.Errorf("dpop: jwk parse: %w", err)
	}
	switch j.Kty {
	case "OKP":
		if j.Crv == "" || j.X == "" {
			return JWK{}, errors.New("dpop: OKP jwk missing crv/x")
		}
		return JWK{Kty: "OKP", Crv: j.Crv, X: j.X}, nil
	case "EC":
		if j.Crv == "" || j.X == "" || j.Y == "" {
			return JWK{}, errors.New("dpop: EC jwk missing crv/x/y")
		}
		return JWK{Kty: "EC", Crv: j.Crv, X: j.X, Y: j.Y}, nil
	case "RSA":
		if j.N == "" || j.E == "" {
			return JWK{}, errors.New("dpop: RSA jwk missing n/e")
		}
		return JWK{Kty: "RSA", N: j.N, E: j.E}, nil
	default:
		return JWK{}, fmt.Errorf("dpop: unsupported jwk kty %q", j.Kty)
	}
}

// jwkThumbprintRFC7638 computes the RFC 7638 §3 JWK thumbprint: the
// base64url-no-pad SHA-256 of the canonical JSON of the REQUIRED members
// for the key type, lexically ordered with no whitespace. The required
// members differ per kty (§3.2), and computing the wrong member set yields
// a DIFFERENT thumbprint — for DPoP a wrong thumbprint is a binding bypass
// (a stolen token replayed with a different key would validate), so each
// kty MUST use its own canonical form:
//
//	OKP: {"crv":...,"kty":"OKP","x":...}
//	EC:  {"crv":...,"kty":"EC","x":...,"y":...}
//	RSA: {"e":...,"kty":"RSA","n":...}
//
// The members are emitted in the exact lexical order RFC 7638 mandates;
// the string is assembled directly (not via json.Marshal) so the member
// ORDER and the absence of whitespace are guaranteed regardless of struct
// field order or encoder behavior. Values are already base64url strings
// from the (verified) JWK, so they are interpolated as-is.
func jwkThumbprintRFC7638(jwk JWK) (string, error) {
	var canonical string
	switch jwk.Kty {
	case "OKP":
		if jwk.Crv == "" || jwk.X == "" {
			return "", errors.New("dpop: OKP jwk missing crv/x for thumbprint")
		}
		canonical = `{"crv":"` + jwk.Crv + `","kty":"OKP","x":"` + jwk.X + `"}`
	case "EC":
		if jwk.Crv == "" || jwk.X == "" || jwk.Y == "" {
			return "", errors.New("dpop: EC jwk missing crv/x/y for thumbprint")
		}
		canonical = `{"crv":"` + jwk.Crv + `","kty":"EC","x":"` + jwk.X + `","y":"` + jwk.Y + `"}`
	case "RSA":
		if jwk.E == "" || jwk.N == "" {
			return "", errors.New("dpop: RSA jwk missing e/n for thumbprint")
		}
		canonical = `{"e":"` + jwk.E + `","kty":"RSA","n":"` + jwk.N + `"}`
	default:
		return "", fmt.Errorf("dpop: unsupported jwk kty %q for thumbprint", jwk.Kty)
	}
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

// DPoPTokenTypeOr returns "DPoP" when a JKT binding is present, else
// defaultType. Relocated from accessors_handlers.go (which was at the line
// budget) — beside dpopTokenTypeOr, which it delegates to.
func (s *Server) DPoPTokenTypeOr(defaultType, jkt string) string {
	return dpopTokenTypeOr(defaultType, jkt)
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
var ErrDPoPNonceRequired = errors.New("dpop: nonce required")

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

// WithDPoPProofMaxAge sets how far in the PAST a DPoP proof's `iat`
// may be before it is rejected as stale (RFC 9449 §4.3). The default
// is 60s ([dpopProofMaxAgeDefault]) — the conventional FAPI 2.0 / RFC
// 9449 value. Loosen it for fleets whose DPoP clients drift; tighten
// it for strict deployments. d <= 0 keeps the 60s default, so leaving
// this unset is byte-identical to the previous hardcoded behavior.
//
// This mirrors the JWT issuers' With{Algo}MaxClockSkew options so DPoP
// and bearer-token validation share one configurable-skew story.
func WithDPoPProofMaxAge(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.dpopProofMaxAge = d
		}
	}
}

// WithDPoPMaxClockSkew sets how far in the FUTURE a DPoP proof's `iat`
// may be (clients whose clocks run ahead of the AS) before rejection.
// Default 60s ([dpopProofClockSkewDefault]); d <= 0 keeps it. Naming
// mirrors WithEd25519MaxClockSkew et al. so the operator surface is
// uniform across DPoP proofs and JWT bearers.
//
// Note: this governs proof `iat` only. The standalone HMAC nonce
// provider keeps the default future-skew (it is not Server-coupled).
func WithDPoPMaxClockSkew(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.dpopProofClockSkew = d
		}
	}
}

// resolvedDPoPProofMaxAge returns the configured proof max-age, falling
// back to the 60s default when unset (<= 0). One place owns the clamp so
// a zero-valued field is always interpreted identically.
func (s *Server) resolvedDPoPProofMaxAge() time.Duration {
	if s.dpopProofMaxAge > 0 {
		return s.dpopProofMaxAge
	}
	return dpopProofMaxAgeDefault
}

// resolvedDPoPProofClockSkew returns the configured future-skew tolerance,
// defaulting to 60s when unset (<= 0).
func (s *Server) resolvedDPoPProofClockSkew() time.Duration {
	if s.dpopProofClockSkew > 0 {
		return s.dpopProofClockSkew
	}
	return dpopProofClockSkewDefault
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
		s.logErrorCtx(ctx, "dpop nonce issue failed", "error", err)
		return
	}
	ctx.ResponseWriter().Header().Set(HeaderDPoPNonce, n)
}

// urlQueryEscape wraps net/url.QueryEscape for callsites that want
// to compose query strings manually rather than build url.Values.
func urlQueryEscape(s string) string { return url.QueryEscape(s) }
