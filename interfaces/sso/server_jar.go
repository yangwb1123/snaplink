package sso

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/security"
)

// RFC 9101 — JWT-Secured Authorization Request (JAR).
//
// Lets a client wrap its authorization request parameters in a
// signed JWT (the "request object"), then send it as the
// `request` parameter on /auth/login. The AS verifies the
// signature against the client's registered public key
// (Client.JWKS) and uses the JWT's claims as the canonical
// authorization parameters.
//
// Threats JAR closes that vanilla URL/body parameters don't:
//
//   1. Tampered redirect_uri: an attacker on the user-agent
//      redirect path can flip `?redirect_uri=` to a phishing
//      URL. With JAR, the redirect_uri is inside a signed JWT —
//      tampering invalidates the signature.
//   2. URL-log leakage: long-lived debug logs and intermediate
//      proxies capture URL parameters. The JAR JWT minimizes
//      the leaked surface (just an opaque JWT instead of the
//      structured params).
//   3. Cross-AS confusion: the JAR JWT's `aud` claim binds it
//      to a specific AS. A JWT meant for AS-A won't pass
//      verification at AS-B because the audience check fails.
//
// PAR (RFC 9126) solves (1) + (3) by pushing the request
// server-side. JAR solves the same set without a separate
// server round-trip but requires the client to hold a signing
// key. Most production deployments offer both; this server
// does the same.
//
// Scope of this implementation:
//   - Asymmetric JWS only — EdDSA + ES256/384/512 + RS256 + PS256
//     (security.AsymmetricJWSAlgs). Signature verification routes
//     through the shared, alg-confusion-safe security.VerifyCompactJWS
//     (the same verifier the SPIFFE / CAEP / federation paths use):
//     the header `alg` is gated against the asymmetric allowlist
//     BEFORE any signature work, the key is bound by `kid`, and the
//     matched JWK's kty/crv MUST be consistent with the alg — so a
//     symmetric (HS*) or `none` alg, or a kid pointing at a wrong-type
//     key, fails closed. Real-world clients overwhelmingly sign with
//     RS256/ES256, and OpenID Federation RPs may present RSA/ECDSA
//     chain-vouched keys, so EdDSA-only rejected most of them.
//   - Both `request` (inline JWT) and `request_uri` (URI-fetched
//     JWT) are wired. The URI-fetch path lives in jar_fetch.go,
//     opts in via WithJARFetcher + Client.AllowedRequestURIs, is
//     HTTPS-only with no-redirect, and is advertised in discovery
//     as `request_uri_parameter_supported: true` when the fetcher
//     is registered. PAR (RFC 9126) is offered alongside for the
//     "push the request server-side" case with stronger
//     single-use + replay-resistant semantics.
//   - JWT claims win on conflict with URL/body parameters, but
//     non-conflicting fields outside the JWT are still applied.
//     This is the "merge-with-JWT-priority" semantic also used
//     by PAR. FAPI 2.0's strict "ignore everything outside the
//     JWT" mode is reserved for a future config flag.

// KeyRequest is the wire parameter name for the JAR JWT on
// /auth/login.
const KeyRequest = "request"

// ErrInvalidRequestObject is the RFC 9101 §6.3 sentinel error
// code. Mapped to 400 invalid_request_object on the wire when
// JWT parsing, signature verification, or claim validation
// fails. The three failure cases are intentionally collapsed
// to one wire code per the same oracle-leak hardening pattern
// used elsewhere in this server.
const ErrInvalidRequestObject = "invalid_request_object"

// JARTypHeader is the RECOMMENDED `typ` value per RFC 9101
// §10.8. Tolerated alternatives: empty (legacy clients) and
// "JWT" (libraries that default to that).
const JARTypHeader = "oauth-authz-req+jwt"

// jarPayload mirrors the authorization-request parameters
// the AS will merge in when a JAR JWT is present. Plus the
// standard JWT control claims (aud/iss/exp/nbf) for §6.3
// validation.
type jarPayload struct {
	ClientID             string          `json:"client_id"`
	ResponseType         string          `json:"response_type"`
	RedirectURI          string          `json:"redirect_uri"`
	Scope                string          `json:"scope"`
	State                string          `json:"state"`
	Nonce                string          `json:"nonce"`
	CodeChallenge        string          `json:"code_challenge"`
	CodeChallengeMethod  string          `json:"code_challenge_method"`
	Resource             []string        `json:"resource"`
	AuthorizationDetails json.RawMessage `json:"authorization_details"`
	LoginHint            string          `json:"login_hint"`
	ResponseMode         string          `json:"response_mode"`
	ACRValues            string          `json:"acr_values"`
	UILocales            string          `json:"ui_locales"`
	Claims               json.RawMessage `json:"claims"`

	// JWT control claims for §6.3 validation.
	Aud audClaim `json:"aud,omitempty"`
	Iss string   `json:"iss,omitempty"`
	Exp int64    `json:"exp,omitempty"`
	Nbf int64    `json:"nbf,omitempty"`
	JTI string   `json:"jti,omitempty"`
}

// audClaim is the RFC 7519 §4.1.3 polymorphic `aud` — either a
// string or an array of strings. JAR JWTs carry the AS issuer
// here; the verifier accepts either shape.
type audClaim []string

func (a *audClaim) UnmarshalJSON(data []byte) error {
	if len(data) == 0 || string(data) == "null" {
		return nil
	}
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		*a = []string{s}
		return nil
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err != nil {
		return err
	}
	*a = arr
	return nil
}

// verifyJAR parses, signature-verifies, and validates an RFC
// 9101 JAR request JWT. Returns the claim payload on success,
// or an error to be mapped to invalid_request_object on the
// wire.
//
// Verification gates per RFC 9101 §6.3:
//   - JWT is 3 base64url segments
//   - Header `typ` MUST be empty, "JWT", or "oauth-authz-req+jwt"
//   - Header `alg` MUST be an asymmetric alg (security.AsymmetricJWSAlgs:
//     EdDSA / ES256/384/512 / RS256 / PS256), gated BEFORE signature
//     verify; `alg: none` + symmetric HS* fail closed
//   - Header `kid` MUST match a JWK in client.JWKS, whose kty/crv MUST
//     be consistent with the alg
//   - Signature MUST verify against the matched public key
//   - exp / nbf honored when present
//   - aud MUST include the AS's identity (asIssuer)
//   - iss SHOULD equal client.ID (when the iss claim is set)
//   - client_id claim MUST equal client.ID (when the
//     client_id claim is set)
func verifyJAR(ctx context.Context, rawJWT string, client *Client, asIssuer string, replay security.JTIReplayStore, replayFailClosed bool) (*jarPayload, error) {
	if client == nil {
		return nil, errors.New("jar: client required")
	}
	if len(client.JWKS) == 0 {
		return nil, errors.New("jar: client has no registered JWKS")
	}
	parts := strings.Split(rawJWT, ".")
	if len(parts) != 3 {
		return nil, errors.New("jar: malformed JWT (expected 3 segments)")
	}
	if err := parseJARTypHeader(parts[0]); err != nil {
		return nil, err
	}

	// Signature verification through the shared, alg-confusion-safe
	// verifier: asymmetric-allowlist gate BEFORE verify (no alg=none, no
	// HS*), kid-bound key selection, kty/crv↔alg consistency, EC
	// on-curve, RSA>=2048. Returns the verified payload bytes; widening
	// past EdDSA to ES*/RS*/PS* is a pure allowlist change here.
	praw, err := security.VerifyCompactJWS(rawJWT, client.JWKS, security.AsymmetricJWSAlgs())
	if err != nil {
		return nil, fmt.Errorf("jar: %w", err)
	}
	var p jarPayload
	if err := json.Unmarshal(praw, &p); err != nil {
		return nil, fmt.Errorf("jar: payload parse: %w", err)
	}

	if err := validateJARClaims(&p, client, asIssuer); err != nil {
		return nil, err
	}

	if done, err := enforceJARReplay(ctx, &p, replay, replayFailClosed); done {
		return &p, err
	}

	return &p, nil
}

// parseJARTypHeader checks the JAR-specific `typ` header (RFC 9101 §10.8).
//
// The `typ` header is JAR-specific (RFC 9101 §10.8) and is NOT
// VerifyCompactJWS's concern, so it is checked here. `alg`, `kid`,
// the kty/crv↔alg consistency, and the signature itself are ALL
// owned by VerifyCompactJWS in verifyJAR — this header parse is only to
// reach `typ` and MUST NOT be trusted for any security decision (it
// reads an UNVERIFIED segment).
func parseJARTypHeader(headerSeg string) error {
	hraw, err := base64.RawURLEncoding.DecodeString(headerSeg)
	if err != nil {
		return fmt.Errorf("jar: header decode: %w", err)
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hraw, &h); err != nil {
		return fmt.Errorf("jar: header parse: %w", err)
	}
	switch h.Typ {
	case "", "JWT", JARTypHeader:
		return nil
	default:
		return fmt.Errorf("jar: typ %q not supported", h.Typ)
	}
}

// validateJARClaims enforces the RFC 9101 §6.3 control-claim gates on the
// already-signature-verified payload: exp/nbf, aud, iss, and client_id.
func validateJARClaims(p *jarPayload, client *Client, asIssuer string) error {
	now := time.Now().Unix()
	if p.Exp != 0 && now >= p.Exp {
		return errors.New("jar: JWT expired")
	}
	if p.Nbf != 0 && now < p.Nbf {
		return errors.New("jar: JWT not yet valid")
	}

	// aud must include the AS — guards against a JWT crafted for
	// a different AS being replayed at this one. Empty aud =
	// legacy compat (skip check; operators with strict needs can
	// gate this via a future config flag).
	if len(p.Aud) > 0 && asIssuer != "" && !slices.Contains([]string(p.Aud), asIssuer) {
		return fmt.Errorf("jar: aud does not include %q", asIssuer)
	}
	if p.Iss != "" && p.Iss != client.ID {
		return fmt.Errorf("jar: iss %q != client_id %q", p.Iss, client.ID)
	}
	if p.ClientID != "" && p.ClientID != client.ID {
		return fmt.Errorf("jar: client_id %q in JWT does not match %q", p.ClientID, client.ID)
	}
	return nil
}

// enforceJARReplay applies RFC 9101 §10.8 jti replay protection.
//
// Returns (done, err): when done is true the caller MUST stop and return
// (&p, err) — preserving the tri-state where a fail-OPEN store error yields
// SUCCESS (done=true, err=nil → &p, nil) while a detected replay or a
// fail-CLOSED store error yields the identical "jar: jti replay detected"
// error. done=false means the replay check passed (or was skipped) and the
// caller continues.
//
// When the operator has wired a security.JTIReplayStore and the JWT carries a
// jti, refuse to process a JWT whose jti has been seen within its expiry
// window. The defense is opt-in (store nil) so legacy deployments aren't
// broken; production should always wire it. Empty jti skips the check — RFC
// 9101 makes jti OPTIONAL but recommends it, so we don't synthesize one.
func enforceJARReplay(ctx context.Context, p *jarPayload, replay security.JTIReplayStore, replayFailClosed bool) (bool, error) {
	if replay == nil || p.JTI == "" {
		return false, nil
	}
	expiresAt := time.Unix(p.Exp, 0)
	if p.Exp == 0 || expiresAt.Before(time.Now()) {
		expiresAt = time.Now().Add(security.DefaultJTIReplayWindow)
	}
	first, err := replay.MarkSeen(ctx, p.JTI, expiresAt)
	if err != nil {
		// Store error: MarkSeen couldn't confirm the jti is
		// unseen. Default fail-OPEN — a broken replay store
		// shouldn't lock out legitimate clients (availability
		// over replay defense). Fail-CLOSED (opt-in) instead
		// treats store-uncertainty AS a replay and rejects with
		// the SAME error a detected replay returns, so the wire
		// shape is identical (no store-health oracle).
		if replayFailClosed {
			return true, errors.New("jar: jti replay detected")
		}
		return true, nil
	}
	if !first {
		return true, errors.New("jar: jti replay detected")
	}
	return false, nil
}

// bindOAuthParams delegates to oauth.BindParams. Kept as an unexported
// alias so existing internal call sites (handler.go, handlers.go)
// continue to compile during the gradual handlers extraction.
func bindOAuthParams(ctx HandlerContext, v any) error { return oauth.BindParams(ctx, v) }

// RFC 8705 §3 — Mutual-TLS Client Certificate-Bound Access Tokens.
//
// The companion proof-of-possession mechanism to DPoP. Where DPoP
// binds to a JWK the client signs with, mTLS binds to the TLS
// client certificate the client presents during the connection
// handshake. Tokens minted while a client cert was on the wire
// carry an `x5t#S256` value in their `cnf` claim — the SHA-256
// thumbprint of the cert DER. Resource servers reject the token
// unless the SAME cert is on the wire when it's presented.
//
// Scope of THIS implementation (issuance side):
//   - Per-request cert extraction (default: direct TLS handshake
//     via r.TLS.PeerCertificates[0]).
//   - Pluggable ClientCertExtractor so reverse-proxy-terminated TLS
//     (envoy / nginx forwarding X-Forwarded-Client-Cert) works.
//   - SHA-256 thumbprint computation + stamping into the issued
//     access token's `cnf.x5t#S256` claim.
//   - Discovery: `tls_client_certificate_bound_access_tokens: true`
//     when an extractor is wired.
//
// Resource-side verification (a downstream service confirming the
// token's cnf.x5t#S256 matches the cert on the inbound connection)
// is left to the resource — same architectural separation as the
// DPoP commit.

// ClientCertExtractor pulls the client's TLS certificate out of an
// incoming request. The default implementation reads
// r.TLS.PeerCertificates[0] (direct TLS termination on the AS).
// Reverse-proxy-terminated deployments inject a custom extractor
// that parses the proxy's "X-Forwarded-Client-Cert" header
// (envoy / nginx convention).
//
// Returns nil + ok=false when the request had no client cert — the
// /token handler then mints an unbound bearer token (legacy path).
type ClientCertExtractor interface {
	ExtractClientCert(r *http.Request) (cert *x509.Certificate, ok bool)
}

// applyRequestObject handles the RFC 9101 JAR `request` parameter: unwrap any
// JWE wrapper (§6.4), verify the signed JWT against the client's JWKS, and merge
// its claims into req (JWT values win on conflict, matching PAR's merge
// semantics). Returns true if it wrote an error response (the caller MUST
// return); false to continue. A no-op returning false when no request object is
// present. Extracted verbatim from handleLogin to keep that orchestrator's
// complexity within budget — the credential/risk/MFA ordering is unchanged.
func (s *Server) applyRequestObject(ctx HandlerContext, req *login.Request, client *Client) bool {
	if req.Request == "" {
		return false
	}
	// RFC 9101 §6.4 encrypted variant: when the payload is JWE-shaped and
	// WithJARDecrypter is wired, decrypt first; the plaintext is the same signed
	// JAR JWT verifyJAR validates. Without a decrypter, JWE-shaped payloads fail
	// invalid_request_object (fail-closed; can't validate what we can't decrypt).
	jarRaw, unwrapErr := security.JWEUnwrap(ctx.Request().Context(), req.Request, s.jarDecrypter)
	if unwrapErr != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequestObject)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequestObject, unwrapErr.Error()))
		return true
	}
	jar, jarErr := verifyJAR(ctx.Request().Context(), jarRaw, client, s.resolveIssuer(ctx), s.jtiReplayStore, s.jtiReplayFailClosed)
	if jarErr != nil {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidRequestObject)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyDesc(ctx, ErrInvalidRequestObject, jarErr.Error()))
		return true
	}
	mergeVerifiedJAR(req, jar)
	return false
}

// mergeVerifiedJAR merges a verified JAR's non-empty fields into req. RFC 9101:
// request-object values take precedence over the matching query parameters.
func mergeVerifiedJAR(req *login.Request, jar *jarPayload) {
	if jar.ResponseType != "" {
		req.ResponseType = jar.ResponseType
	}
	if jar.RedirectURI != "" {
		req.RedirectURI = jar.RedirectURI
	}
	if jar.Scope != "" {
		req.Scope = strings.Split(jar.Scope, " ")
	}
	if jar.State != "" {
		req.State = jar.State
	}
	if jar.Nonce != "" {
		req.Nonce = jar.Nonce
	}
	if jar.CodeChallenge != "" {
		req.CodeChallenge = jar.CodeChallenge
		req.CodeChallengeMethod = jar.CodeChallengeMethod
	}
	if len(jar.Resource) > 0 {
		req.Resource = jar.Resource
	}
	if len(jar.AuthorizationDetails) > 0 {
		req.AuthorizationDetails = oauth.CloneRawJSON(jar.AuthorizationDetails)
	}
	if jar.LoginHint != "" {
		req.LoginHint = jar.LoginHint
	}
	if jar.ResponseMode != "" {
		req.ResponseMode = jar.ResponseMode
	}
	if jar.ACRValues != "" {
		req.ACRValues = jar.ACRValues
	}
	if jar.UILocales != "" {
		req.UILocales = jar.UILocales
	}
	if len(jar.Claims) > 0 {
		req.Claims = oauth.CloneRawJSON(jar.Claims)
	}
}

// ClientCertExtractorFunc adapts a function to the
// [ClientCertExtractor] interface.
type ClientCertExtractorFunc func(r *http.Request) (*x509.Certificate, bool)
