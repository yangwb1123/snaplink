package sso

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/tenant"
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
//   - Ed25519 (EdDSA) only. The signature-algorithm allowlist
//     mirrors supportedJWTAlgs in defaultimpl/ — extending it
//     requires updating both sites.
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
//   - Header `alg` MUST be in the allowlist (EdDSA only today)
//   - Header `typ` MUST be empty, "JWT", or "oauth-authz-req+jwt"
//   - Header `kid` MUST match a JWK in client.JWKS
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

	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jar: header decode: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hraw, &h); err != nil {
		return nil, fmt.Errorf("jar: header parse: %w", err)
	}
	if h.Alg != "EdDSA" {
		return nil, fmt.Errorf("jar: alg %q not supported", h.Alg)
	}
	switch h.Typ {
	case "", "JWT", JARTypHeader:
		// ok
	default:
		return nil, fmt.Errorf("jar: typ %q not supported", h.Typ)
	}

	pub, kidMatched := jwkLookupEd25519(client.JWKS, h.Kid)
	if pub == nil {
		if h.Kid != "" {
			return nil, fmt.Errorf("jar: no JWK matches kid %q", h.Kid)
		}
		return nil, errors.New("jar: no compatible JWK found")
	}
	_ = kidMatched

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jar: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, errors.New("jar: signature invalid")
	}

	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jar: payload decode: %w", err)
	}
	var p jarPayload
	if err := json.Unmarshal(praw, &p); err != nil {
		return nil, fmt.Errorf("jar: payload parse: %w", err)
	}

	now := time.Now().Unix()
	if p.Exp != 0 && now >= p.Exp {
		return nil, errors.New("jar: JWT expired")
	}
	if p.Nbf != 0 && now < p.Nbf {
		return nil, errors.New("jar: JWT not yet valid")
	}

	// aud must include the AS — guards against a JWT crafted for
	// a different AS being replayed at this one. Empty aud =
	// legacy compat (skip check; operators with strict needs can
	// gate this via a future config flag).
	if len(p.Aud) > 0 && asIssuer != "" && !slices.Contains([]string(p.Aud), asIssuer) {
		return nil, fmt.Errorf("jar: aud does not include %q", asIssuer)
	}
	if p.Iss != "" && p.Iss != client.ID {
		return nil, fmt.Errorf("jar: iss %q != client_id %q", p.Iss, client.ID)
	}
	if p.ClientID != "" && p.ClientID != client.ID {
		return nil, fmt.Errorf("jar: client_id %q in JWT does not match %q", p.ClientID, client.ID)
	}

	// RFC 9101 §10.8 replay protection. When the operator has
	// wired a security.JTIReplayStore and the JWT carries a jti, refuse to
	// process a JWT whose jti has been seen within its expiry
	// window. The defense is opt-in (store nil) so legacy
	// deployments aren't broken; production should always wire
	// it. Empty jti skips the check — RFC 9101 makes jti
	// OPTIONAL but recommends it, so we don't synthesize one.
	if replay != nil && p.JTI != "" {
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
				return nil, errors.New("jar: jti replay detected")
			}
			return &p, nil
		}
		if !first {
			return nil, errors.New("jar: jti replay detected")
		}
	}

	return &p, nil
}

// jwkLookupEd25519 picks the Ed25519 public key matching kid
// from a JWK set. When kid is empty, returns the first
// compatible OKP/Ed25519 key (legacy clients with one key per
// set). Returns (nil, false) when no compatible key found.
func jwkLookupEd25519(set []JWK, kid string) (ed25519.PublicKey, bool) {
	for _, jwk := range set {
		if kid != "" && jwk.Kid != kid {
			continue
		}
		if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" {
			continue
		}
		xb, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil || len(xb) != ed25519.PublicKeySize {
			continue
		}
		return ed25519.PublicKey(xb), true
	}
	return nil, false
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

// ClientCertExtractorFunc adapts a function to the
// [ClientCertExtractor] interface.
type ClientCertExtractorFunc func(r *http.Request) (*x509.Certificate, bool)

func (f ClientCertExtractorFunc) ExtractClientCert(r *http.Request) (*x509.Certificate, bool) {
	return f(r)
}

// DefaultTLSPeerCertExtractor reads r.TLS.PeerCertificates[0] —
// the conventional path for direct TLS-terminated AS deployments
// where the Go server itself handles the handshake.
var DefaultTLSPeerCertExtractor ClientCertExtractor = ClientCertExtractorFunc(func(r *http.Request) (*x509.Certificate, bool) {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, false
	}
	return r.TLS.PeerCertificates[0], true
})

// certificateThumbprintS256 computes RFC 8705 §3.1's
// `x5t#S256` — base64url-no-pad encoding of SHA-256(cert.Raw).
// cert MUST NOT be nil (callers gate on extractor's ok=false).
func certificateThumbprintS256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// verifyMTLSBearer enforces the resource-side half of RFC 8705 §3.
// Mirror of verifyDPoPBearer: when the access token carries
// cnf.x5t#S256, the inbound request MUST be on a TLS connection
// whose client cert has the matching SHA-256 thumbprint.
//
// Returns nil when:
//   - the token isn't mTLS-bound (no cnf.x5t#S256), OR
//   - the inbound cert thumbprint equals the bound value.
//
// Returns an error mapped to invalid_token (same wire shape as
// "invalid bearer") on mismatch — oracle-resistance: probes can't
// distinguish unbound from bound-but-mismatched tokens.
//
// Skips the check when no ClientCertExtractor is wired: an
// operator that minted mTLS-bound tokens via one deployment and
// then disabled the extractor would otherwise lock every bound
// token out. Operators changing mTLS posture should revoke
// existing bound tokens explicitly.
func (s *Server) verifyMTLSBearer(ctx HandlerContext, claims *TokenClaims) error {
	if claims == nil || claims.ConfirmationX5TS256 == "" {
		return nil
	}
	if s.clientCertExtractor == nil {
		// No extractor wired — see method doc for the
		// trade-off. The cert is still required on the wire
		// for any HTTP framework that auto-populates r.TLS,
		// just not validated.
		return nil
	}
	cert, ok := s.clientCertExtractor.ExtractClientCert(ctx.Request())
	if !ok || cert == nil {
		return errCertRequired
	}
	got := certificateThumbprintS256(cert)
	if got != claims.ConfirmationX5TS256 {
		return errCertThumbprintMismatch
	}
	return nil
}

// Sentinel errors so logging can distinguish the failure modes
// even though the wire collapses them to invalid_token.
var (
	errCertRequired           = httpError("mtls: token bound but no client cert presented")
	errCertThumbprintMismatch = httpError("mtls: cert thumbprint does not match cnf.x5t#S256")
)

// httpError is a stdlib-free sentinel-error type kept local to
// this file (avoids importing errors just for two constants).
type httpError string

func (e httpError) Error() string { return string(e) }

// applyPairwiseSubject computes the pairwise sub for (client, localSub)
// and persists the reverse mapping in the wired store. Returns the
// pairwise sub when the client opted in AND the store is wired;
// returns localSub unchanged otherwise. Called at every issuance
// path that mints a token whose sub claim the RP will see.
//
// Fail-open: when the store's MapPairwise fails, the function still
// returns the computed pairwise sub but logs the error via the
// supplied error sink. The token MINTS with the pairwise sub —
// resource-side lookups will fail (`invalid_token`) until the next
// successful map. The alternative (fail-closed) would block
// issuance, which is worse than a token whose userinfo path
// temporarily fails.
func (s *Server) applyPairwiseSubject(ctx context.Context, client *Client, localSub string) string {
	if client == nil || s.pairwiseStore == nil {
		return localSub
	}
	if !strings.EqualFold(client.SubjectType, security.SubjectTypePairwise) {
		return localSub
	}
	sector := security.SectorIdentifier(client)
	pairwise := security.ComputePairwiseSubject(sector, localSub, s.pairwiseSalt)
	if pairwise == "" {
		return localSub
	}
	if err := s.pairwiseStore.MapPairwise(ctx, pairwise, localSub); err != nil {
		s.logger.Error("pairwise: map failed (continuing — resource lookups may fail)", "error", err, "client_id", client.ID)
	}
	return pairwise
}

// resolveLocalSubject reverses a pairwise sub on inbound resource
// requests. When pairwise is wired AND the sub looks like a pairwise
// value (not present in UserProvider as a local id), the store is
// consulted; security.ErrPairwiseUnknown surfaces to the caller which maps it
// to the standard invalid_token response.
//
// When pairwise is NOT wired or the sub is a known local id, the
// input is returned unchanged — pairwise opt-in is per-client, so
// non-pairwise clients keep their public sub semantics.
//
// The cheap-path optimization (looking up local first) means
// non-pairwise deployments pay nothing beyond what they already paid
// before this feature existed.
func (s *Server) resolveLocalSubject(ctx context.Context, sub string) (string, error) {
	if sub == "" {
		return sub, nil
	}
	if s.pairwiseStore == nil {
		return sub, nil
	}
	local, err := s.pairwiseStore.LocalSubject(ctx, sub)
	if err == nil {
		return local, nil
	}
	if errors.Is(err, security.ErrPairwiseUnknown) {
		// Not a pairwise sub — caller's claim is already local.
		return sub, nil
	}
	return sub, err
}

// WithPairwiseSubjectStore enables OIDC Core §8 pairwise subject
// identifiers. Per-client subject_type metadata gates use: clients
// with SubjectType="pairwise" get an opaque per-sector sub in their
// tokens; "public" (default) clients continue to receive the local
// subject identifier. Resource-side handlers (/userinfo, etc.) use
// the store's reverse map to recover the local sub for lookups.
//
// Discovery doc advertises both "public" and "pairwise" in
// subject_types_supported when this option is wired.
//
// Single-replica memory backend is provided
// (NewMemoryPairwiseSubjectStore); multi-replica deployments need a
// shared backend so pairwise subs issued on replica A resolve on
// replica B.
func WithPairwiseSubjectStore(store security.PairwiseSubjectStore) Option {
	return func(s *Server) { s.pairwiseStore = store }
}

// WithPairwiseSalt overrides the deterministic salt mixed into
// pairwise sub computation. Operators SHOULD set this to a
// deployment-stable secret distributed out-of-band — the default is
// publicly known and lets attackers pre-compute pairwise sub →
// local sub mappings if they ever see a local sub in some other
// channel. Empty value falls back to security.DefaultPairwiseSalt.
func WithPairwiseSalt(salt string) Option {
	return func(s *Server) { s.pairwiseSalt = salt }
}

// RFC 7521 + RFC 7523 — JWT Bearer client authentication.
//
// Lets confidential clients prove their identity to /token (and
// related endpoints) by signing a JWT instead of presenting a
// client_secret. The standard `private_key_jwt` mechanism in OIDC
// Core §9. Useful when:
//
//   - Client_secret distribution is a compliance pain (shared secret
//     storage / rotation across CI / multi-region deployments).
//   - The deployment already maintains a JWKS for the client (this
//     server's JAR support uses the same Client.JWKS field).
//   - High-security environments mandate asymmetric-key authentication.

// ClientAssertionTypeJWTBearer is the RFC 7521 §4.2 URN for
// JWT-shaped client assertions. The /token endpoint only accepts
// JWT bearer (the spec carves out a SAML 2.0 variant too;
// `urn:ietf:params:oauth:client-assertion-type:saml2-bearer` is
// not supported here today).
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// DefaultClientAssertionMaxLifetime caps how far into the future a
// client_assertion's `exp` claim can sit. RFC 7523 §3 requires the
// AS to reject overly-long-lived assertions; 5 minutes matches the
// common convention and the request-object lifetime ceilings.
const DefaultClientAssertionMaxLifetime = 5 * time.Minute

// verifyJWTClientAssertion validates an RFC 7523 §3 client
// assertion. Returns the asserted client_id on success — callers
// MUST use this return value (NOT the wire `client_id` form param)
// for subsequent lookups, since the JWT's `sub` claim is the
// authoritative identity binding.
//
// Validation gates per RFC 7523 §3:
//   - JWT MUST decode as 3 base64url segments
//   - Header `alg` MUST be in the EdDSA allowlist (matches JAR)
//   - Header `typ` MAY be present; if present MUST be "JWT" or
//     "client-authentication+jwt"
//   - Header `kid` selects the verification key from Client.JWKS
//   - Signature MUST verify against the matched public key
//   - iss + sub MUST be equal AND non-empty AND equal client_id
//     (when the request-form client_id was supplied — when not, sub
//     drives the lookup)
//   - aud MUST include the AS issuer (acceptable values: the
//     resolveIssuer string the server emits in discovery)
//   - exp MUST be in the future AND within DefaultClientAssertionMaxLifetime
//   - jti MUST be present when security.JTIReplayStore is wired; replay
//     rejects the duplicate
//
// Errors collapse to one wire shape on the caller side
// (invalid_client) so attacker probing can't distinguish "wrong
// signature" from "missing client" from "wrong audience".
func verifyJWTClientAssertion(
	ctx context.Context,
	assertion string,
	formClientID string,
	clientStore ClientStore,
	asIssuer string,
	replay security.JTIReplayStore,
	replayFailClosed bool,
) (string, error) {
	if clientStore == nil {
		return "", errors.New("jwt_client_assertion: client store required")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", errors.New("jwt_client_assertion: malformed JWT")
	}
	hraw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("jwt_client_assertion: header decode: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hraw, &h); err != nil {
		return "", fmt.Errorf("jwt_client_assertion: header parse: %w", err)
	}
	if h.Alg != "EdDSA" {
		return "", fmt.Errorf("jwt_client_assertion: alg %q not supported", h.Alg)
	}
	switch h.Typ {
	case "", "JWT", "client-authentication+jwt":
	default:
		return "", fmt.Errorf("jwt_client_assertion: typ %q not supported", h.Typ)
	}

	praw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("jwt_client_assertion: payload decode: %w", err)
	}
	var p struct {
		Iss string   `json:"iss"`
		Sub string   `json:"sub"`
		Aud audClaim `json:"aud"`
		Exp int64    `json:"exp"`
		Nbf int64    `json:"nbf"`
		Iat int64    `json:"iat"`
		JTI string   `json:"jti"`
	}
	if err := json.Unmarshal(praw, &p); err != nil {
		return "", fmt.Errorf("jwt_client_assertion: payload parse: %w", err)
	}
	if p.Sub == "" || p.Sub != p.Iss {
		return "", errors.New("jwt_client_assertion: iss/sub must be equal and non-empty")
	}
	if formClientID != "" && formClientID != p.Sub {
		return "", errors.New("jwt_client_assertion: form client_id does not match sub")
	}
	now := time.Now()
	if p.Exp == 0 || now.After(time.Unix(p.Exp, 0)) {
		return "", errors.New("jwt_client_assertion: expired or missing exp")
	}
	if time.Unix(p.Exp, 0).After(now.Add(DefaultClientAssertionMaxLifetime)) {
		return "", fmt.Errorf("jwt_client_assertion: exp too far in future (max %s)", DefaultClientAssertionMaxLifetime)
	}
	if p.Nbf != 0 && now.Before(time.Unix(p.Nbf, 0)) {
		return "", errors.New("jwt_client_assertion: nbf in future")
	}
	if asIssuer != "" && !slices.Contains([]string(p.Aud), asIssuer) {
		return "", fmt.Errorf("jwt_client_assertion: aud does not include %q", asIssuer)
	}

	client, err := clientStore.Get(ctx, p.Sub)
	if err != nil || client == nil {
		return "", errors.New("jwt_client_assertion: client not found")
	}
	if len(client.JWKS) == 0 {
		return "", errors.New("jwt_client_assertion: client has no registered JWKS")
	}
	pub, _ := jwkLookupEd25519(client.JWKS, h.Kid)
	if pub == nil {
		return "", errors.New("jwt_client_assertion: no JWK matches kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", fmt.Errorf("jwt_client_assertion: signature decode: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return "", errors.New("jwt_client_assertion: signature invalid")
	}

	// Replay defense — when wired and the JWT carries a jti, refuse
	// any second sighting within its exp window. Same store + same
	// semantics JAR replay protection uses; one knob covers both.
	if replay != nil && p.JTI != "" {
		first, err := replay.MarkSeen(ctx, p.JTI, time.Unix(p.Exp, 0))
		switch {
		case err != nil:
			// Store error — default fail-OPEN (continue). Fail-CLOSED
			// (opt-in) rejects with the detected-replay error so the
			// wire shape is identical (no store-health oracle).
			if replayFailClosed {
				return "", errors.New("jwt_client_assertion: jti replay detected")
			}
		case !first:
			return "", errors.New("jwt_client_assertion: jti replay detected")
		}
	}

	return p.Sub, nil
}

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

// dpopProofMaxAgeDefault bounds how stale a proof JWT may be. RFC 9449
// §4.3 mandates a "reasonable" iat window; 60 seconds matches
// the conventional value across the FAPI 2.0 + RFC 9449 ecosystem.
// Operators override per deployment via WithDPoPProofMaxAge; this is
// the value the Server falls back to when the field is unset (<= 0).
const dpopProofMaxAgeDefault = 60 * time.Second

// dpopProofClockSkewDefault tolerates clients whose clocks are slightly
// ahead of the AS. Same bound as iat staleness on the other side.
// Override via WithDPoPMaxClockSkew (mirrors the JWT issuers'
// With{Algo}MaxClockSkew options for a uniform configurable-skew story).
const dpopProofClockSkewDefault = 60 * time.Second

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
//   - payload iat MUST be within maxAge (past) / clockSkew (future)
//   - payload jti MUST be present (replay-defense token)
//
// maxAge + clockSkew are the operator-tunable windows resolved from the
// Server (WithDPoPProofMaxAge / WithDPoPMaxClockSkew), defaulting to 60s.
// They are passed in (rather than read from a const) so a deployment whose
// DPoP clients drift beyond 60s can loosen, and a strict one can tighten —
// matching the JWT issuers' already-configurable skew.
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
	if p.IAT > now+int64(clockSkew.Seconds()) {
		return nil, errors.New("dpop: iat in the future beyond clock skew")
	}
	if p.IAT < now-int64(maxAge.Seconds()) {
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
		first, err := replay.MarkSeen(ctx, "dpop:"+p.JTI, time.Now().Add(maxAge))
		switch {
		case err != nil:
			// Store error — default fail-OPEN (continue). Fail-CLOSED
			// (opt-in) rejects with the detected-replay error so the
			// wire shape is identical (no store-health oracle).
			if replayFailClosed {
				return nil, errors.New("dpop: jti replay detected")
			}
		case !first:
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
		s.jtiReplayFailClosed,
		s.dpopNonceProvider,
		s.resolvedDPoPProofMaxAge(),
		s.resolvedDPoPProofClockSkew(),
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
	// ts + now are UnixNano, and time.Duration is already nanoseconds, so
	// int64(dpopProofClockSkewDefault) is the correct nanosecond bound here
	// (no .Seconds() — that would shrink the skew to 60ns). The nonce
	// provider is a standalone component with its own lifecycle (own ttl,
	// own key); it is not Server-coupled, so it tolerates the same default
	// future-skew as proof iat rather than reaching into a Server field.
	if ts > now+int64(dpopProofClockSkewDefault) {
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
		s.logger.Error("dpop nonce issue failed", "error", err)
		return
	}
	ctx.ResponseWriter().Header().Set(HeaderDPoPNonce, n)
}

// urlQueryEscape wraps net/url.QueryEscape for callsites that want
// to compose query strings manually rather than build url.Values.
func urlQueryEscape(s string) string { return url.QueryEscape(s) }

// OIDC Back-Channel Logout 1.0.
//
// When a user logs out of the SSO server (via POST /logout or
// GET /end_session), every relying party that the user has an
// active session with should also tear down its local session
// — otherwise the user is "logged out of one app, still logged
// into N others". OIDC BCL closes that gap by having the AS
// POST a signed logout_token to each RP's registered
// `backchannel_logout_uri`. The RP verifies the token (it's a
// JWT signed by the same key serving the JWKS endpoint) and
// invalidates its session.
//
// Scope of THIS implementation:
//   - Single-RP notification is the default; multi-RP fan-out
//     (notify every RP the user is signed into) engages when
//     [WithSubjectClientIndex] is wired — fanOutBackchannelLogout
//     walks the index for the subject and posts a logout_token to
//     every BCL-capable client.
//   - sid claim is included on the logout_token when the issuer
//     has a session id for the subject (Server-side SessionManager
//     populates one; the access-token issuer stamps it via the
//     RFC 9068 `sid` claim). Fan-out targets keep their original
//     sid when one is recorded; missing-sid targets omit the
//     claim per OIDC BCL §2.4.

// LogoutTokenIssuer mints OIDC Back-Channel Logout 1.0 §2.4
// logout tokens. Same signing key as the access-token issuer is
// the conventional and recommended setup so RPs verify with one
// JWKS entry.
type LogoutTokenIssuer interface {
	IssueLogoutToken(ctx context.Context, req *LogoutTokenRequest) (string, error)
}

// LogoutTokenRequest carries the issuance inputs. TTL falls
// back to a short default when zero — logout tokens are
// single-use and short-lived by nature (the RP processes one
// immediately on receipt).
type LogoutTokenRequest struct {
	Subject  string
	Audience string
	TTL      time.Duration

	// SID is the OIDC Back-Channel Logout 1.0 §2.4 session
	// identifier. When set, the issued logout_token carries a
	// `sid` claim — the RP uses it to invalidate the specific
	// session it received the matching id_token for, rather
	// than wiping every session for the subject. Empty omits
	// the claim (legacy/coarse behavior).
	SID string
}

// LogoutNotifier delivers a signed logout_token to the RP's
// backchannel_logout_uri per OIDC BCL §2.5. Implementations MUST
// respect the supplied context's deadline so the AS isn't
// blocked when an RP is slow or unreachable.
type LogoutNotifier interface {
	Notify(ctx context.Context, uri string, logoutToken string) error
}

// DefaultBackchannelLogoutTimeout caps an individual RP
// notification. Short on purpose — the user is waiting on the
// /logout response while this round-trips, and a slow RP must
// not delay the rest of the logout pipeline. A failure here is
// logged + audited but not fatal.
const DefaultBackchannelLogoutTimeout = 5 * time.Second

// DefaultBackchannelLogoutMaxConcurrent caps the multi-RP fan-out
// parallelism so a user with 50+ active RPs doesn't have /end_session
// open 50 simultaneous outbound HTTP connections (which can starve
// the connection pool + exhaust ephemeral ports under burst). 8 is
// a conservative default that keeps p99 logout latency bounded at
// roughly `timeout × ceil(N / max)` instead of `timeout × N` in the
// serial path. Override with WithBackchannelLogoutMaxConcurrent.
const DefaultBackchannelLogoutMaxConcurrent = 8

// HTTPLogoutNotifier is the production LogoutNotifier. POSTs
// `logout_token=<jwt>` as
// application/x-www-form-urlencoded per OIDC BCL §2.5.
type HTTPLogoutNotifier struct {
	Client *http.Client
}

// NewHTTPLogoutNotifier returns an HTTP notifier with a default
// 5s timeout. Callers may swap in a custom *http.Client to wire
// proxies, custom TLS roots, or tracing instrumentation.
func NewHTTPLogoutNotifier() *HTTPLogoutNotifier {
	return &HTTPLogoutNotifier{
		Client: &http.Client{Timeout: DefaultBackchannelLogoutTimeout},
	}
}

// Notify implements LogoutNotifier. Returns an error if the POST
// fails or the RP returns a non-2xx status — caller decides
// whether to retry or surface the failure to the user.
func (n *HTTPLogoutNotifier) Notify(ctx context.Context, uri string, logoutToken string) error {
	if uri == "" {
		return errors.New("backchannel_logout: empty uri")
	}
	form := url.Values{"logout_token": {logoutToken}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uri, bytes.NewReader([]byte(form)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "*/*")
	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: DefaultBackchannelLogoutTimeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain the body up to a small cap so HTTP/1.1 connection reuse works
	// even when the RP sends a verbose error page; throw it away.
	_, _ = io.CopyN(io.Discard, resp.Body, 1<<14)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return fmt.Errorf("backchannel_logout: non-2xx status %d from %s", resp.StatusCode, uri)
}

// sendBackchannelLogout fans out a logout notification for the
// given (subject, client). No-op when:
//   - The back-channel logout subsystem isn't wired
//     (logoutTokenIssuer + logoutNotifier MUST both be set).
//   - The client doesn't declare BackchannelLogoutURI.
//
// Failures are logged + audited but never block the parent
// /logout response — see the contract on LogoutNotifier.
func (s *Server) sendBackchannelLogout(ctx HandlerContext, client *Client, subject string, sid string) {
	if s.logoutTokenIssuer == nil || s.logoutNotifier == nil {
		return
	}
	if client == nil || client.BackchannelLogoutURI == "" {
		return
	}
	tokenCtx, cancel := context.WithTimeout(ctx.Request().Context(), DefaultBackchannelLogoutTimeout)
	defer cancel()
	logoutToken, err := s.logoutTokenIssuer.IssueLogoutToken(tokenCtx, &LogoutTokenRequest{
		Subject:  subject,
		Audience: client.ID,
		// OIDC BCL §2.4: `sid` lets the RP scope the logout to
		// the specific session it received the matching id_token
		// for. Empty when the inbound id_token_hint had no sid
		// claim (legacy tokens minted before sid plumbing).
		SID: sid,
	})
	if err != nil {
		s.logger.Error("backchannel logout: issue token failed",
			"error", err, "client", client.ID, "subject", subject)
		s.recordLogoutNotifyFailure(ctx, client.ID, subject, err.Error())
		return
	}
	if err := s.logoutNotifier.Notify(tokenCtx, client.BackchannelLogoutURI, logoutToken); err != nil {
		s.logger.Error("backchannel logout: notify failed",
			"error", err, "client", client.ID, "uri", client.BackchannelLogoutURI)
		s.recordLogoutNotifyFailure(ctx, client.ID, subject, err.Error())
		return
	}
	s.recordLogoutNotifySuccess(ctx, client.ID, subject, client.BackchannelLogoutURI)
}

// recordSubjectClientAccess stamps the (subject, clientID) pair into
// the security.SubjectClientIndex so multi-RP back-channel logout fan-out can
// reach this client later. No-op when the index isn't wired or
// either id is empty (client_credentials passes empty subject in
// some paths; just skip the bookkeeping write). Failures are logged
// but never block the calling flow — the index is a UX optimization,
// not a correctness gate.
func (s *Server) recordSubjectClientAccess(ctx context.Context, subject, clientID string) {
	if s.subjectClientIndex == nil || subject == "" || clientID == "" {
		return
	}
	if err := s.subjectClientIndex.RecordAccess(ctx, subject, clientID); err != nil {
		s.logger.Error("subject_client_index: record access failed",
			"error", err, "subject", subject, "client", clientID)
	}
}

// fanOutBackchannelLogout drives the multi-RP variant of
// sendBackchannelLogout. When the security.SubjectClientIndex is wired, every
// client the subject has been seen with — not just the one the
// bearer / id_token_hint named — gets a logout_token POST. The
// triggering client (passed via `originClient`) is included in the
// fan-out set; callers SHOULD NOT additionally call
// sendBackchannelLogout for that client.
//
// Each successful notification calls Forget so a follow-up logout
// for the same subject doesn't re-notify a client that already
// processed its logout — keeps the index trim and prevents
// duplicate logout_token POSTs on subsequent (no-op) logouts.
//
// When the index isn't wired, falls back to the single-RP path
// behind sendBackchannelLogout against originClient.
func (s *Server) fanOutBackchannelLogout(ctx HandlerContext, originClient *Client, subject string, sid string) {
	if s.subjectClientIndex == nil {
		// Legacy single-RP behavior.
		s.sendBackchannelLogout(ctx, originClient, subject, sid)
		return
	}
	if subject == "" || s.clientStore == nil {
		return
	}
	clientIDs, err := s.subjectClientIndex.ListClients(ctx.Request().Context(), subject)
	if err != nil {
		s.logger.Error("subject_client_index: list failed", "error", err, "subject", subject)
		// Fall through to single-RP so the triggering client at least
		// hears about the logout when the index is degraded.
		s.sendBackchannelLogout(ctx, originClient, subject, sid)
		return
	}
	// Always include the origin client even if the index missed it
	// (e.g. the very first login on a new replica before propagation).
	seen := make(map[string]struct{}, len(clientIDs)+1)
	if originClient != nil {
		clientIDs = append(clientIDs, originClient.ID)
	}
	// Deduplicate + filter to the BCL-capable subset BEFORE spawning
	// workers so we know exactly how many to wait on and Forget calls
	// for non-BCL clients happen immediately (no goroutine spin-up
	// cost for them).
	targets := make([]*Client, 0, len(clientIDs))
	for _, cid := range clientIDs {
		if cid == "" {
			continue
		}
		if _, dup := seen[cid]; dup {
			continue
		}
		seen[cid] = struct{}{}
		c, err := s.clientStore.Get(ctx.Request().Context(), cid)
		if err != nil || c == nil || c.BackchannelLogoutURI == "" {
			// Client was deleted or doesn't speak BCL — Forget so the
			// index doesn't carry it forever; nothing else to do.
			_ = s.subjectClientIndex.Forget(ctx.Request().Context(), subject, cid)
			continue
		}
		targets = append(targets, c)
	}
	if len(targets) == 0 {
		return
	}
	// Parallel fan-out with bounded concurrency. Serial loop would
	// stack each RP's `DefaultBackchannelLogoutTimeout` (5s default)
	// linearly — a user with 10 RPs and one slow RP would block
	// /end_session for 50s before unblocking. Bounded worker pool
	// keeps p99 at roughly timeout × ceil(N / max) while avoiding
	// the 50+-connection burst a naive unbounded goroutine-per-RP
	// would emit. The Forget call follows the notification (success
	// or failure) on the same worker — see sendBackchannelLogout
	// for the audit recording contract.
	max := s.backchannelLogoutMaxConcurrent
	if max <= 0 {
		max = DefaultBackchannelLogoutMaxConcurrent
	}
	if max > len(targets) {
		max = len(targets)
	}
	work := make(chan *Client, len(targets))
	for _, c := range targets {
		work <- c
	}
	close(work)
	var wg sync.WaitGroup
	wg.Add(max)
	for i := 0; i < max; i++ {
		go func() {
			defer wg.Done()
			for c := range work {
				// Per-client sid filter: every fan-out RP gets the
				// SAME sid value. RPs that don't recognize the sid
				// fall back to subject-wide logout per BCL §2.4 —
				// exactly the desired soft-degradation.
				s.sendBackchannelLogout(ctx, c, subject, sid)
				_ = s.subjectClientIndex.Forget(ctx.Request().Context(), subject, c.ID)
			}
		}()
	}
	wg.Wait()
}

// OIDC Front-Channel Logout 1.0.
//
// When the user logs out via /end_session and one or more clients
// the subject is signed into expose a FrontchannelLogoutURI, the
// response body is an HTML page with a hidden iframe per such
// client. The browser loads each URI; the RPs respond by clearing
// their own session cookies. After a short delay the page redirects
// to post_logout_redirect_uri if one was supplied and allowlisted —
// the delay gives every iframe time to fire its request before the
// user agent navigates away.
//
// Multi-RP fan-out mirrors BCL: when [WithSubjectClientIndex] is
// wired, gatherFrontchannelLogoutIframes walks the index and emits
// one iframe per FCL-capable client the subject has logged into
// across the cluster. Without the index, only the primary client
// (the one matched by id_token_hint / client_id_hint) gets an
// iframe — the original single-RP behavior is preserved as a
// graceful fallback.
//
// Caveats:
//
//   - sid claim only on the primary iframe. Fan-out targets get an
//     empty sid because the AS doesn't keep per-(subject, client)
//     session IDs in the security.SubjectClientIndex; FCL §3 allows sid
//     omission when the AS doesn't have one for that target.
//   - Fire-and-forget: the AS has no signal whether the iframes
//     actually cleared the RPs' sessions. Matches BCL's fail-open
//     posture — logout completes regardless of RP cooperation.

// frontchannelLogoutTemplate renders the OIDC FCL 1.0 §3 HTML
// response. The two-second meta-refresh is the working compromise:
// long enough for the iframes to issue their requests, short enough
// that users don't perceive a hang. html/template auto-escapes
// every iframe `src` and the `.RedirectURI` in their respective
// attribute contexts — `src=` and `href=` are URL-safe, the
// meta-refresh `content=` is HTML-escaped. Operator-controlled
// inputs only, but escaping is belt-and-braces against future
// client-supplied values.
var frontchannelLogoutTemplate = template.Must(template.New("fcl").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Logout</title>
{{if .RedirectURI}}<meta http-equiv="refresh" content="2; url={{.RedirectURI}}">{{end}}
</head>
<body>
{{range .IframeURIs}}<iframe src="{{.}}" style="display:none" referrerpolicy="no-referrer" sandbox="allow-same-origin allow-scripts"></iframe>
{{end}}{{if .RedirectURI}}<p>You will be redirected to <a href="{{.RedirectURI}}">{{.RedirectURI}}</a> shortly.</p>{{end}}
</body>
</html>
`))

// frontchannelLogoutData is the template input. IframeURIs is a
// pre-composed slice (each URI already has sid+iss query params
// appended where applicable); the template only iterates.
type frontchannelLogoutData struct {
	IframeURIs  []string
	RedirectURI string
}

// renderFrontchannelLogout writes the FCL HTML response. Always
// 200 OK — the logout already happened by the time we render; the
// HTML page is the side-effect carrier, not the operation. X-Frame-
// Options: DENY prevents an attacker from embedding our /end_session
// response in their own iframe to trick users into involuntary
// logout (a low-impact but real clickjacking vector).
//
// iframeURIs are pre-composed by gatherFrontchannelLogoutIframes
// with sid + iss query params per OIDC Front-Channel Logout 1.0 §3
// — sid disambiguates the RP's concurrent sessions, iss helps
// multi-issuer RPs route the logout.
func (s *Server) renderFrontchannelLogout(ctx HandlerContext, iframeURIs []string, redirectURI string) {
	w := ctx.ResponseWriter()
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_ = frontchannelLogoutTemplate.Execute(w, frontchannelLogoutData{
		IframeURIs:  iframeURIs,
		RedirectURI: redirectURI,
	})
}

// gatherFrontchannelLogoutIframes returns the iframe URIs (with
// sid + iss query params appended) to render on the FCL page.
//
// The primary client — the one matched by id_token_hint /
// client_id_hint — comes first when it has a FrontchannelLogoutURI;
// it carries the sid from the inbound id_token so the RP can
// disambiguate which session to clear. When [WithSubjectClientIndex]
// is wired, every additional client the subject is logged into
// across the cluster contributes one more iframe (deduplicated;
// sorted for deterministic output). Fan-out targets get an empty
// sid — the AS doesn't keep per-(subject, client) session IDs in
// the index, and FCL §3 allows sid omission when the AS doesn't
// have one for that target.
//
// Returns an empty slice when no client has FCL configured; callers
// MUST check len(...) > 0 before deciding to render the HTML page
// (versus falling through to the 302 / 204 paths).
func (s *Server) gatherFrontchannelLogoutIframes(ctx HandlerContext, subject string, primary *Client, sid string) []string {
	iss := s.resolveIssuer(ctx)
	out := []string{}
	seen := map[string]bool{}
	if primary != nil && primary.FrontchannelLogoutURI != "" {
		out = append(out, appendFrontchannelLogoutSidIss(primary.FrontchannelLogoutURI, sid, iss))
		seen[primary.ID] = true
	}
	if s.subjectClientIndex == nil || subject == "" || s.clientStore == nil {
		return out
	}
	ids, err := s.subjectClientIndex.ListClients(ctx.Request().Context(), subject)
	if err != nil {
		s.logger.Error("subject_client_index: list failed (fcl fanout)", "error", err, "subject", subject)
		return out
	}
	sort.Strings(ids)
	for _, id := range ids {
		if seen[id] {
			continue
		}
		c, err := s.clientStore.Get(ctx.Request().Context(), id)
		if err != nil || c == nil || c.FrontchannelLogoutURI == "" {
			continue
		}
		out = append(out, appendFrontchannelLogoutSidIss(c.FrontchannelLogoutURI, "", iss))
		seen[id] = true
	}
	return out
}

// appendFrontchannelLogoutSidIss appends `sid` + `iss` query params
// to the iframe URI when present. Both empty = return URI unchanged.
// Preserves any pre-existing query string on the RP-registered URI.
func appendFrontchannelLogoutSidIss(uri, sid, iss string) string {
	if sid == "" && iss == "" {
		return uri
	}
	var params []string
	if sid != "" {
		params = append(params, "sid="+urlQueryEscape(sid))
	}
	if iss != "" {
		params = append(params, "iss="+urlQueryEscape(iss))
	}
	sep := "?"
	if strings.Contains(uri, "?") {
		sep = "&"
	}
	return uri + sep + strings.Join(params, "&")
}

// Small Server-coupled response helpers grouped here for navigability.
// Formerly lived in standalone files (token_no_store.go, bearer_challenge.go,
// audit_partial_revoke.go); merged because the concern is one: shape an
// HTTP response with security / audit headers or events.

// tokenNoStoreHeaders stamps RFC 6749 §5.1 cache-prevention headers
// on credential-bearing responses. /token, /token/introspect,
// /token/revoke and /par all return data that intermediaries MUST
// NOT retain — leaked tokens replayed off a cache would defeat
// the rotation + revocation invariants the rest of the server
// enforces. Pragma: no-cache is the HTTP/1.0 companion the RFC
// requires alongside Cache-Control; both go on every response
// regardless of status so error bodies (which include error_code
// shapes a snooping cache could fingerprint) get the same
// treatment as success.
// tokenNoStoreHeaders delegates to middleware.TokenNoStoreHeaders.
func tokenNoStoreHeaders(ctx HandlerContext) { middleware.TokenNoStoreHeaders(ctx) }

// setBearerChallenge stamps an RFC 6750 §3 WWW-Authenticate header
// on a 401 response. Protected resources that accept Bearer tokens
// MUST include this challenge so RPs know which scheme to use and
// can branch on `error=invalid_token` to trigger a refresh vs.
// `error=insufficient_scope` (reserved for /userinfo scope gates
// added later).
//
// realm: the protection space — defaulted to "sso" when the
// issuer can't be resolved. errorCode / errorDescription: omitted
// for the "no credentials presented" case (RFC §3.1: error
// parameters are only included when the request had a token that
// failed validation). Description values are quoted-string escaped
// per RFC 7235 §2.2 so untrusted upstream values can't break out
// and inject additional auth-params.
func setBearerChallenge(ctx HandlerContext, realm, errorCode, errorDescription string) {
	if realm == "" {
		realm = "sso"
	}
	parts := []string{`Bearer realm=` + security.QuoteAuthParam(realm)}
	if errorCode != "" {
		parts = append(parts, `error=`+security.QuoteAuthParam(errorCode))
	}
	if errorDescription != "" {
		parts = append(parts, `error_description=`+security.QuoteAuthParam(errorDescription))
	}
	ctx.ResponseWriter().Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
}

// auditPartialRevokeFailure emits an `EventPartialRevokeFailure` event
// when at least one TokenIssuer failed to revoke a token while at
// least one succeeded — the "logout everywhere" promise has been
// partially violated and operators MUST follow up manually before the
// failed-issuer's tokens reach natural expiry.
//
// Both lists are recorded so SIEM filters can compute the success
// ratio over time and alert when failed/(revoked+failed) crosses a
// threshold. When failed is empty (full success or "no issuer owned
// this token"), this is a no-op — emitting an event in those cases
// would be noise. Safe to call with a nil Recorder; uses audit.SetMeta so
// geo + tenant middleware enrichment isn't clobbered.
func (s *Server) auditPartialRevokeFailure(ctx HandlerContext, revoked, failed []string) {
	if s.auditor == nil || len(failed) == 0 {
		return
	}
	e := &audit.Event{
		Type:      audit.EventPartialRevokeFailure,
		Outcome:   audit.OutcomeFailure,
		Timestamp: time.Now(),
	}
	audit.SetMeta(e, "revoked", strings.Join(revoked, ","))
	audit.SetMeta(e, "failed", strings.Join(failed, ","))
	s.auditor.Record(ctx.Request().Context(), e)
}

// RevokeTenantRefreshTokens purges every refresh token issued to any client
// belonging to tenantID — the active-revocation companion to tenant
// suspension. WithTenantSuspensionCheck only *lazily* rejects a tenant-bound
// token on its next validate (and only when wired), and never touches
// refresh tokens; this proactively deletes them so a suspended tenant's
// sessions can't be resumed from a still-valid refresh token, and so the
// tokens stay gone even after the tenant is later reactivated.
//
// Opt-in + best-effort: returns (0, nil) when the client store can't
// enumerate by tenant (no TenantScopedClientStore) or the refresh store
// can't purge by client (no oauth.RefreshTokenClientPurger) — wiring neither
// yields no active revocation, identical to today's behavior. A per-client
// purge failure is logged and collected but never aborts the remaining
// clients, so one bad client can't strand the rest. Returns the total tokens
// deleted plus any joined per-client errors.
func (s *Server) RevokeTenantRefreshTokens(ctx context.Context, tenantID string) (int, error) {
	if tenantID == "" {
		return 0, nil
	}
	scoped, ok := s.clientStore.(TenantScopedClientStore)
	if !ok {
		return 0, nil
	}
	purger, ok := s.refreshTokenStore.(oauth.RefreshTokenClientPurger)
	if !ok {
		return 0, nil
	}
	clients, err := scoped.ListByTenant(ctx, tenantID)
	if err != nil {
		return 0, fmt.Errorf("sso: list tenant clients: %w", err)
	}
	var (
		total int
		errs  []error
	)
	for _, c := range clients {
		n, derr := purger.DeleteAllForClient(ctx, c.ID)
		if derr != nil {
			if s.logger != nil {
				s.logger.Error("revoke tenant refresh tokens: client purge failed",
					"error", derr, "tenant", tenantID, "client", c.ID)
			}
			errs = append(errs, derr)
			continue
		}
		total += n
	}
	s.auditTenantTokensRevoked(ctx, tenantID, total)
	return total, errors.Join(errs...)
}

// auditTenantTokensRevoked records the active revocation a tenant suspension
// triggered. Count is informational; a zero count still records so a SIEM
// sees the suspension was enforced even when the tenant held no live tokens.
// Safe with a nil Recorder; uses audit.SetMeta so geo + tenant enrichment
// isn't clobbered. Takes a plain context (not HandlerContext) — this is an
// SDK-level operation, not necessarily tied to an inbound HTTP request.
func (s *Server) auditTenantTokensRevoked(ctx context.Context, tenantID string, count int) {
	if s.auditor == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventTenantTokensRevoked,
		Outcome:   audit.OutcomeSuccess,
		ActorID:   tenantID,
		Timestamp: time.Now(),
	}
	audit.SetMeta(e, "refresh_tokens_revoked", strconv.Itoa(count))
	s.auditor.Record(ctx, e)
}

// DefaultTenantSuspensionCacheTTL bounds how long a tenant's
// suspension state may be cached between lookups. Short enough that
// a Suspended → Active or Active → Suspended flip propagates
// promptly across the fleet; long enough that hot-path token
// validation doesn't hammer the tenant store on every request.
const DefaultTenantSuspensionCacheTTL = 30 * time.Second

// ErrTenantSuspended is returned by Validate when the token's
// owning client belongs to a tenant whose Status is Suspended.
// Resource paths map this to invalid_token; introspect maps it to
// inactive — same shape every other validation failure produces, so
// an attacker can't probe "is this tenant suspended?" by inspecting
// the error.
var ErrTenantSuspended = errors.New("sso: tenant suspended")

// suspensionCacheEntry pairs a tenant's suspended state with its
// freshness deadline. Caching the boolean lets the hot path skip the
// tenant.Store round-trip on every token validation.
type suspensionCacheEntry struct {
	suspended bool
	expiresAt time.Time
}

// suspensionCache is a tiny TTL map indexed by tenant ID. Sized for
// the typical tens-to-low-thousands of tenants; if you need more,
// swap to an LRU. Reads take RLock so they don't contend on the hot
// validate path.
type suspensionCache struct {
	mu      sync.RWMutex
	entries map[string]suspensionCacheEntry
	ttl     time.Duration
}

func newSuspensionCache(ttl time.Duration) *suspensionCache {
	return &suspensionCache{
		entries: make(map[string]suspensionCacheEntry),
		ttl:     ttl,
	}
}

func (c *suspensionCache) get(tenantID string) (suspended bool, fresh bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[tenantID]
	if !ok {
		return false, false
	}
	if time.Now().After(e.expiresAt) {
		return false, false
	}
	return e.suspended, true
}

func (c *suspensionCache) put(tenantID string, suspended bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tenantID] = suspensionCacheEntry{
		suspended: suspended,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *suspensionCache) invalidate(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenantID)
}

// WithTenantSuspensionCheck enables a post-validation gate: every
// token whose owning client is bound to a tenant
// (Client.TenantID != "") has the tenant's Status looked up; tokens
// whose tenant is Suspended fail validation. Combined with the
// existing tenant_mismatch gate at issuance, this closes the gap
// where a token issued while the tenant was Active continues to
// work after suspension.
//
// Lookups are cached per tenant ID for ttl (default
// DefaultTenantSuspensionCacheTTL when ttl <= 0). A tenant store
// outage is treated as fail-open — the request proceeds with the
// cached value (or no check, if the cache hasn't seen this tenant
// yet) — because we'd rather serve stale-Active than 401 every
// request during a tenant store partition.
//
// No-op when no tenant store has been wired via [WithTenantStore].
func WithTenantSuspensionCheck(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl <= 0 {
			ttl = DefaultTenantSuspensionCacheTTL
		}
		s.tenantSuspensionEnabled = true
		s.tenantSuspensionCache = newSuspensionCache(ttl)
	}
}

// InvalidateTenantSuspensionCache clears the cached suspension state
// for tenantID. Wire this into admin SetStatus handlers so that an
// operator flipping Suspended → Active or Active → Suspended takes
// effect on the next validate, not after the TTL expires.
//
// When an invalidation bus is wired ([WithInvalidationBus]), this also
// publishes the change so every other replica clears its local cache
// too — closing the cross-replica window where a just-suspended tenant
// is still honored elsewhere until that node's TTL elapses. Publish
// failures are logged, not propagated: the local invalidation already
// succeeded and peers fall back to their TTL, matching the suspension
// check's fail-open design.
//
// Safe to call when no cache is configured (no-op).
func (s *Server) InvalidateTenantSuspensionCache(tenantID string) {
	if s.tenantSuspensionCache != nil {
		s.tenantSuspensionCache.invalidate(tenantID)
	}
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: tenantID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", tenantID, "error", err)
		}
	}
}

// StartInvalidationBus begins consuming cross-replica invalidation
// Events on this replica. Call it once with the process run context;
// the returned channel closes when the subscriber goroutine exits (ctx
// cancelled or bus closed), mirroring netpolicy Classifier.Start so cmd
// can coordinate shutdown the same way.
//
// No-op when no bus is wired: returns an already-closed channel and a
// nil error so callers may invoke it unconditionally.
func (s *Server) StartInvalidationBus(ctx context.Context) (<-chan struct{}, error) {
	done := make(chan struct{})
	if s.invalidationBus == nil {
		close(done)
		return done, nil
	}
	events, err := s.invalidationBus.Subscribe(ctx)
	if err != nil {
		close(done)
		return done, err
	}
	go func() {
		defer close(done)
		for evt := range events {
			s.applyInvalidation(evt)
		}
	}()
	return done, nil
}

// ErrCIBANotEnabled is returned by ResolveBackchannelAuthRequest when no
// CIBA store is wired (WithCIBA not configured). It is an SDK-level
// sentinel, not a wire error code.
var ErrCIBANotEnabled = errors.New("sso: CIBA is not enabled")

// cibaPingDeliveryTimeout bounds the detached ping goroutine spawned on
// resolution. The request that triggered the approval has already returned,
// so the goroutine runs on context.Background() with NO inherited deadline —
// without this bound a hanging/never-returning custom notifier would leak the
// goroutine forever. Deliberately set LONGER than the reference
// httpCIBAPingNotifier's own 5s HTTP client timeout so the transport's timeout
// fires first on the common path (yielding a clean error, not a context
// cancellation), while a custom notifier that ignores ctx still gets bounded.
const cibaPingDeliveryTimeout = 10 * time.Second

// ResolveBackchannelAuthRequest transitions a pending CIBA request to
// approved or denied and, in ping delivery mode, notifies the client.
// Operators call this from their device-confirmation callback instead of
// poking CIBAStore.SetStatus directly, so the ping fires automatically on
// resolution.
//
// The status transition is authoritative (the client's /token poll mints
// or refuses tokens off it). The ping is best-effort: when a
// CIBAPingNotifier is wired (WithCIBAPingNotifier) and the request
// carries a client_notification_token (ping mode), it fires asynchronously
// — a failed ping is logged, not returned, since the client can still
// poll. Poll-only requests (no notifier or no token) just transition.
//
// Returns ErrCIBANotEnabled if CIBA isn't wired, or the store's error for
// an unknown/expired (oauth.ErrCIBARequestNotFound) or already-resolved
// (oauth.ErrCIBARequestResolved) request.
func (s *Server) ResolveBackchannelAuthRequest(ctx context.Context, authReqID string, approved bool) error {
	if s.cibaStore == nil {
		return ErrCIBANotEnabled
	}
	// Read before transition so a racing /token poll that consumes +
	// deletes the entry can't strip the notification token from under us.
	req, err := s.cibaStore.Get(ctx, authReqID)
	if err != nil {
		return err
	}
	status := oauth.CIBADenied
	if approved {
		status = oauth.CIBAApproved
	}
	if err := s.cibaStore.SetStatus(ctx, authReqID, status); err != nil {
		return err
	}
	if s.cibaPingNotifier != nil && req.ClientNotificationToken != "" {
		clientID, token := req.ClientID, req.ClientNotificationToken
		// Fire-and-forget so the operator's resolution callback (and the
		// /token poll it races) never waits on the ping — the status
		// transition above is already authoritative. deliverCIBAPing supervises
		// the call (bounded timeout + recover + metric/audit on failure) so a
		// hanging webhook can't leak this goroutine and a panicking custom
		// notifier can't die silently.
		go s.deliverCIBAPing(clientID, authReqID, token)
	}
	return nil
}

// deliverCIBAPing supervises a single detached CIBA ping delivery. It is the
// body of the goroutine spawned by ResolveBackchannelAuthRequest, extracted so
// the timeout + recover + metric/audit wrapper is unit-testable in isolation.
//
// Hardening over the original bare `go n.Notify(context.Background(), ...)`:
//   - Bounded context: a hanging/never-returning notifier can no longer leak
//     this goroutine indefinitely (cibaPingDeliveryTimeout).
//   - recover(): a panicking custom notifier is contained here — it logs +
//     audits + counts an error instead of taking down the goroutine (and
//     potentially the process) with no trace.
//   - Observability: every outcome increments sso_ciba_ping_total{outcome};
//     failures (error return OR recovered panic) also emit a ciba_ping_failed
//     audit event so operators can see WHICH client's ping failed.
//
// The ping is best-effort by contract (the client can still poll), so a failure
// is logged + recorded, never surfaced — there is no caller to return to.
func (s *Server) deliverCIBAPing(clientID, authReqID, token string) {
	// recover() so a panic in a third-party notifier can't crash the goroutine
	// silently (or escalate to a process-wide crash on an unrecovered panic in
	// a bare goroutine). On recovery, treat it as a delivery failure.
	defer func() {
		if r := recover(); r != nil {
			reason := fmt.Sprintf("panic: %v", r)
			s.logger.Error("ciba ping notification panicked", "auth_req_id", authReqID, "client_id", clientID, "panic", r)
			s.recordCIBAPingFailure(clientID, authReqID, reason)
		}
	}()

	// context.Background() is the correct PARENT here (the request that
	// triggered the approval has returned, so there is no live request ctx to
	// inherit — inheriting one would cancel the ping immediately). We ADD a
	// deadline so a notifier that blocks past the bound is unblocked and the
	// goroutine returns.
	ctx, cancel := context.WithTimeout(context.Background(), cibaPingDeliveryTimeout)
	defer cancel()

	if err := s.cibaPingNotifier.Notify(ctx, clientID, authReqID, token); err != nil {
		s.logger.Error("ciba ping notification failed", "auth_req_id", authReqID, "client_id", clientID, "error", err)
		s.recordCIBAPingFailure(clientID, authReqID, err.Error())
		return
	}
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("success").Inc()
	}
}

// recordCIBAPingFailure is the shared error tail for deliverCIBAPing: bump the
// error metric + emit the ciba_ping_failed audit event. Detached goroutine, so
// it audits over context.Background() via the background-context recorder helper
// (mirrors the signing-key aggregation degraded/recovered events).
func (s *Server) recordCIBAPingFailure(clientID, authReqID, reason string) {
	if s.metrics != nil {
		s.metrics.CIBAPingTotal.WithLabelValues("error").Inc()
	}
	audit.RecordCIBAPingFailed(s.auditor, context.Background(), clientID, authReqID, reason)
}

// applyInvalidation clears the local cache a received Event targets. It
// MUST NOT re-publish — only the originating admin mutation publishes,
// so receivers clearing their cache here can't trigger a fan-out loop.
func (s *Server) applyInvalidation(evt cluster.Event) {
	switch evt.Kind {
	case cluster.KindTenantSuspension:
		if s.tenantSuspensionCache != nil {
			s.tenantSuspensionCache.invalidate(evt.Key)
		}
	case cluster.KindTenantResidency:
		if s.tenantResidencyCache != nil {
			s.tenantResidencyCache.invalidate(evt.Key)
		}
	case cluster.KindDiscoveryReload:
		s.invalidateDiscoveryCaches()
	case cluster.KindAuthzPolicyChange:
		// evt.Key is the clientID whose role definitions changed; drop this
		// replica's cached bundle so the sidecar's next pull re-renders.
		s.invalidateAuthzPolicyBundleCacheLocal(evt.Key)
	default:
		// Unknown kind from a newer peer — ignore rather than error, so a
		// mixed-version cluster degrades gracefully during a rollout.
	}
}

// checkTenantNotSuspended is the post-validation gate. Returns nil
// when the token is allowed to proceed (no tenant binding, no store,
// store unreachable, or tenant active) and ErrTenantSuspended when
// the token's tenant has been suspended.
func (s *Server) checkTenantNotSuspended(ctx context.Context, claims *TokenClaims) error {
	if !s.tenantSuspensionEnabled {
		return nil
	}
	if s.tenantStore == nil || s.clientStore == nil {
		return nil
	}
	if claims == nil || claims.ClientID == "" {
		return nil
	}
	client, err := s.clientStore.Get(ctx, claims.ClientID)
	if err != nil || client == nil || client.TenantID == "" {
		// Unknown client or unbound client — nothing to gate on.
		return nil
	}
	if s.tenantSuspensionCache != nil {
		if suspended, fresh := s.tenantSuspensionCache.get(client.TenantID); fresh {
			if suspended {
				return ErrTenantSuspended
			}
			return nil
		}
	}
	t, err := s.tenantStore.GetTenant(ctx, client.TenantID)
	if err != nil || t == nil {
		// Fail open on store outage; don't 401 the world.
		return nil
	}
	suspended := t.Status == tenant.StatusSuspended
	if s.tenantSuspensionCache != nil {
		s.tenantSuspensionCache.put(client.TenantID, suspended)
	}
	if suspended {
		return ErrTenantSuspended
	}
	return nil
}

// DefaultTenantResidencyCacheTTL bounds how long a tenant's resolved
// ResidencyPolicy may be cached between lookups. Mirrors the
// suspension-cache TTL rationale: short enough that a policy edit
// (HomeRegion / AllowedRegions / EnforceWrites) propagates promptly across
// the fleet, long enough that hot-path enforcement doesn't hammer the
// tenant store on every request.
const DefaultTenantResidencyCacheTTL = 60 * time.Second

// residencyCacheEntry pairs a tenant's resolved residency policy with its
// freshness deadline. Caching the value-typed policy lets the enforcement
// path skip the tenant.Store round-trip on every check.
type residencyCacheEntry struct {
	policy    region.ResidencyPolicy
	expiresAt time.Time
}

// residencyCache is a tiny TTL map indexed by tenant ID, sized for the
// typical tens-to-low-thousands of tenants (swap to an LRU if you need
// more). Reads take RLock so they don't contend on the enforcement path.
// Mirrors suspensionCache exactly, caching a ResidencyPolicy instead of a
// suspended bool.
type residencyCache struct {
	mu      sync.RWMutex
	entries map[string]*residencyCacheEntry
	ttl     time.Duration
}

func (c *residencyCache) get(tenantID string) (region.ResidencyPolicy, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[tenantID]
	if !ok {
		return region.ResidencyPolicy{}, false
	}
	if time.Now().After(e.expiresAt) {
		return region.ResidencyPolicy{}, false
	}
	return e.policy, true
}

func (c *residencyCache) put(tenantID string, policy region.ResidencyPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tenantID] = &residencyCacheEntry{
		policy:    policy,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *residencyCache) invalidate(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenantID)
}

// WithTenantResidencyCheck enables the data-residency enforcement engine:
// a tenant's ResidencyPolicy (derived from its HomeRegion / AllowedRegions
// / EnforceWrites fields) is consulted via [Server.checkTenantResidency] to
// decide whether the serving region may handle a given tenant-bound
// request. A serving region outside the tenant's AllowedRegions yields
// region.ErrRegionNotAllowed; a write that would land outside HomeRegion
// under EnforceWrites yields region.ErrResidencyViolation.
//
// Lookups are cached per tenant ID for ttl (default
// DefaultTenantResidencyCacheTTL when ttl <= 0). Like the suspension
// check, a tenant store outage is treated as FAIL-OPEN — residency is an
// AP/governance control, not a security CP invariant, so a store partition
// must not block the world.
//
// The cache is allocated ONLY here, so a server that never calls this
// option keeps tenantResidencyCache nil and behaves byte-identically to a
// pre-residency build. checkTenantResidency is not yet wired into any
// handler in this commit — the middleware + login gate that call it land
// in a follow-up; until then the engine is defined-but-inert.
func WithTenantResidencyCheck(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl <= 0 {
			ttl = DefaultTenantResidencyCacheTTL
		}
		s.tenantResidencyEnabled = true
		s.tenantResidencyCache = &residencyCache{
			entries: make(map[string]*residencyCacheEntry),
			ttl:     ttl,
		}
	}
}

// checkTenantResidency is the data-residency enforcement gate. It decides
// whether servingRegion may handle a request for tenantID (a write when
// isWrite). Returns nil when the request is allowed, region.ErrRegionNotAllowed
// when the serving region is outside the tenant's AllowedRegions, or
// region.ErrResidencyViolation when a write would leave the home region
// under EnforceWrites.
//
// Decision order (each early-return is its own "unconstrained" gate):
//
//  1. not enabled / no serving region / no tenant → nil (byte-identical,
//     unconstrained — region is a routing signal, absence means anywhere).
//  2. tenant store outage → nil (FAIL-OPEN — see below).
//  3. empty HomeRegion → nil (tenant set no residency anchor).
//  4. servingRegion == HomeRegion → nil (home is always allowed).
//  5. AllowedRegions non-empty AND servingRegion not in it →
//     ErrRegionNotAllowed.
//  6. isWrite AND EnforceWrites AND servingRegion != HomeRegion →
//     ErrResidencyViolation.
//  7. else → nil.
//
// FAIL-OPEN rationale: residency is an AP/governance control, NOT a
// security CP invariant. A tenant-store partition must not 4xx every
// tenant-bound request across the fleet — we'd rather serve a request in a
// possibly-non-home region for the brief outage window than take the
// service down. This mirrors checkTenantNotSuspended's fail-open exactly
// (an unreachable tenant store, or a not-found tenant, allows the request).
func (s *Server) checkTenantResidency(ctx context.Context, tenantID string, servingRegion region.ID, isWrite bool) error {
	if !s.tenantResidencyEnabled || servingRegion == "" || tenantID == "" {
		return nil
	}

	policy, ok := region.ResidencyPolicy{}, false
	if s.tenantResidencyCache != nil {
		policy, ok = s.tenantResidencyCache.get(tenantID)
	}
	if !ok {
		if s.tenantStore == nil {
			return nil
		}
		t, err := s.tenantStore.GetTenant(ctx, tenantID)
		if err != nil || t == nil {
			// Fail open on store outage (or not-found tenant) — don't 4xx the
			// world during a tenant store partition. Matches
			// checkTenantNotSuspended.
			if err != nil && s.logger != nil {
				s.logger.Error("tenant residency check: tenant store lookup failed; failing open",
					"error", err, "tenant", tenantID)
			}
			return nil
		}
		policy = residencyPolicyFromTenant(t)
		if s.tenantResidencyCache != nil {
			s.tenantResidencyCache.put(tenantID, policy)
		}
	}

	if policy.HomeRegion == "" {
		return nil
	}
	if servingRegion == policy.HomeRegion {
		return nil
	}
	if len(policy.AllowedRegions) > 0 && !slices.Contains(policy.AllowedRegions, servingRegion) {
		return region.ErrRegionNotAllowed
	}
	if isWrite && policy.EnforceWrites && servingRegion != policy.HomeRegion {
		return region.ErrResidencyViolation
	}
	return nil
}

// mapResidencyError maps a checkTenantResidency sentinel onto its public
// wire error code for the authorization-response body. The two residency
// sentinels stay DISTINCT governance codes — region_not_allowed and
// residency_violation reveal a tenant's data-residency binding exactly the
// way tenant_mismatch reveals tenant binding, so collapsing them to a generic
// access_denied would only blur an operator-facing governance signal, NOT
// close any credential-oracle (these carry no anti-enumeration concern, §2).
// An unexpected error falls back to access_denied (safe generic) rather than
// leaking an unmapped internal string.
func (s *Server) mapResidencyError(err error) string {
	switch {
	case errors.Is(err, region.ErrRegionNotAllowed):
		return ErrRegionNotAllowed
	case errors.Is(err, region.ErrResidencyViolation):
		return ErrResidencyViolation
	default:
		return ErrAccessDenied
	}
}

// residencyPolicyFromTenant maps a tenant's plain-string residency fields
// into the region.ResidencyPolicy value the enforcement gate operates on.
// tenant/ stays a lower-level package (plain strings); region/ owns the
// typed mapping. Kept separate so it's unit-testable and the cached value
// is the already-typed policy.
func residencyPolicyFromTenant(t *tenant.Tenant) region.ResidencyPolicy {
	var allowed []region.ID
	if len(t.AllowedRegions) > 0 {
		allowed = make([]region.ID, len(t.AllowedRegions))
		for i, r := range t.AllowedRegions {
			allowed[i] = region.ID(r)
		}
	}
	return region.ResidencyPolicy{
		HomeRegion:     region.ID(t.HomeRegion),
		AllowedRegions: allowed,
		EnforceWrites:  t.EnforceWrites,
	}
}

// InvalidateTenantResidencyCache clears the cached residency policy for
// tenantID. Wire this into admin handlers that mutate a tenant's
// HomeRegion / AllowedRegions / EnforceWrites so the change takes effect on
// the next enforcement check, not after the TTL expires.
//
// When an invalidation bus is wired ([WithInvalidationBus]), this also
// publishes the change so every other replica clears its local cache too —
// closing the cross-replica window where a stale residency policy is still
// honored elsewhere until that node's TTL elapses. Publish failures are
// logged, not propagated: the local invalidation already succeeded and
// peers fall back to their TTL, matching the residency check's fail-open
// design. Mirrors InvalidateTenantSuspensionCache exactly.
//
// Safe to call when no cache is configured (no-op).
func (s *Server) InvalidateTenantResidencyCache(tenantID string) {
	if s.tenantResidencyCache != nil {
		s.tenantResidencyCache.invalidate(tenantID)
	}
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindTenantResidency, Key: tenantID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", tenantID, "error", err)
		}
	}
}

// maybeEncryptIDToken applies OIDC ID Token encryption when the client
// registered an id_token_encrypted_response_alg. It returns the value
// to place in the response and whether emission is safe.
//
//   - Client opted out (empty alg): returns (signed, true) — the plain
//     signed JWS is emitted unchanged.
//   - Client opted in AND encryption succeeds: returns (jwe, true) —
//     the nested JWE(JWS(...)) is emitted.
//   - Client opted in but no encrypter is wired OR encryption fails
//     (missing/unusable RP enc key, crypto failure): returns ("",
//     false) — FAIL CLOSED. The caller MUST omit id_token rather than
//     leak a cleartext token a client explicitly asked to have
//     encrypted. The missing-key vs crypto-failure distinction never
//     reaches the wire (a single omission).
func (s *Server) maybeEncryptIDToken(ctx context.Context, client *Client, signed string) (string, bool) {
	if client == nil || client.IDTokenEncryptedResponseAlg == "" {
		return signed, true
	}
	if s.jweResponseEncrypter == nil {
		s.logger.Error("id_token encryption requested but no JWEResponseEncrypter wired; omitting id_token", "client", client.ID)
		return "", false
	}
	enc := client.IDTokenEncryptedResponseEnc
	if enc == "" {
		enc = "A256GCM"
	}
	jwe, err := s.jweResponseEncrypter.Encrypt(ctx, []byte(signed), client.JWKS, client.IDTokenEncryptedResponseAlg, enc)
	if err != nil {
		// Undifferentiated: missing key and crypto failure both land
		// here and both omit the token (no oracle).
		s.logger.Error("id_token encryption failed; omitting id_token", "error", err, "client", client.ID)
		return "", false
	}
	return jwe, true
}
