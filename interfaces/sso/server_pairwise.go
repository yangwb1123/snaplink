package sso

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/shared/security"
)

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
//   - Header `typ` MAY be present; if present MUST be "JWT" or
//     "client-authentication+jwt"
//   - Header `alg` MUST be an asymmetric alg (security.AsymmetricJWSAlgs:
//     EdDSA / ES256/384/512 / RS256 / PS256, same set as JAR + DPoP),
//     gated BEFORE signature verify; `alg: none` + symmetric HS* fail
//     closed
//   - Header `kid` selects the verification key from Client.JWKS, whose
//     kty/crv MUST be consistent with the alg
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
// resolveAssertionClient looks up the self-asserted `sub` and validates it's
// usable for private_key_jwt authentication — extracted from
// verifyJWTClientAssertion to stay under the function-length budget. Every
// failure here collapses to the same wire shape as the caller's other
// rejections (invalid_client), so the specific message text is never
// distinguishable on the wire.
func resolveAssertionClient(ctx context.Context, clientStore ClientStore, sub string) (*Client, error) {
	client, err := clientStore.Get(ctx, sub)
	if err != nil || client == nil {
		return nil, errors.New("jwt_client_assertion: client not found")
	}
	if !client.Active {
		// A pending (not-yet-approved) or deactivated client MUST NOT
		// authenticate via private_key_jwt just because ValidateSecret's
		// Active gate (the OTHER client-auth path) doesn't run this path.
		return nil, errors.New("jwt_client_assertion: client inactive")
	}
	if len(client.JWKS) == 0 {
		return nil, errors.New("jwt_client_assertion: client has no registered JWKS")
	}
	return client, nil
}

func verifyJWTClientAssertion(ctx context.Context, assertion, formClientID string, clientStore ClientStore, asIssuer string, replay security.JTIReplayStore, replayFailClosed bool) (string, error) {
	if clientStore == nil {
		return "", errors.New("jwt_client_assertion: client store required")
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return "", errors.New("jwt_client_assertion: malformed JWT")
	}
	if err := parseAssertionTypHeader(parts[0]); err != nil {
		return "", err
	}
	p, err := decodeAssertionClaims(parts[1])
	if err != nil {
		return "", err
	}
	if err := validateAssertionClaims(p, formClientID, asIssuer); err != nil {
		return "", err
	}

	// Lookup-then-verify: resolve the self-asserted `sub` to a registered
	// client FIRST, then verify the signature against THAT client's JWKS.
	// This ordering is the auth core and MUST NOT be reordered — an
	// attacker who lies about `sub` simply fails the signature check below.
	client, err := resolveAssertionClient(ctx, clientStore, p.Sub)
	if err != nil {
		return "", err
	}
	// Signature verification through the shared, alg-confusion-safe
	// verifier: asymmetric-allowlist gate BEFORE verify (no alg=none, no
	// HS*), kid-bound key selection against the client's registered
	// JWKS, kty/crv↔alg consistency, EC on-curve, RSA>=2048. Widening
	// past EdDSA to ES*/RS*/PS* is a pure allowlist change here.
	if _, err := security.VerifyCompactJWS(assertion, client.JWKS, security.AsymmetricJWSAlgs()); err != nil {
		return "", fmt.Errorf("jwt_client_assertion: %w", err)
	}

	if err := enforceAssertionReplay(ctx, p, replay, replayFailClosed); err != nil {
		return "", err
	}

	return p.Sub, nil
}

// assertionClaims holds the RFC 7523 §3 payload fields read from the
// UNVERIFIED JWT segment. They MUST NOT drive any security decision
// beyond reaching the self-asserted `sub` used to LOOK UP the client
// (whose registered JWKS then verifies the signature).
type assertionClaims struct {
	Iss string   `json:"iss"`
	Sub string   `json:"sub"`
	Aud audClaim `json:"aud"`
	Exp int64    `json:"exp"`
	Nbf int64    `json:"nbf"`
	Iat int64    `json:"iat"`
	JTI string   `json:"jti"`
}

// parseAssertionTypHeader checks the RFC 7523-specific `typ` JOSE header.
// The `typ` is not VerifyCompactJWS's concern, so it is checked here;
// `alg`, `kid`, the kty/crv↔alg consistency, and the signature are ALL
// owned by VerifyCompactJWS — this reads an UNVERIFIED segment.
func parseAssertionTypHeader(segment string) error {
	hraw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("jwt_client_assertion: header decode: %w", err)
	}
	var h struct {
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(hraw, &h); err != nil {
		return fmt.Errorf("jwt_client_assertion: header parse: %w", err)
	}
	switch h.Typ {
	case "", "JWT", "client-authentication+jwt":
		return nil
	default:
		return fmt.Errorf("jwt_client_assertion: typ %q not supported", h.Typ)
	}
}

// decodeAssertionClaims decodes the UNVERIFIED payload segment into the
// RFC 7523 §3 claim set. No claim here is trusted for a security
// decision beyond the lookup `sub` (see verifyJWTClientAssertion).
func decodeAssertionClaims(segment string) (assertionClaims, error) {
	var p assertionClaims
	praw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return p, fmt.Errorf("jwt_client_assertion: payload decode: %w", err)
	}
	if err := json.Unmarshal(praw, &p); err != nil {
		return p, fmt.Errorf("jwt_client_assertion: payload parse: %w", err)
	}
	return p, nil
}

// validateAssertionClaims enforces the non-cryptographic RFC 7523 §3
// gates (iss/sub, form client_id binding, exp window + max-lifetime
// ceiling, nbf, aud) in the SAME order as the inline original.
func validateAssertionClaims(p assertionClaims, formClientID, asIssuer string) error {
	if p.Sub == "" || p.Sub != p.Iss {
		return errors.New("jwt_client_assertion: iss/sub must be equal and non-empty")
	}
	if formClientID != "" && formClientID != p.Sub {
		return errors.New("jwt_client_assertion: form client_id does not match sub")
	}
	now := time.Now()
	if p.Exp == 0 || now.After(time.Unix(p.Exp, 0)) {
		return errors.New("jwt_client_assertion: expired or missing exp")
	}
	if time.Unix(p.Exp, 0).After(now.Add(DefaultClientAssertionMaxLifetime)) {
		return fmt.Errorf("jwt_client_assertion: exp too far in future (max %s)", DefaultClientAssertionMaxLifetime)
	}
	if p.Nbf != 0 && now.Before(time.Unix(p.Nbf, 0)) {
		return errors.New("jwt_client_assertion: nbf in future")
	}
	if asIssuer != "" && !slices.Contains([]string(p.Aud), asIssuer) {
		return fmt.Errorf("jwt_client_assertion: aud does not include %q", asIssuer)
	}
	return nil
}

// enforceAssertionReplay applies jti replay defense — when wired and the
// JWT carries a jti, refuse any second sighting within its exp window.
// Same store + semantics JAR replay protection uses. A store error
// defaults to fail-OPEN (continue); fail-CLOSED (opt-in) rejects with the
// SAME detected-replay error so the wire shape is identical (no
// store-health oracle).
func enforceAssertionReplay(ctx context.Context, p assertionClaims, replay security.JTIReplayStore, replayFailClosed bool) error {
	if replay == nil || p.JTI == "" {
		return nil
	}
	first, err := replay.MarkSeen(ctx, p.JTI, time.Unix(p.Exp, 0))
	switch {
	case err != nil:
		if replayFailClosed {
			return errors.New("jwt_client_assertion: jti replay detected")
		}
	case !first:
		return errors.New("jwt_client_assertion: jti replay detected")
	}
	return nil
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
//   - Verify the proof JWT: typ=dpop+jwt, an asymmetric alg
//     (security.AsymmetricJWSAlgs: EdDSA / ES256/384/512 / RS256 /
//     PS256 — DPoP is almost always ES256 in the wild), the public
//     jwk in the header, htm=POST, htu=/token, iat in window, jti
//     present.
//   - Compute the JWK thumbprint (RFC 7638) — over the canonical
//     required members PER key type (OKP: crv/kty/x; EC: crv/kty/x/y;
//     RSA: e/kty/n) — and stamp it into the issued access token's
//     `cnf.jkt` claim (RFC 7800).
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
//   - header alg MUST be an asymmetric alg (security.AsymmetricJWSAlgs:
//     EdDSA / ES256/384/512 / RS256 / PS256), gated BEFORE signature
//     verify; `alg: none` + symmetric HS* fail closed
//   - header jwk MUST be a public JWK (OKP/EC/RSA), consistent with the
//     alg, whose private counterpart signed the proof
//   - payload htm MUST equal the request method
//   - payload htu MUST equal the request URL (sans query/fragment)
//   - payload iat MUST be within maxAge (past) / clockSkew (future)
//   - payload jti MUST be present (replay-defense token)
//
// maxAge + clockSkew are the operator-tunable windows resolved from the
// Server (WithDPoPProofMaxAge / WithDPoPMaxClockSkew), defaulting to 60s.
// They are passed in (rather than read from a const) so a deployment whose
// DPoP clients drift beyond 60s can loosen, and a strict one can tighten —
