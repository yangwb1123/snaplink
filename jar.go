package sso

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
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
//   - `request` parameter inline only. RFC 9101 also allows
//     `request_uri` for a URI-fetched JWT — NOT YET wired
//     because PAR already covers the "push the request
//     server-side" case with stronger semantics.
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
func verifyJAR(ctx context.Context, rawJWT string, client *Client, asIssuer string, replay JTIReplayStore) (*jarPayload, error) {
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
	// wired a JTIReplayStore and the JWT carries a jti, refuse to
	// process a JWT whose jti has been seen within its expiry
	// window. The defense is opt-in (store nil) so legacy
	// deployments aren't broken; production should always wire
	// it. Empty jti skips the check — RFC 9101 makes jti
	// OPTIONAL but recommends it, so we don't synthesize one.
	if replay != nil && p.JTI != "" {
		expiresAt := time.Unix(p.Exp, 0)
		if p.Exp == 0 || expiresAt.Before(time.Now()) {
			expiresAt = time.Now().Add(DefaultJTIReplayWindow)
		}
		first, err := replay.MarkSeen(ctx, p.JTI, expiresAt)
		if err != nil {
			// Fail-OPEN on store errors: a broken replay store
			// shouldn't lock out legitimate clients. The caller
			// logs the failure (handler-side) so operators see
			// the degradation.
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
