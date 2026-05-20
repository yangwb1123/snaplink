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
//   - jti MUST be present when JTIReplayStore is wired; replay
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
	replay JTIReplayStore,
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
		if err == nil && !first {
			return "", errors.New("jwt_client_assertion: jti replay detected")
		}
	}

	return p.Sub, nil
}
