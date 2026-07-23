// Package fapi implements the FAPI 2.0 Security Profile compliance
// layer as a pure-logic policy seam. It holds the rule set and a
// Validator that, given already-extracted request signals, returns the
// list of baseline violations. The caller (the SSO server) owns the
// integration points (authorization + token issuance) and decides,
// from the configured Mode, whether a violation rejects the request
// (Enforce) or is merely recorded for an operator ramp-up (Inspection).
//
// Why a standalone package: FAPI enforcement is cross-cutting (it
// touches /auth/login, /par, /token) but the decision logic is pure.
// Isolating it here keeps the rules testable without a running server
// and avoids any import cycle — fapi depends on nothing in the root
// sso package.
package fapi

import (
	"encoding/base64"
	"encoding/json"
)

// Mode selects how the Validator's callers treat rule violations.
type Mode int

const (
	// ModeOff disables every check. Callers normally leave the
	// Validator unwired rather than constructing a ModeOff one, but
	// the zero value is safe (no checks, no overhead).
	ModeOff Mode = iota

	// ModeInspection reports violations (the caller emits a
	// fapi_compliance_violation audit event) but lets the request
	// proceed unchanged. This is the deliberate antidote to the FAPI 1
	// adoption failure: a hard all-or-nothing switch is a cliff that
	// breaks every not-yet-migrated RP. Inspection lets an operator
	// collect the per-RP compliance-gap list first, fix RPs, then flip
	// to Enforce.
	ModeInspection

	// ModeEnforce rejects any request that violates a baseline rule.
	ModeEnforce
)

// String renders the mode for logs / discovery / config round-trips.
func (m Mode) String() string {
	switch m {
	case ModeInspection:
		return "inspection"
	case ModeEnforce:
		return "enforce"
	default:
		return "off"
	}
}

// Rule IDs are stable identifiers carried in the
// fapi_compliance_violation audit event (and the rejection's
// error_description). Operators and dashboards branch on these, never
// on the free-text Detail — same contract as wire error codes.
const (
	// RulePARRequired — the authorization request MUST be a pushed
	// authorization request (RFC 9126 PAR); front-channel parameter
	// passing is prohibited (FAPI 2.0 §5.3.1).
	RulePARRequired = "fapi:par_required"

	// RuleSignedRequest — the authorization request parameters MUST be
	// carried in a signed request object (RFC 9101 JAR).
	RuleSignedRequest = "fapi:signed_request"

	// RulePKCES256 — PKCE with code_challenge_method=S256 is required;
	// plain is prohibited.
	RulePKCES256 = "fapi:pkce_s256"

	// RuleNoImplicit — only response_type=code is permitted; implicit
	// and hybrid flows (which return tokens in the front channel) are
	// prohibited.
	RuleNoImplicit = "fapi:no_implicit"

	// RuleSenderConstrained — issued access tokens MUST be
	// sender-constrained via DPoP (RFC 9449) or mTLS (RFC 8705);
	// bearer tokens are prohibited.
	RuleSenderConstrained = "fapi:sender_constrained"

	// RuleClientAuth — confidential clients MUST authenticate with an
	// asymmetric method: private_key_jwt (RFC 7521/7523) or mTLS
	// (RFC 8705). Shared-secret authentication
	// (client_secret_basic / client_secret_post) is prohibited (FAPI
	// 2.0 §5.3.2).
	RuleClientAuth = "fapi:client_auth"

	// RuleSigningAlg — the signing algorithm used for ID tokens, JARM
	// responses, request objects, and client authentication assertions
	// MUST be a FAPI 2.0-approved algorithm. RSA-based algorithms
	// (RS256, RS384, RS512, PS256, PS384, PS512) are prohibited;
	// only ECDSA (ES256, ES384, ES512) and EdDSA are permitted
	// (FAPI 2.0 SP §5.3.3 and FAPI 2.0 Message Signing).
	RuleSigningAlg = "fapi:signing_alg"

	// RuleCIBAPushMode — when CIBA is used in FAPI 2.0 enforce mode,
	// the backchannel token delivery mode MUST be pushed (ping or
	// poll modes are not compliant).
	RuleCIBAPushMode = "fapi:ciba_push_mode"
)

// FAPIAllowedAlgValues returns the set of signing algorithms FAPI 2.0
// Security Profile permits. RSA-based algs (RS256/RS384/RS512/PS256/
// PS384/PS512) are prohibited; only ECDSA and EdDSA are permitted.
// Used to filter discovery doc algorithm lists and validate at runtime.
var FAPIAllowedAlgValues = []string{
	"ES256", "ES384", "ES512",
	"EdDSA",
}

// FAPIAllowedAlgSet returns FAPIAllowedAlgValues as a set for O(1) lookup.
func FAPIAllowedAlgSet() map[string]struct{} {
	s := make(map[string]struct{}, len(FAPIAllowedAlgValues))
	for _, a := range FAPIAllowedAlgValues {
		s[a] = struct{}{}
	}
	return s
}

// IsFAPIAllowedAlg reports whether alg is in the FAPI 2.0 allowlist.
func IsFAPIAllowedAlg(alg string) bool {
	for _, a := range FAPIAllowedAlgValues {
		if a == alg {
			return true
		}
	}
	return false
}

// FAPIAllowedClientAuthMethods returns the client-authentication methods
// FAPI 2.0 Security Profile permits: only asymmetric methods (private_key_jwt
// and tls_client_auth). Used to narrow discovery doc auth method lists.
var FAPIAllowedClientAuthMethods = []string{
	ClientAuthPrivateKeyJWT,
	ClientAuthTLS,
}

// ExtractJWTAlg extracts the `alg` header from a compact JWS string without
// verifying the signature. Returns empty string on any parse failure (not a
// JWS, not JSON, missing alg, or base64 decode error).
func ExtractJWTAlg(compact string) string {
	if compact == "" {
		return ""
	}
	// Compact JWS: header.payload.signature (three dot-separated segments).
	var headerSeg string
	for i, c := range compact {
		if c == '.' {
			if i == 0 {
				return "" // starts with dot
			}
			headerSeg = compact[:i]
			break
		}
	}
	if headerSeg == "" {
		return "" // no dot found — not a compact JWS
	}
	// Base64url decode the header (RFC 4648 §5, no padding).
	decoded, err := base64.RawURLEncoding.DecodeString(headerSeg)
	if err != nil {
		// Try padded base64url as fallback.
		decoded, err = base64.URLEncoding.DecodeString(headerSeg)
		if err != nil {
			return ""
		}
	}
	// Parse the JSON header to extract "alg".
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(decoded, &hdr); err != nil {
		return ""
	}
	return hdr.Alg
}

// Client-authentication method identifiers (OAuth 2.0 token endpoint
// auth methods, RFC 8414). The caller classifies the detected method
// into one of these and passes it to CheckClientAuth.
const (
	ClientAuthNone          = "none"
	ClientAuthSecretBasic   = "client_secret_basic"
	ClientAuthSecretPost    = "client_secret_post"
	ClientAuthPrivateKeyJWT = "private_key_jwt"
	ClientAuthTLS           = "tls_client_auth"
	ClientAuthSelfSignedTLS = "self_signed_tls_client_auth"
)

// Violation is one failed baseline rule for one request. Detail is
// human-facing context for the audit event / error_description; RuleID
// is the stable machine identifier.
type Violation struct {
	RuleID   string
	ClientID string
	Detail   string
}
