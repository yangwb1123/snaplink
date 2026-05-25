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
)

// Violation is one failed baseline rule for one request. Detail is
// human-facing context for the audit event / error_description; RuleID
// is the stable machine identifier.
type Violation struct {
	RuleID   string
	ClientID string
	Detail   string
}
