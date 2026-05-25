package fapi

import "strings"

// Validator evaluates the FAPI 2.0 Security Profile baseline rules. It
// holds only the Mode; every method takes already-extracted request
// signals and returns the violations it finds, leaving the
// enforce-vs-inspect decision to the caller via Mode / Enforcing.
//
// All methods are nil-safe and ModeOff-safe (return nil), so the
// integration points can call them unconditionally on a possibly-nil
// Validator without a guard at each site.
type Validator struct {
	mode Mode
}

// New returns a Validator for the given mode. A ModeOff validator is
// inert; callers typically pass nil instead, which every method
// tolerates.
func New(mode Mode) *Validator { return &Validator{mode: mode} }

// Mode reports the configured mode (ModeOff for a nil Validator).
func (v *Validator) Mode() Mode {
	if v == nil {
		return ModeOff
	}
	return v.mode
}

// Enforcing reports whether violations should reject the request (as
// opposed to inspection-only auditing). False for a nil / ModeOff /
// ModeInspection validator.
func (v *Validator) Enforcing() bool {
	return v != nil && v.mode == ModeEnforce
}

// Active reports whether any checking happens at all — false for a
// nil / ModeOff validator. Integration points use this to skip
// computing signals when FAPI is not wired.
func (v *Validator) Active() bool {
	return v != nil && v.mode != ModeOff
}

// AuthorizationContext carries the already-extracted signals describing
// an authorization request (/auth/login). The caller populates these
// from its own request parsing; the Validator stays free of any HTTP /
// server types.
type AuthorizationContext struct {
	ClientID            string
	ResponseType        string
	UsedPAR             bool // request arrived via a pushed authorization request_uri
	SignedRequest       bool // parameters were carried in a signed (JAR) request object
	CodeChallenge       string
	CodeChallengeMethod string
}

// CheckAuthorization returns every FAPI 2.0 baseline violation present
// in ac (FAPI 2.0 §5.3.1, authorization request requirements). An empty
// slice means compliant. Order is stable (PAR, signed request, no
// implicit, PKCE) so audit output and tests are deterministic.
func (v *Validator) CheckAuthorization(ac AuthorizationContext) []Violation {
	if !v.Active() {
		return nil
	}
	var vs []Violation
	if !ac.UsedPAR {
		vs = append(vs, Violation{RulePARRequired, ac.ClientID, "authorization request must use a pushed authorization request (PAR)"})
	}
	if !ac.SignedRequest {
		vs = append(vs, Violation{RuleSignedRequest, ac.ClientID, "authorization request parameters must be carried in a signed request object (JAR)"})
	}
	if ac.ResponseType != "code" {
		vs = append(vs, Violation{RuleNoImplicit, ac.ClientID, "response_type must be code; implicit and hybrid flows are prohibited"})
	}
	if ac.CodeChallenge == "" || !strings.EqualFold(ac.CodeChallengeMethod, "S256") {
		vs = append(vs, Violation{RulePKCES256, ac.ClientID, "PKCE with code_challenge_method=S256 is required"})
	}
	return vs
}

// TokenContext carries the already-extracted signals for a token
// request (/token) issuance.
type TokenContext struct {
	ClientID          string
	GrantType         string
	SenderConstrained bool // the issued access token is DPoP- or mTLS-bound
}

// CheckToken returns the FAPI 2.0 violations for a token issuance. The
// sole baseline rule checked here is sender-constraining: FAPI 2.0
// prohibits bearer access tokens, requiring DPoP or mTLS binding. The
// caller passes SenderConstrained from whichever binding it detected.
func (v *Validator) CheckToken(tc TokenContext) []Violation {
	if !v.Active() {
		return nil
	}
	var vs []Violation
	if !tc.SenderConstrained {
		vs = append(vs, Violation{RuleSenderConstrained, tc.ClientID, "access token must be sender-constrained via DPoP or mTLS; bearer tokens are prohibited"})
	}
	return vs
}
