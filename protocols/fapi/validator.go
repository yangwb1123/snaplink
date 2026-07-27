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

	// ClientAuthMethod is the client-authentication method the caller
	// detected (one of the ClientAuth* constants). Empty means the
	// caller did not classify it (no client-auth check is performed),
	// keeping the field opt-in for callers that only care about
	// sender-constraining.
	ClientAuthMethod string
}

// CheckToken returns the FAPI 2.0 violations for a token issuance.
// Baseline rules checked here: sender-constraining (FAPI 2.0 prohibits
// bearer access tokens, requiring DPoP or mTLS binding) and
// client-authentication (shared-secret auth is prohibited). The caller
// passes SenderConstrained from whichever binding it detected and
// ClientAuthMethod from the detected client-auth method. Order is
// stable (sender-constrained, client-auth) for deterministic audit /
// tests.
func (v *Validator) CheckToken(tc TokenContext) []Violation {
	if !v.Active() {
		return nil
	}
	var vs []Violation
	if !tc.SenderConstrained {
		vs = append(vs, Violation{RuleSenderConstrained, tc.ClientID, "access token must be sender-constrained via DPoP or mTLS; bearer tokens are prohibited"})
	}
	vs = append(vs, v.checkClientAuth(tc.ClientID, tc.ClientAuthMethod)...)
	return vs
}

// CheckClientAuth returns the FAPI 2.0 client-authentication violation
// (if any) for the detected auth method. Exposed separately so a
// caller can run the client-auth rule at a different point than full
// token issuance. Empty method is a no-op (unclassified).
func (v *Validator) CheckClientAuth(clientID, method string) []Violation {
	if !v.Active() {
		return nil
	}
	return v.checkClientAuth(clientID, method)
}

// checkClientAuth implements the RuleClientAuth logic. FAPI 2.0 §5.3.2
// permits only asymmetric client authentication: private_key_jwt or
// mTLS. Shared-secret methods (client_secret_basic / _post) and `none`
// are violations.
func (v *Validator) checkClientAuth(clientID, method string) []Violation {
	switch method {
	case "", ClientAuthPrivateKeyJWT, ClientAuthTLS, ClientAuthSelfSignedTLS:
		// Empty = unclassified (skip); the rest are compliant.
		return nil
	}
	return []Violation{{RuleClientAuth, clientID, "client must authenticate via private_key_jwt or mTLS; shared-secret client authentication is prohibited"}}
}

// SigningAlgContext carries the signals for a signing-algorithm check.
type SigningAlgContext struct {
	ClientID           string
	RequestObjectAlg   string // alg of the signed request object (JAR), empty if unsigned
	IDTokenAlg         string // alg of the ID token about to be issued, empty if not an OIDC flow
	ClientAssertionAlg string // alg of the client assertion (private_key_jwt), empty if none
}

// CheckSigningAlg returns violations for any signing algorithm that is NOT
// in the FAPI 2.0 Security Profile approved list. RSA-based algorithms
// (RS256, RS384, RS512, PS256, PS384, PS512) are prohibited; only ECDSA
// and EdDSA are permitted. An empty alg is silently skipped (not checked)
// so callers with no signing context can pass through without noise.
func (v *Validator) CheckSigningAlg(sc SigningAlgContext) []Violation {
	if !v.Active() {
		return nil
	}
	var vs []Violation
	// Check the request object signing alg (JAR).
	if sc.RequestObjectAlg != "" && !IsFAPIAllowedAlg(sc.RequestObjectAlg) {
		vs = append(vs, Violation{
			RuleID:   RuleSigningAlg,
			ClientID: sc.ClientID,
			Detail:   "request object signing algorithm " + sc.RequestObjectAlg + " is not FAPI 2.0 compliant; use ES256, ES384, ES512, or EdDSA",
		})
	}
	// Check the ID token signing alg.
	if sc.IDTokenAlg != "" && !IsFAPIAllowedAlg(sc.IDTokenAlg) {
		vs = append(vs, Violation{
			RuleID:   RuleSigningAlg,
			ClientID: sc.ClientID,
			Detail:   "ID token signing algorithm " + sc.IDTokenAlg + " is not FAPI 2.0 compliant; use ES256, ES384, ES512, or EdDSA",
		})
	}
	// Check the client assertion signing alg (private_key_jwt).
	if sc.ClientAssertionAlg != "" && !IsFAPIAllowedAlg(sc.ClientAssertionAlg) {
		vs = append(vs, Violation{
			RuleID:   RuleSigningAlg,
			ClientID: sc.ClientID,
			Detail:   "client assertion signing algorithm " + sc.ClientAssertionAlg + " is not FAPI 2.0 compliant; use ES256, ES384, ES512, or EdDSA",
		})
	}
	return vs
}

// CIBAContext carries CIBA-specific signals for FAPI compliance checking.
type CIBAContext struct {
	ClientID         string
	DeliveryMode     string // poll, ping, or push
	UserCodeRequired bool
}

// CheckCIBA returns violations when the CIBA backchannel delivery mode is
// not push in FAPI 2.0 enforce mode. Only push mode (where the IdP pushes
// the authorization result to the RP's registered notification endpoint)
// satisfies the FAPI 2.0 requirement for direct, authenticated notification.
func (v *Validator) CheckCIBA(cc CIBAContext) []Violation {
	if !v.Active() {
		return nil
	}
	var vs []Violation
	if cc.DeliveryMode != "" && cc.DeliveryMode != "push" {
		vs = append(vs, Violation{
			RuleID:   RuleCIBAPushMode,
			ClientID: cc.ClientID,
			Detail:   "CIBA backchannel delivery mode must be 'push'; got '" + cc.DeliveryMode + "' which is not FAPI 2.0 compliant",
		})
	}
	return vs
}

// AllowedAlgValues returns the signing algorithm values that are compliant
// with the current FAPI mode. In enforce mode, only FAPI-approved algs
// (ES256, ES384, ES512, EdDSA) are returned. In inspection or off mode,
// all algs are returned (the caller's full set) — inspection audits
// violations but does not narrow the discovery doc.
// This is a HELPER for discovery doc construction, not a validation method.
func (v *Validator) AllowedAlgValues(all []string) []string {
	if !v.Enforcing() {
		return all
	}
	set := FAPIAllowedAlgSet()
	filtered := make([]string, 0, len(all))
	for _, a := range all {
		if _, ok := set[a]; ok {
			filtered = append(filtered, a)
		}
	}
	return filtered
}

// AllowedClientAuthMethods returns the client-authentication methods that
// are compliant with the current FAPI mode. In enforce mode, only
// asymmetric methods (private_key_jwt, tls_client_auth) are permitted.
// In inspection or off mode, all methods are returned unchanged.
func (v *Validator) AllowedClientAuthMethods(all []string) []string {
	if !v.Enforcing() {
		return all
	}
	// In enforce mode, narrow to asymmetric methods only.
	set := make(map[string]struct{}, len(FAPIAllowedClientAuthMethods))
	for _, m := range FAPIAllowedClientAuthMethods {
		set[m] = struct{}{}
	}
	filtered := make([]string, 0, len(all))
	for _, m := range all {
		if _, ok := set[m]; ok {
			filtered = append(filtered, m)
		}
	}
	return filtered
}
