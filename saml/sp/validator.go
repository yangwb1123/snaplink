package sp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"time"

	"github.com/crewjam/saml"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/core"
)

// samlAssertionNS is the SAML 2.0 assertion XML namespace. Both <Assertion>
// and <EncryptedAssertion> live here; we count them to enforce the
// single-assertion rule (XSW hardening) before handing off to crewjam.
const samlAssertionNS = "urn:oasis:names:tc:SAML:2.0:assertion"

// ErrAssertionInvalid is the SINGLE error every assertion-validation failure
// collapses to. ProcessAssertion returns ONLY this (never a more specific
// cause) so the caller maps it to one oracle-safe wire code — an attacker
// probing the ACS cannot tell a bad signature from a wrong audience from a
// replay. Its Error() string IS sso.ErrSAMLAssertionInvalid, and callers match
// it with errors.Is. The per-cause detail (crewjam's InvalidResponseError) is
// deliberately DISCARDED here; an operator wanting it for an audit event must
// capture it inside ProcessAssertion, never surface it on the wire.
var ErrAssertionInvalid = errors.New(sso.ErrSAMLAssertionInvalid)

// ProcessAssertion validates a base64-encoded SAML Response (as POSTed to the
// ACS endpoint) and, on success, returns the authenticated subject as an
// sso.AuthResult. relayState is the RelayState form value echoed back by the
// IdP (the provider hint / opaque login state); it is not trusted for any
// security decision here.
//
// Validation pipeline (ALL failures collapse to ErrAssertionInvalid):
//
//  1. base64-decode the SAMLResponse.
//  2. Reject a response carrying more than one assertion (plaintext or
//     encrypted). crewjam's ParseResponse silently returns the FIRST valid
//     assertion among several; an attacker could append a forged second
//     assertion alongside a legitimately-signed one. We refuse multi-assertion
//     responses outright — a defense-in-depth complement to crewjam's
//     reference-URI-based signature resolution.
//  3. crewjam ParseXMLResponse — THE XSW-resistant gate. It resolves the
//     signed element by the DSig SignedInfo Reference URI, verifies the
//     signature against the PINNED IdP cert (from IDPMetadata; never an
//     assertion-embedded cert), and checks Issuer, Destination, Status,
//     Conditions (NotBefore/NotOnOrAfter), SubjectConfirmation Recipient +
//     expiry, and the AudienceRestriction against this SP's EntityID.
//  4. Independent re-assertion of audience, recipient, and expiry — crewjam
//     already enforces these, but re-checking here means this SP's acceptance
//     invariants are explicit and survive any future change to crewjam's
//     defaults (e.g. someone wiring a custom ValidateAudienceRestriction).
//  5. Replay: the AssertionID must not have been seen (within its validity
//     window) on this replica.
//
// On success the AuthResult carries ExternalID=NameID, Provider=Name,
// Attributes (mapped per AttributeMapping), AuthMethods=[AMRSaml].
func (a *SPAuthenticator) ProcessAssertion(ctx context.Context, samlResponseB64, relayState string) (*sso.AuthResult, error) {
	_ = ctx        // reserved for future per-request deadlines on metadata refresh
	_ = relayState // opaque login state; not a security input

	rawXML, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		return nil, ErrAssertionInvalid
	}

	// (2) Single-assertion rule. Count saml:Assertion + saml:EncryptedAssertion
	// elements in the decoded XML; >1 is rejected before crewjam can pick one.
	if n := countAssertions(rawXML); n != 1 {
		return nil, ErrAssertionInvalid
	}

	// (3) crewjam's XSW-resistant signature + condition validation against the
	// pinned cert. currentURL is the SP ACS URL: crewjam compares the Response
	// Destination against it (and/or sp.AcsURL). possibleRequestIDs is empty —
	// the stateless ACS keeps no AuthnRequest-ID store. crewjam runs with
	// AllowIDPInitiated=true (so its un-suppliable ID-list checks don't
	// hard-fail), and the SP's IdP-initiated posture is re-imposed by the
	// ServiceProvider.ValidateRequestID hook installed at construction (which
	// rejects an unsolicited empty-InResponseTo response unless the operator
	// set AllowIDPInitiated). The signature + audience + recipient + expiry
	// gate applies regardless.
	currentURL := a.sp.AcsURL
	assertion, err := a.sp.ParseXMLResponse(rawXML, a.possibleRequestIDs(), currentURL)
	if err != nil {
		// crewjam returns *saml.InvalidResponseError / ErrBadStatus with cause
		// detail; we DISCARD the detail and return the single collapsed error.
		return nil, ErrAssertionInvalid
	}
	if assertion == nil || assertion.Subject == nil || assertion.Subject.NameID == nil {
		return nil, ErrAssertionInvalid
	}

	now := a.clock()

	// (4) Independent re-assertion (defense-in-depth; crewjam already checked
	// these, but we make this SP's acceptance contract explicit).
	if !audienceContains(assertion, a.cfg.EntityID) {
		return nil, ErrAssertionInvalid
	}
	if !recipientMatches(assertion, a.sp.AcsURL.String()) {
		return nil, ErrAssertionInvalid
	}
	if expired(assertion, now) {
		return nil, ErrAssertionInvalid
	}

	// (5) Replay: dedup by AssertionID for as long as the assertion could be
	// validly presented. Use the SubjectConfirmation NotOnOrAfter (the bearer
	// presentation deadline) when present, else the Conditions NotOnOrAfter.
	if id := assertion.ID; id != "" {
		if fresh := a.replay.checkAndRemember(id, replayExpiry(assertion, now), now); !fresh {
			return nil, ErrAssertionInvalid
		}
	}

	return a.assertionToResult(assertion), nil
}

// possibleRequestIDs returns the AuthnRequest IDs the assertion's InResponseTo
// may match. The stateless ACS keeps no per-request store, so this is always
// empty; correlation is enforced (as far as a stateless ACS can) by the
// ValidateRequestID hook plus the content checks (signature/audience/recipient/
// expiry) and RelayState.
func (a *SPAuthenticator) possibleRequestIDs() []string { return nil }

// clock returns the current time via the (test-overridable) seam.
func (a *SPAuthenticator) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// assertionToResult projects a validated assertion onto an sso.AuthResult,
// applying AttributeMapping (SAML attribute Name/FriendlyName -> local key) and
// stamping the SAML AMR.
func (a *SPAuthenticator) assertionToResult(assertion *saml.Assertion) *sso.AuthResult {
	nameID := assertion.Subject.NameID.Value

	attrs := map[string]string{}
	for _, stmt := range assertion.AttributeStatements {
		for _, attr := range stmt.Attributes {
			if len(attr.Values) == 0 {
				continue
			}
			key := a.mapAttr(attr)
			if key == "" {
				continue
			}
			// First value wins for single-valued mapping (the common case:
			// email, name). Multi-valued attributes (groups/roles) keep their
			// first value here; richer multi-value projection is a consumer
			// concern (the AuthResult.Attributes contract is string->string).
			attrs[key] = attr.Values[0].Value
		}
	}

	return &sso.AuthResult{
		UserID:      nameID,
		ExternalID:  nameID,
		Provider:    a.cfg.Name,
		Attributes:  attrs,
		AuthMethods: []string{core.AMRSaml},
	}
}

// mapAttr resolves the local attribute key for a SAML attribute: an explicit
// AttributeMapping entry (keyed by Name, then FriendlyName) wins; otherwise the
// SAML Name passes through (or FriendlyName when Name is empty). An empty
// result means "drop this attribute".
func (a *SPAuthenticator) mapAttr(attr saml.Attribute) string {
	if a.attrMap != nil {
		if local, ok := a.attrMap[attr.Name]; ok {
			return local
		}
		if attr.FriendlyName != "" {
			if local, ok := a.attrMap[attr.FriendlyName]; ok {
				return local
			}
		}
	}
	if attr.Name != "" {
		return attr.Name
	}
	return attr.FriendlyName
}

// countAssertions counts SAML-namespace <Assertion> + <EncryptedAssertion>
// elements anywhere in the decoded response XML, using a streaming stdlib
// decoder (no external dependency, no XML expansion surface beyond the token
// scan). Used to enforce the single-assertion rule before crewjam selects one.
func countAssertions(rawXML []byte) int {
	dec := xml.NewDecoder(bytes.NewReader(rawXML))
	// Refuse external entities / DTD-driven expansion: a nil Entity map plus
	// the default decoder (which does not resolve external DTDs) keeps this a
	// pure structural scan.
	dec.Strict = false
	count := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			break
		}
		if se, ok := tok.(xml.StartElement); ok {
			if se.Name.Space == samlAssertionNS &&
				(se.Name.Local == "Assertion" || se.Name.Local == "EncryptedAssertion") {
				count++
			}
		}
	}
	return count
}

// audienceContains reports whether the assertion's AudienceRestriction names
// the given SP entity ID. An assertion with NO AudienceRestriction is treated
// as NOT matching (we require an explicit audience — an unrestricted assertion
// must not authenticate at a specific SP).
func audienceContains(assertion *saml.Assertion, entityID string) bool {
	if assertion.Conditions == nil {
		return false
	}
	if len(assertion.Conditions.AudienceRestrictions) == 0 {
		return false
	}
	for _, ar := range assertion.Conditions.AudienceRestrictions {
		if ar.Audience.Value == entityID {
			return true
		}
	}
	return false
}

// recipientMatches reports whether every bearer SubjectConfirmationData
// Recipient equals this SP's ACS URL. An assertion with no SubjectConfirmation
// carrying a Recipient is treated as NOT matching.
func recipientMatches(assertion *saml.Assertion, acsURL string) bool {
	if assertion.Subject == nil {
		return false
	}
	matched := false
	for _, sc := range assertion.Subject.SubjectConfirmations {
		if sc.SubjectConfirmationData == nil {
			continue
		}
		if sc.SubjectConfirmationData.Recipient != acsURL {
			// A confirmation pointing at a different recipient is disqualifying.
			return false
		}
		matched = true
	}
	return matched
}

// expired reports whether the assertion is outside its validity window at now,
// checking both the Conditions NotOnOrAfter and every bearer
// SubjectConfirmationData NotOnOrAfter. (No clock-skew slack is added here: the
// SP's own acceptance is deliberately exact; crewjam's prior check already
// applied its MaxClockSkew, so an assertion that passed crewjam by a hair will
// still pass this unless it has since crossed the hard boundary — the
// re-assertion is a backstop, not a second skew window.)
func expired(assertion *saml.Assertion, now time.Time) bool {
	if assertion.Conditions != nil {
		noa := assertion.Conditions.NotOnOrAfter
		if !noa.IsZero() && !now.Before(noa) { // now >= NotOnOrAfter
			return true
		}
		nb := assertion.Conditions.NotBefore
		if !nb.IsZero() && now.Before(nb) {
			return true
		}
	}
	if assertion.Subject != nil {
		for _, sc := range assertion.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData == nil {
				continue
			}
			noa := sc.SubjectConfirmationData.NotOnOrAfter
			if !noa.IsZero() && !now.Before(noa) {
				return true
			}
		}
	}
	return false
}

// replayExpiry picks the time after which the assertion can no longer be
// validly replayed — the earliest of its SubjectConfirmation NotOnOrAfter and
// Conditions NotOnOrAfter. The replay store prunes the AssertionID at that
// point (by then any later presentation fails the expiry check anyway).
func replayExpiry(assertion *saml.Assertion, now time.Time) time.Time {
	var exp time.Time
	consider := func(t time.Time) {
		if t.IsZero() {
			return
		}
		if exp.IsZero() || t.Before(exp) {
			exp = t
		}
	}
	if assertion.Conditions != nil {
		consider(assertion.Conditions.NotOnOrAfter)
	}
	if assertion.Subject != nil {
		for _, sc := range assertion.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil {
				consider(sc.SubjectConfirmationData.NotOnOrAfter)
			}
		}
	}
	if exp.IsZero() {
		// No explicit deadline: keep the ID for a conservative bounded window so
		// it still dedups; the LRU cap evicts it eventually regardless. Use the
		// caller's clock seam (not time.Now()) so the prune stays deterministic
		// under a pinned test clock and never mixes wall-clock with a pinned now.
		exp = now.Add(5 * time.Minute)
	}
	return exp
}
