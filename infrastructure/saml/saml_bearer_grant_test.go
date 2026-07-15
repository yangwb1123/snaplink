package saml_test

// BearerAssertionValidator previously accepted a completely UNSIGNED,
// attacker-forged RFC 7522 assertion as long as it was structurally
// well-formed (Bearer SubjectConfirmation + unexpired Conditions). Nothing
// pinned the assertion to a trusted IdP signing key and AudienceRestriction
// was never checked, so anyone who could reach /token could mint their own
// "SAML assertion" for any NameID and receive a real access token. These
// tests exercise the XML-DSig signature verification and AudienceRestriction
// check that close that gap (unsigned / untrusted-signer / tampered /
// wrong-audience assertions rejected; a genuinely IdP-signed, correctly
// audienced one accepted).

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	samlmod "github.com/snaplink/sso/saml"
	"github.com/snaplink/sso/shared/core"
)

const bearerAudience = "https://sso.example.com/token"

// newBearerHandlerContext builds a bare HandlerContext suitable for calling
// ValidateAssertion directly (no server/router involved).
func newBearerHandlerContext() core.HandlerContext {
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	w := httptest.NewRecorder()
	return core.NewContext(w, r)
}

// buildBearerAssertion constructs an RFC 7522 bearer assertion (NOT wrapped
// in a samlp:Response -- the grant transports a bare <Assertion>).
func buildBearerAssertion(nameID, issuer, audience string) *crewjam.Assertion {
	now := time.Now()
	return &crewjam.Assertion{
		ID:           "id-" + randHex(),
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       crewjam.Issuer{Value: issuer},
		Subject: &crewjam.Subject{
			NameID: &crewjam.NameID{Format: string(crewjam.EmailAddressNameIDFormat), Value: nameID},
			SubjectConfirmations: []crewjam.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &crewjam.SubjectConfirmationData{
					NotOnOrAfter: now.Add(5 * time.Minute),
				},
			}},
		},
		Conditions: &crewjam.Conditions{
			NotBefore:    now.Add(-time.Minute),
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []crewjam.AudienceRestriction{{
				Audience: crewjam.Audience{Value: audience},
			}},
		},
	}
}

// unsignedBearerAssertionBytes serializes a (deliberately unsigned) assertion
// element exactly as it would appear as the RFC 7522 "assertion" parameter
// before base64 encoding.
func unsignedBearerAssertionBytes(t *testing.T, a *crewjam.Assertion) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(a.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return raw
}

// signedBearerAssertionBytes signs a with signer's key (goxmldsig enveloped
// signature, mirroring saml_test.go's mintSignedResponse) and returns the
// serialized, signed, standalone <Assertion> element.
func signedBearerAssertionBytes(t *testing.T, a *crewjam.Assertion, signer *idpKey) []byte {
	t.Helper()
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("signing context: %v", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"); err != nil {
		t.Fatalf("set sig method: %v", err)
	}
	signedEl, err := ctx.SignEnveloped(a.Element())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signedEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return raw
}

func toB64(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }

// newTrustedValidator builds a validator trusting signer's cert for bearerAudience.
func newTrustedValidator(t *testing.T, signer *idpKey) *samlmod.BearerAssertionValidator {
	t.Helper()
	v, err := samlmod.NewBearerAssertionValidator(samlmod.BearerAssertionValidatorConfig{
		TrustedCertificates: [][]byte{signer.certPEM()},
		Audience:            bearerAudience,
	})
	if err != nil {
		t.Fatalf("NewBearerAssertionValidator: %v", err)
	}
	return v
}

// TestBearerAssertionValidator_RejectsUnsignedForgedAssertion is the
// vulnerability-demonstrating case: an attacker-supplied, completely unsigned
// assertion must never authenticate, no matter how well-formed it is.
func TestBearerAssertionValidator_RejectsUnsignedForgedAssertion(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	forged := buildBearerAssertion("attacker@evil.example", "https://not-even-a-real-idp.example", bearerAudience)
	assertionB64 := toB64(unsignedBearerAssertionBytes(t, forged))

	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatalf("SECURITY: unsigned, forged SAML assertion was accepted (subject=%q)", subject)
	}
}

// TestBearerAssertionValidator_RejectsUntrustedSigner proves the signature
// check is pinned to TrustedCertificates, not merely "any signature present":
// an assertion validly signed by a DIFFERENT key must still be rejected.
func TestBearerAssertionValidator_RejectsUntrustedSigner(t *testing.T) {
	trusted := newIDPKey(t)
	attacker := newIDPKey(t)
	v := newTrustedValidator(t, trusted)

	a := buildBearerAssertion("attacker@evil.example", "https://attacker-idp.example", bearerAudience)
	assertionB64 := toB64(signedBearerAssertionBytes(t, a, attacker))

	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatalf("SECURITY: assertion signed by an untrusted key was accepted (subject=%q)", subject)
	}
}

// TestBearerAssertionValidator_RejectsTamperedAssertion proves the validator
// parses fields from the SIGNED content, not from a second independent parse
// of attacker-controlled bytes: a validly-signed assertion whose NameID is
// mutated after signing must fail (the signature no longer covers the
// modified content).
func TestBearerAssertionValidator_RejectsTamperedAssertion(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	raw := signedBearerAssertionBytes(t, a, signer)

	tampered := strings.Replace(string(raw), "alice@example.com", "attacker@evil.example", 1)
	if tampered == string(raw) {
		t.Fatal("test bug: NameID substring not found to tamper")
	}
	assertionB64 := toB64([]byte(tampered))

	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatalf("SECURITY: tampered post-signature assertion was accepted (subject=%q)", subject)
	}
}

// TestBearerAssertionValidator_RejectsWrongAudience proves the
// AudienceRestriction gate: a validly-signed assertion naming a DIFFERENT
// audience must not authenticate at this token endpoint.
func TestBearerAssertionValidator_RejectsWrongAudience(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", "https://someone-elses-sso.example.com/token")
	assertionB64 := toB64(signedBearerAssertionBytes(t, a, signer))

	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatalf("assertion restricted to a different audience was accepted (subject=%q)", subject)
	}
}

// TestBearerAssertionValidator_RejectsMissingAudienceRestriction proves an
// UNRESTRICTED assertion (no AudienceRestriction at all) is rejected, not
// treated as a wildcard match -- mirrors saml/sp's audienceContains posture.
func TestBearerAssertionValidator_RejectsMissingAudienceRestriction(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	a.Conditions.AudienceRestrictions = nil
	assertionB64 := toB64(signedBearerAssertionBytes(t, a, signer))

	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatalf("assertion with no AudienceRestriction was accepted (subject=%q)", subject)
	}
}

// TestBearerAssertionValidator_AcceptsValidSignedAssertion is the happy path:
// a genuinely IdP-signed assertion naming the configured audience is
// accepted and yields the NameID subject.
func TestBearerAssertionValidator_AcceptsValidSignedAssertion(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	assertionB64 := toB64(signedBearerAssertionBytes(t, a, signer))

	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err != nil {
		t.Fatalf("ValidateAssertion: unexpected error: %v", err)
	}
	if subject != "alice@example.com" {
		t.Fatalf("subject = %q, want alice@example.com", subject)
	}
}

// TestNewBearerAssertionValidator_RequiresTrustedCertificates proves
// construction fails closed when no trust anchor is configured, rather than
// silently producing a validator that can never verify a signature.
func TestNewBearerAssertionValidator_RequiresTrustedCertificates(t *testing.T) {
	_, err := samlmod.NewBearerAssertionValidator(samlmod.BearerAssertionValidatorConfig{
		Audience: bearerAudience,
	})
	if err == nil {
		t.Fatal("expected error when TrustedCertificates is unset")
	}
}

// TestNewBearerAssertionValidator_RequiresAudience proves construction fails
// closed when no audience is configured.
func TestNewBearerAssertionValidator_RequiresAudience(t *testing.T) {
	signer := newIDPKey(t)
	_, err := samlmod.NewBearerAssertionValidator(samlmod.BearerAssertionValidatorConfig{
		TrustedCertificates: [][]byte{signer.certPEM()},
	})
	if err == nil {
		t.Fatal("expected error when Audience is unset")
	}
}

// TestBearerAssertionValidator_RejectsReplayedAssertion is the direct
// regression test for the missing replay-dedup gap: a genuinely IdP-signed,
// correctly-audienced assertion is accepted on its FIRST redemption but must
// be rejected on a SECOND presentation of the exact same bytes, within its
// still-valid window. Before the fix, checkBearerReplay did not exist and
// every check in the pipeline (signature, subject, conditions, audience,
// issuer) passed identically on replay, so the same signed assertion could
// mint an unbounded number of access tokens.
func TestBearerAssertionValidator_RejectsReplayedAssertion(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	assertionB64 := toB64(signedBearerAssertionBytes(t, a, signer))

	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err != nil {
		t.Fatalf("first redemption: unexpected error: %v", err)
	}
	if subject != "alice@example.com" {
		t.Fatalf("first redemption: subject = %q, want alice@example.com", subject)
	}

	_, err = v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatal("SECURITY: the SAME assertion was redeemed for a second access token (replay not rejected)")
	}
}

// TestBearerAssertionValidator_DistinctAssertionsBothAccepted proves the
// replay dedup is keyed by assertion ID, not e.g. by subject or a global
// once-only gate: two DIFFERENT assertions for the same subject must both be
// accepted.
func TestBearerAssertionValidator_DistinctAssertionsBothAccepted(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a1 := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	a2 := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)

	if _, err := v.ValidateAssertion(newBearerHandlerContext(), toB64(signedBearerAssertionBytes(t, a1, signer))); err != nil {
		t.Fatalf("first assertion: unexpected error: %v", err)
	}
	if _, err := v.ValidateAssertion(newBearerHandlerContext(), toB64(signedBearerAssertionBytes(t, a2, signer))); err != nil {
		t.Fatalf("second (distinct) assertion: unexpected error: %v", err)
	}
}

// TestBearerAssertionValidator_RejectsExpiredBearerConfirmationDespiteValidConditions
// is the regression test for the missing SubjectConfirmationData expiry
// check: SAML's bearer profile uses the Bearer SubjectConfirmationData's OWN
// NotOnOrAfter to bound how long a captured assertion may be PRESENTED --
// independent of, and typically tighter than, the assertion's overall
// <Conditions> window. Before the fix, hasBearerSubjectConfirmation checked
// only the Method attribute and never consulted NotBefore/NotOnOrAfter, so an
// assertion whose broader Conditions window was still comfortably valid, but
// whose SPECIFIC bearer confirmation had already lapsed, was accepted anyway
// -- silently widening the bearer presentation window to the (often much
// longer) Conditions window.
func TestBearerAssertionValidator_RejectsExpiredBearerConfirmationDespiteValidConditions(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	// The overall Conditions window is comfortably valid...
	a.Conditions.NotOnOrAfter = time.Now().Add(time.Hour)
	// ...but the bearer confirmation's OWN presentation window already lapsed.
	a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = time.Now().Add(-time.Minute)

	assertionB64 := toB64(signedBearerAssertionBytes(t, a, signer))
	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatalf("SECURITY: assertion accepted despite an EXPIRED bearer SubjectConfirmationData window (subject=%q)", subject)
	}
}

// TestBearerAssertionValidator_RejectsNotYetValidBearerConfirmation proves the
// NotBefore half of the same gate: a bearer confirmation window that has not
// STARTED yet must also be rejected, not just one that has ended.
func TestBearerAssertionValidator_RejectsNotYetValidBearerConfirmation(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotBefore = time.Now().Add(time.Hour)

	assertionB64 := toB64(signedBearerAssertionBytes(t, a, signer))
	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err == nil {
		t.Fatalf("SECURITY: assertion accepted before its bearer SubjectConfirmationData NotBefore (subject=%q)", subject)
	}
}

// TestBearerAssertionValidator_AcceptsLiveBearerConfirmationWindow is the
// accept-path counterpart: a bearer confirmation window that is currently
// live (NotBefore in the past, NotOnOrAfter in the future) must still
// succeed -- proving the fix does not reject a normal, unexpired assertion.
func TestBearerAssertionValidator_AcceptsLiveBearerConfirmationWindow(t *testing.T) {
	signer := newIDPKey(t)
	v := newTrustedValidator(t, signer)

	a := buildBearerAssertion("alice@example.com", "https://idp.example.com", bearerAudience)
	scd := a.Subject.SubjectConfirmations[0].SubjectConfirmationData
	scd.NotBefore = time.Now().Add(-time.Minute)
	scd.NotOnOrAfter = time.Now().Add(time.Minute)

	assertionB64 := toB64(signedBearerAssertionBytes(t, a, signer))
	subject, err := v.ValidateAssertion(newBearerHandlerContext(), assertionB64)
	if err != nil {
		t.Fatalf("ValidateAssertion: unexpected error: %v", err)
	}
	if subject != "alice@example.com" {
		t.Fatalf("subject = %q, want alice@example.com", subject)
	}
}
