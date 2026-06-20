package idp

import (
	"encoding/base64"
	"fmt"
	"sort"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"github.com/snaplink/sso/interfaces/sso"
)

// DefaultAssertionTTL is the validity window stamped onto a minted assertion
// (Conditions.NotOnOrAfter + the bearer SubjectConfirmation NotOnOrAfter). 5
// minutes is the SAML-conventional short bearer window: long enough for the
// browser to POST the auto-submit form to the SP, short enough that a captured
// assertion is useless almost immediately (the SP also dedups by AssertionID).
const DefaultAssertionTTL = 5 * time.Minute

// assertionClockSkew is the small backdating applied to NotBefore /
// IssueInstant so an SP whose clock trails this IdP by a few seconds does not
// reject a just-minted assertion as not-yet-valid. It does NOT extend the
// forward validity (NotOnOrAfter is still now+TTL) — it only softens the lower
// bound, mirroring crewjam's MaxClockSkew usage in its reference IdP.
const assertionClockSkew = 1 * time.Minute

// BuildResponse constructs a base64-encoded SAML Response whose nested
// Assertion is XML-DSig signed (enveloped, exclusive-C14N, SHA-256) with the
// per-tenant key behind signer. It returns the base64 SAMLResponse the
// /saml/sso/finish auto-POST form carries to the SP's REGISTERED ACS.
//
// SECURITY-CRITICAL invariants (all enforced here):
//
//   - The ASSERTION is signed, not merely the Response. saml/sp (and most SPs)
//     validate the assertion signature; an unsigned assertion would be
//     trivially forgeable. The assertion is NEVER emitted unsigned — a signing
//     failure aborts with an error (the caller returns 500, no response).
//   - AudienceRestriction == pending.SPEntityID, so the assertion authenticates
//     ONLY at the SP it was minted for (an SP that receives a mis-audienced
//     assertion rejects it; saml/sp does exactly this).
//   - SubjectConfirmationData.Recipient == pending.ACSURL, the SP's REGISTERED
//     ACS (validated at /saml/sso) — taken from the stored pending request,
//     never from any finish-time input.
//   - InResponseTo == pending.RequestID on both the Response and the
//     SubjectConfirmation, binding the assertion to the SP's original
//     AuthnRequest.
//
// `now` is injected (not read from the wall clock) so callers share one
// timestamp across the assertion's instants and tests stay deterministic.
func BuildResponse(pending PendingRequest, user *sso.User, signer *AssertionSigner, issuer string, ttl time.Duration, now time.Time) (string, error) {
	if signer == nil {
		return "", ErrUnsupportedSigningKey
	}
	if ttl <= 0 {
		ttl = DefaultAssertionTTL
	}

	notBefore := now.Add(-assertionClockSkew)
	notOnOrAfter := now.Add(ttl)

	nameIDFormat := pending.NameIDFormat
	if nameIDFormat == "" {
		nameIDFormat = string(saml.EmailAddressNameIDFormat)
	}

	// NameID value: the user's id (the SSO subject). User.ID is the canonical
	// subject the rest of the server keys on.
	nameIDValue := user.ID

	assertion := &saml.Assertion{
		ID:           "id-" + randHex(),
		IssueInstant: now,
		Version:      "2.0",
		Issuer: saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Subject: &saml.Subject{
			NameID: &saml.NameID{
				Format:          nameIDFormat,
				NameQualifier:   issuer,
				SPNameQualifier: pending.SPEntityID,
				Value:           nameIDValue,
			},
			SubjectConfirmations: []saml.SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &saml.SubjectConfirmationData{
						InResponseTo: pending.RequestID,
						NotOnOrAfter: notOnOrAfter,
						// Recipient is the SP's REGISTERED ACS (from pending),
						// never a response-controlled URL — the assertion can
						// only be presented at the place the SP pre-registered.
						Recipient: pending.ACSURL,
					},
				},
			},
		},
		Conditions: &saml.Conditions{
			NotBefore:    notBefore,
			NotOnOrAfter: notOnOrAfter,
			AudienceRestrictions: []saml.AudienceRestriction{
				{Audience: saml.Audience{Value: pending.SPEntityID}},
			},
		},
		AuthnStatements: []saml.AuthnStatement{
			{
				AuthnInstant: now,
				// SAML AMR analogue: PasswordProtectedTransport is the
				// interoperable default authn-context class. (The SSO session
				// already authenticated the user; the precise per-method AMR
				// rides on the access-token path, not the SAML class ref.)
				AuthnContext: saml.AuthnContext{
					AuthnContextClassRef: &saml.AuthnContextClassRef{
						Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
					},
				},
			},
		},
		AttributeStatements: []saml.AttributeStatement{
			{Attributes: userAttributes(user)},
		},
	}

	// Sign the ASSERTION element (enveloped). This mirrors crewjam's
	// MakeAssertionEl: SignEnveloped appends the Signature as the assertion's
	// last child; we pull it back onto the struct so the re-rendered element
	// carries it in the canonical position.
	signedAssertionEl, err := signAssertion(assertion, signer)
	if err != nil {
		return "", err
	}

	response := &saml.Response{
		ID:           "id-" + randHex(),
		Version:      "2.0",
		IssueInstant: now,
		Destination:  pending.ACSURL, // the registered ACS, echoed as Destination
		InResponseTo: pending.RequestID,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	}

	// The Response wraps the SIGNED assertion element. The Response itself is
	// left unsigned: the assertion carries the signature (the shape saml/sp
	// validates, and the common SP posture). Signing the Response too is a
	// valid hardening an operator can add later; the assertion signature is the
	// load-bearing one.
	responseEl := response.Element()
	responseEl.AddChild(signedAssertionEl)

	doc := etree.NewDocument()
	doc.SetRoot(responseEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("saml/idp: serialize response: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// signAssertion enveloped-signs the assertion with signer and returns the
// signed element (Signature attached as the last child, per crewjam's
// MakeAssertionEl). A signing failure is returned, never swallowed — the
// caller MUST NOT emit an unsigned assertion.
func signAssertion(assertion *saml.Assertion, signer *AssertionSigner) (*etree.Element, error) {
	ctx, err := signer.SigningContext()
	if err != nil {
		return nil, err
	}
	assertionEl := assertion.Element()
	signedEl, err := ctx.SignEnveloped(assertionEl)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: sign assertion: %w", err)
	}
	// Pull the appended Signature back onto the struct so the final rendered
	// element places it in the canonical (post-Issuer) position crewjam emits.
	if children := signedEl.ChildElements(); len(children) > 0 {
		last := children[len(children)-1]
		if last.Tag == "Signature" {
			assertion.Signature = last
			return assertion.Element(), nil
		}
	}
	// Fallback: use the signed element directly (still a valid enveloped sig).
	return signedEl, nil
}

// userAttributes projects the user's attributes into SAML Attribute statements.
// Keys are emitted in sorted order so the assertion is deterministic (stable
// across runs — important for reproducible tests and cache-friendly diffs).
// Email + Name get well-known OID/FriendlyName slots when present; the open
// Attributes bag passes through under basic-format names.
func userAttributes(user *sso.User) []saml.Attribute {
	var attrs []saml.Attribute

	if user.Email != "" {
		attrs = append(attrs, saml.Attribute{
			FriendlyName: "mail",
			Name:         "urn:oid:0.9.2342.19200300.100.1.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: user.Email}},
		})
	}
	if user.Name != "" {
		attrs = append(attrs, saml.Attribute{
			FriendlyName: "displayName",
			Name:         "urn:oid:2.16.840.1.113730.3.1.241",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values:       []saml.AttributeValue{{Type: "xs:string", Value: user.Name}},
		})
	}

	keys := make([]string, 0, len(user.Attributes))
	for k := range user.Attributes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		attrs = append(attrs, saml.Attribute{
			Name:       k,
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values:     []saml.AttributeValue{{Type: "xs:string", Value: user.Attributes[k]}},
		})
	}
	return attrs
}
