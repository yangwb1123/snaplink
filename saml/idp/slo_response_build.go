package idp

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
)

// buildLogoutResponseRedirect builds a SIGNED HTTP-Redirect LogoutResponse URL
// (Status Success) the IdP redirects the user-agent to, back to the SP's
// REGISTERED SLO URL. The XML body is UNSIGNED; the signature is the
// SAML-standard DETACHED §3.4.4.1 SigAlg+Signature query pair, computed with the
// per-tenant signer (the SAME key published in metadata) — what a real SP
// validates. destination is the registered SLO URL (never request-supplied);
// inResponseTo binds the SP's LogoutRequest ID; relayState is echoed verbatim;
// `now` is injected for deterministic tests. A signing failure aborts WITHOUT
// emitting anything.
func buildLogoutResponseRedirect(issuer, destination, inResponseTo, relayState string, signer *AssertionSigner, now time.Time) (string, error) {
	if signer == nil {
		return "", ErrUnsupportedSigningKey
	}
	sigAlg, ok := redirectSigAlgFor(signer.SignatureMethod())
	if !ok {
		return "", ErrUnsupportedSigningKey
	}
	signCtx, err := signer.SigningContext()
	if err != nil {
		return "", err
	}
	resp := &saml.LogoutResponse{
		ID:           "id-" + randHex(),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	}
	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("saml/idp: serialize logout response: %w", err)
	}
	return buildRedirectURL(signCtx, sigAlg, destination, "SAMLResponse", raw, relayState)
}

// buildLogoutResponse constructs a base64-encoded SAML LogoutResponse (Status
// Success) whose root element is enveloped-XML-DSig signed with the per-tenant
// key behind signer (the SAME key published in metadata + used for assertions).
// destination is the SP's REGISTERED SLO URL (never request-supplied);
// inResponseTo binds the response to the SP's LogoutRequest ID; `now` is injected
// for deterministic tests. Used for the HTTP-POST response binding (the redirect
// binding uses buildLogoutResponseRedirect with a detached signature).
//
// The response is signed (not left bare) so the SP can authenticate that the
// IdP — not an attacker — acknowledged the logout, mirroring the assertion
// signing posture. A signing failure aborts WITHOUT emitting anything.
func buildLogoutResponse(issuer, destination, inResponseTo string, signer *AssertionSigner, now time.Time) (string, error) {
	if signer == nil {
		return "", ErrUnsupportedSigningKey
	}
	resp := &saml.LogoutResponse{
		ID:           "id-" + randHex(),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: now,
		Destination:  destination,
		Issuer: &saml.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  issuer,
		},
		Status: saml.Status{
			StatusCode: saml.StatusCode{Value: saml.StatusSuccess},
		},
	}

	signedEl, err := signLogoutResponse(resp, signer)
	if err != nil {
		return "", err
	}

	doc := etree.NewDocument()
	doc.SetRoot(signedEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		return "", fmt.Errorf("saml/idp: serialize logout response: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// signLogoutResponse enveloped-signs the LogoutResponse element with signer and
// returns the signed element (Signature attached as the last child, the shape
// crewjam's SignLogoutResponse and the SP-side validateSignature expect). A
// signing failure is returned, never swallowed.
func signLogoutResponse(resp *saml.LogoutResponse, signer *AssertionSigner) (*etree.Element, error) {
	ctx, err := signer.SigningContext()
	if err != nil {
		return nil, err
	}
	el := resp.Element()
	signedEl, err := ctx.SignEnveloped(el)
	if err != nil {
		return nil, fmt.Errorf("saml/idp: sign logout response: %w", err)
	}
	return signedEl, nil
}
