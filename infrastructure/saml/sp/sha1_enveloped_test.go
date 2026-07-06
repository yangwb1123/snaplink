package sp

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// rsaSHA1 is the legacy RSA-SHA1 XML-DSig SignatureMethod URI. goxmldsig's
// default ValidationContext (and crewjam's ParseXMLResponse, which uses it)
// would accept a SHA-1 signature; the enveloped paths must reject it
// (no-SHA-1 posture) via envelopedAlgGuard / rejectWeakSignatureAlgorithms.
const rsaSHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"

// signEnvelopedWithMethod enveloped-signs el with signer's key under the
// given XML-DSig SignatureMethod URI and returns the signed element.
func signEnvelopedWithMethod(t *testing.T, el *etree.Element, signer *idpKeypair, method string) *etree.Element {
	t.Helper()
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("signing context: %v", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(method); err != nil {
		t.Fatalf("set signature method %q: %v", method, err)
	}
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatalf("sign enveloped: %v", err)
	}
	return signed
}

// mintResponseWithMethod builds + signs an assertion under method and wraps
// it into a base64 SAMLResponse for the SP ACS.
func mintResponseWithMethod(t *testing.T, p assertionParams, signer *idpKeypair, destination, method string) string {
	t.Helper()
	el := signEnvelopedWithMethod(t, buildAssertion(p).Element(), signer, method)
	return responseFrom(p.idpEntityID, destination, p.inResponseTo, el)
}

// TestSP_ProcessAssertion_SHA256_Accepted is the control: a SHA-256 enveloped
// assertion under the pinned IdP cert validates (proves the SignatureVerifier
// hook does not over-reject the allowlisted algorithm).
func TestSP_ProcessAssertion_SHA256_Accepted(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	resp := mintResponseWithMethod(t, p, idp, tACSURL, rsaSHA256)
	if _, err := a.ProcessAssertion(context.Background(), resp, ""); err != nil {
		t.Fatalf("SHA-256 assertion err = %v, want nil", err)
	}
}

// TestSP_ProcessAssertion_SHA1_Rejected: a VALID RSA-SHA1 enveloped assertion
// under the PINNED IdP cert is REJECTED. crewjam's ParseXMLResponse alone
// (via goxmldsig) would accept it; the SignatureVerifier algorithm guard
// rejects the weak algorithm. Collapses to the one oracle-safe code.
func TestSP_ProcessAssertion_SHA1_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newTestSP(t, idp, tIDPEntity, tSPEntity, tACSURL, now)

	p := defaultAssertionParams(tIDPEntity, tSPEntity, tACSURL)
	resp := mintResponseWithMethod(t, p, idp, tACSURL, rsaSHA1)
	_, err := a.ProcessAssertion(context.Background(), resp, "")
	assertInvalid(t, "sha1-signed assertion", err)
}

// buildIDPLogoutPOSTWithMethod builds a POST-binding LogoutRequest enveloped-
// signed under method (mirrors buildIDPLogoutPOST, parameterized on the alg).
func buildIDPLogoutPOSTWithMethod(t *testing.T, p logoutReq, signer *idpKeypair, method string) string {
	t.Helper()
	id := p.id
	if id == "" {
		id = "id-lo-" + randHex()
	}
	issued := p.issueInstant
	if issued.IsZero() {
		issued = time.Now()
	}
	req := &saml.LogoutRequest{
		ID:           id,
		Version:      "2.0",
		IssueInstant: issued,
		Destination:  p.dest,
		Issuer:       &saml.Issuer{Value: p.issuer},
		NameID:       &saml.NameID{Value: p.nameID},
	}
	el := signEnvelopedWithMethod(t, req.Element(), signer, method)
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b)
}

// TestSP_ProcessLogoutPOST_SHA256_Accepted is the control for the SP
// enveloped LogoutRequest path: a SHA-256 enveloped LogoutRequest validates.
func TestSP_ProcessLogoutPOST_SHA256_Accepted(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	b64 := buildIDPLogoutPOSTWithMethod(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, idp, rsaSHA256)
	if _, err := processPOSTLogout(a, b64); err != nil {
		t.Fatalf("SHA-256 POST logout err = %v, want nil", err)
	}
}

// TestSP_ProcessLogoutPOST_SHA1_Rejected: a VALID RSA-SHA1 enveloped
// LogoutRequest under the pinned IdP cert is rejected (the
// rejectWeakSignatureAlgorithms guard), so a weak-alg logout can't drive a
// local session termination.
func TestSP_ProcessLogoutPOST_SHA1_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	b64 := buildIDPLogoutPOSTWithMethod(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, idp, rsaSHA1)
	if _, err := processPOSTLogout(a, b64); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("SHA-1 POST logout err = %v, want ErrLogoutInvalid", err)
	}
}
