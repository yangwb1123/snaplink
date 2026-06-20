package sp

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

// buildIDPLogoutPOST builds an IdP-initiated LogoutRequest for the HTTP-POST
// binding: the XML body carries an ENVELOPED §3.4.4.1 XML-DSig (not a detached
// query-param signature). When signer != nil the body is SignEnveloped'd with the
// IdP key — exactly what verifyLogoutRequestSignature validates against the pinned
// cert. signer == nil yields an UNSIGNED body (the fail-closed case). Returns the
// base64 SAMLRequest (no deflate — POST binding is plain base64) plus the raw
// signed bytes for tamper tests.
func buildIDPLogoutPOST(t *testing.T, p logoutReq, signer *idpKeypair) (samlRequestB64 string, raw []byte) {
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
	if p.sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: p.sessionIndex}
	}
	el := req.Element()
	if signer != nil {
		ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
		if err != nil {
			t.Fatalf("signing context: %v", err)
		}
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		if err := ctx.SetSignatureMethod(rsaSHA256); err != nil {
			t.Fatalf("set signature method: %v", err)
		}
		signed, err := ctx.SignEnveloped(el)
		if err != nil {
			t.Fatalf("sign enveloped: %v", err)
		}
		el = signed
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b), b
}

// processPOSTLogout drives ProcessLogoutRequest over the HTTP-POST binding
// (redirectBinding=false, no rawQuery) so it routes through the enveloped
// verifyLogoutRequestSignature path.
func processPOSTLogout(a *SPAuthenticator, samlRequestB64 string) (*LogoutSubject, error) {
	return a.ProcessLogoutRequest(samlRequestB64, "", false, "")
}

// TestSP_ProcessLogoutPOST_Signed_ReturnsSubject is the POST-binding happy path:
// a LogoutRequest with an ENVELOPED XML-DSig under the PINNED IdP cert validates
// and yields the subject. Covers verifyLogoutRequestSignature's success path.
func TestSP_ProcessLogoutPOST_Signed_ReturnsSubject(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	b64, _ := buildIDPLogoutPOST(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", sessionIndex: "sess-9", dest: tSPSLOURL}, idp)
	subj, err := processPOSTLogout(a, b64)
	if err != nil {
		t.Fatalf("POST ProcessLogoutRequest signed = %v, want nil", err)
	}
	if subj.NameID != "alice@example.com" {
		t.Errorf("NameID = %q, want alice@example.com", subj.NameID)
	}
	if subj.SessionIndex != "sess-9" {
		t.Errorf("SessionIndex = %q, want sess-9", subj.SessionIndex)
	}
}

// TestSP_ProcessLogoutPOST_Unsigned_Rejected: a POST LogoutRequest with NO
// enveloped Signature element is rejected — verifyLogoutRequestSignature fails
// closed (goxmldsig finds no Signature to validate).
func TestSP_ProcessLogoutPOST_Unsigned_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	b64, _ := buildIDPLogoutPOST(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, nil)
	if _, err := processPOSTLogout(a, b64); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("unsigned POST logout err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutPOST_AttackerKey_Rejected: an enveloped signature by a
// DIFFERENT key (not the pinned IdP cert) does not verify against the trust
// anchor → rejected.
func TestSP_ProcessLogoutPOST_AttackerKey_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	attacker := newIDPKeypair(t) // the SP did NOT pin this key
	b64, _ := buildIDPLogoutPOST(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, attacker)
	if _, err := processPOSTLogout(a, b64); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("attacker-key POST logout err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutPOST_TamperedAfterSign_Rejected: a validly enveloped-signed
// body whose NameID is mutated AFTER signing breaks the digest → goxmldsig
// rejects (XML-DSig integrity). This is the enveloped-binding analogue of the
// detached tamper test.
func TestSP_ProcessLogoutPOST_TamperedAfterSign_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	_, raw := buildIDPLogoutPOST(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, idp)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	// Mutate the NameID after signing (the signature now covers different bytes).
	nameID := doc.Root().FindElement("//NameID")
	if nameID == nil {
		t.Fatal("no NameID in signed request")
	}
	nameID.SetText("mallory@example.com")
	tampered, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(tampered)
	if _, err := processPOSTLogout(a, b64); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("tampered enveloped logout err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutPOST_XSW_Rejected exercises an XML-Signature-Wrapping
// shape against the enveloped POST path: a validly-signed LogoutRequest is kept
// intact (so its signature still verifies) but a SECOND, attacker-controlled
// NameID is injected as a sibling that an XPath-naive consumer might read first.
// verifyLogoutRequestSignature validates the document ROOT's signature with
// IdAttribute pinned, and the subsequent strict unmarshal reads the canonical
// NameID — the wrapper must not flip the outcome to the attacker's identity.
func TestSP_ProcessLogoutPOST_XSW_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	_, raw := buildIDPLogoutPOST(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, idp)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	root := doc.Root()
	// Inject a forged NameID sibling AFTER the legitimate one (classic XSW: a
	// shadow element an attacker hopes the parser picks up). The root's signed
	// digest no longer matches the mutated tree, so verification MUST reject —
	// the request never reaches the unmarshal step with a forged subject.
	forged := etree.NewElement("NameID")
	forged.SetText("attacker@evil.example.com")
	root.AddChild(forged)
	mutated, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(mutated)
	subj, err := processPOSTLogout(a, b64)
	if err == nil {
		t.Fatalf("XSW-shaped logout accepted (subject=%+v); a wrapped/forged tree must be rejected", subj)
	}
	if !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("XSW logout err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutPOST_Replay_Rejected: the SAME enveloped-signed POST
// request replayed is deduped within the freshness window.
func TestSP_ProcessLogoutPOST_Replay_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	b64, _ := buildIDPLogoutPOST(t, logoutReq{id: "id-post-1", issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, idp)
	if _, err := processPOSTLogout(a, b64); err != nil {
		t.Fatalf("first POST logout = %v, want nil", err)
	}
	if _, err := processPOSTLogout(a, b64); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("replayed POST logout err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutPOST_WrongIssuer_Rejected: enveloped-signed by the pinned
// key but claiming a DIFFERENT Issuer is rejected (issuer-binding, defense in
// depth atop the signature).
func TestSP_ProcessLogoutPOST_WrongIssuer_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	b64, _ := buildIDPLogoutPOST(t, logoutReq{issuer: "https://rogue.example.com", nameID: "alice@example.com", dest: tSPSLOURL}, idp)
	if _, err := processPOSTLogout(a, b64); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("wrong-issuer POST logout err = %v, want ErrLogoutInvalid", err)
	}
}
