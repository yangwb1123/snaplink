package saml_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso/interfaces/sso"
)

// mintLogoutPOST builds an IdP-initiated LogoutRequest for the HTTP-POST binding:
// the XML body carries an ENVELOPED §3.4.4.1 XML-DSig (signed with the pinned IdP
// key when signer != nil). Returns the base64 SAMLRequest (plain base64, no
// deflate — that's the POST binding).
func mintLogoutPOST(t *testing.T, signer *idpKey, issuer, nameID, dest string) string {
	t.Helper()
	req := &crewjam.LogoutRequest{
		ID:           "id-lo-" + randHex(),
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  dest,
		Issuer:       &crewjam.Issuer{Value: issuer},
		NameID:       &crewjam.NameID{Value: nameID},
	}
	el := req.Element()
	if signer != nil {
		ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
		if err != nil {
			t.Fatalf("signing context: %v", err)
		}
		ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		if err := ctx.SetSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"); err != nil {
			t.Fatalf("set sig method: %v", err)
		}
		signed, err := ctx.SignEnveloped(el)
		if err != nil {
			t.Fatalf("sign enveloped: %v", err)
		}
		el = signed
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// postSPSLOForm drives the SP SLO handler over the HTTP-POST binding (form body).
func postSPSLOForm(handler http.HandlerFunc, samlRequest, relayState string) *httptest.ResponseRecorder {
	form := url.Values{"SAMLRequest": {samlRequest}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	req := httptest.NewRequest(http.MethodPost, spSLOURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// TestSPSLO_POSTBinding_SignedRequest_TerminatesSession proves the wired SP SLO
// handler accepts the HTTP-POST binding (enveloped XML-DSig over the body),
// terminates the local session, and returns a 302 signed LogoutResponse — the
// POST-binding analogue of the redirect-binding end-to-end test (exercises the
// handler's POST branch end to end).
func TestSPSLO_POSTBinding_SignedRequest_TerminatesSession(t *testing.T) {
	handler, sessions, idp := buildSLOServer(t)

	const nameID = "post-slo@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	b64 := mintLogoutPOST(t, idp, idpEntity, nameID, spSLOURL)
	rec := postSPSLOForm(handler, b64, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("POST SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if s, err := sessions.Get(context.Background(), sess.ID); err == nil && s != nil {
		t.Fatalf("local session %q should be terminated by POST-binding SLO", sess.ID)
	}
}

// TestSPSLO_POSTBinding_Unsigned_NoTermination proves the POST branch is
// fail-closed too: an UNSIGNED enveloped LogoutRequest is rejected and the
// session survives.
func TestSPSLO_POSTBinding_Unsigned_NoTermination(t *testing.T) {
	handler, sessions, _ := buildSLOServer(t)

	const nameID = "post-unsigned@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	b64 := mintLogoutPOST(t, nil, idpEntity, nameID, spSLOURL) // unsigned
	rec := postSPSLOForm(handler, b64, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unsigned POST SLO status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLRequestInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLRequestInvalid)
	}
	if _, err := sessions.Get(context.Background(), sess.ID); err != nil {
		t.Fatalf("session %q terminated by an UNSIGNED POST logout (security violation): %v", sess.ID, err)
	}
}

// TestSPSLO_POSTBinding_MissingSAMLRequest_400 covers the POST branch's empty
// SAMLRequest guard.
func TestSPSLO_POSTBinding_MissingSAMLRequest_400(t *testing.T) {
	handler, _, _ := buildSLOServer(t)
	rec := postSPSLOForm(handler, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing SAMLRequest status = %d, want 400", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

// TestSPSLO_MethodNotAllowed_405 covers the SP SLO handler's default (non
// GET/POST) branch.
func TestSPSLO_MethodNotAllowed_405(t *testing.T) {
	handler, _, _ := buildSLOServer(t)
	req := httptest.NewRequest(http.MethodPut, spSLOURL, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT SLO status = %d, want 405", rec.Code)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store (stamped before method check)", cc)
	}
}
