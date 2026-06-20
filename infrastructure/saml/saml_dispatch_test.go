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

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	samlmod "github.com/snaplink/sso/saml"
	"github.com/snaplink/sso/saml/sp"
)

// spParams names a second SP's distinct entity id + ACS url so a multi-SP Build
// can be wired (each SPAuthenticator pins the SAME IdP cert here, so one IdP key
// signs assertions for either SP — what matters for the dispatch test is which
// authenticator the RelayState selects).
type spParams struct {
	name     string
	entityID string
	acsURL   string
}

// buildMultiSPACS wires saml.Build with TWO cert-pinned SPs and returns the ACS
// handler. The two SPs share the pinned IdP key (idp) so a single minter can
// produce a valid assertion for whichever SP the RelayState dispatches to.
func buildMultiSPACS(t *testing.T, a, b spParams) (http.HandlerFunc, *idpKey) {
	t.Helper()
	idp := newIDPKey(t)
	res, err := samlmod.Build(samlmod.Deps{
		SessionManager: defaultimpl.NewMemorySessionManager(),
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
		ClientStore:    defaultimpl.NewMemoryClientStore(),
	}, samlmod.Config{
		SPs: []sp.SPConfig{
			{Name: a.name, EntityID: a.entityID, ACSURL: a.acsURL, IDPCert: idp.certPEM(), IDPEntityID: idpEntity},
			{Name: b.name, EntityID: b.entityID, ACSURL: b.acsURL, IDPCert: idp.certPEM(), IDPEntityID: idpEntity},
		},
	})
	if err != nil {
		t.Fatalf("saml.Build (multi-SP): %v", err)
	}
	for i := range res.Handlers {
		h := &res.Handlers[i]
		if h.Path == sso.PathSAMLSSOCallback && h.Method == http.MethodPost {
			return h.Handler, idp
		}
	}
	t.Fatalf("multi-SP Build produced no POST %s handler", sso.PathSAMLSSOCallback)
	return nil, nil
}

// mintSignedResponseFor mints a valid signed SAMLResponse whose audience +
// recipient target the given SP (entityID + acs), so it validates through THAT
// SP's authenticator. It carries a Response InResponseTo so it satisfies the
// stateless SP's default SP-initiated-only posture (mirrors mintSignedResponse).
func mintSignedResponseFor(t *testing.T, idp *idpKey, entityID, acs, nameID string) string {
	t.Helper()
	now := time.Now()
	a := &crewjam.Assertion{
		ID:           "id-" + randHex(),
		IssueInstant: now,
		Version:      "2.0",
		Issuer:       crewjam.Issuer{Value: idpEntity},
		Subject: &crewjam.Subject{
			NameID: &crewjam.NameID{Format: string(crewjam.EmailAddressNameIDFormat), Value: nameID},
			SubjectConfirmations: []crewjam.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &crewjam.SubjectConfirmationData{
					NotOnOrAfter: now.Add(5 * time.Minute),
					Recipient:    acs,
				},
			}},
		},
		Conditions: &crewjam.Conditions{
			NotBefore:    now.Add(-time.Minute),
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []crewjam.AudienceRestriction{{
				Audience: crewjam.Audience{Value: entityID},
			}},
		},
		AuthnStatements: []crewjam.AuthnStatement{{
			AuthnInstant: now,
			AuthnContext: crewjam.AuthnContext{
				AuthnContextClassRef: &crewjam.AuthnContextClassRef{
					Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
				},
			},
		}},
	}
	ctx, err := dsig.NewSigningContext(idp.key, [][]byte{idp.cert.Raw})
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
	resp := &crewjam.Response{
		ID:           "id-" + randHex(),
		Version:      "2.0",
		IssueInstant: now,
		Destination:  acs,
		InResponseTo: "id-req-" + randHex(),
		Issuer:       &crewjam.Issuer{Value: idpEntity},
		Status:       crewjam.Status{StatusCode: crewjam.StatusCode{Value: crewjam.StatusSuccess}},
	}
	respEl := resp.Element()
	respEl.AddChild(signedEl)
	doc := etree.NewDocument()
	doc.SetRoot(respEl)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// postACSTo posts a SAMLResponse with an explicit RelayState to a given ACS URL
// path (multi-SP tests need to control the path + relay hint).
func postACSTo(handler http.HandlerFunc, path, samlResponse, relayState string) *httptest.ResponseRecorder {
	form := url.Values{"SAMLResponse": {samlResponse}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

const (
	spBEntity = "https://sp-b.example.com/saml/metadata"
	spBACS    = "https://sp-b.example.com/auth/saml/callback"
)

// TestACS_MultiSP_DispatchByRelayName proves the ACS dispatcher selects the
// SPAuthenticator named by the RelayState when several SPs are wired: an assertion
// minted for SP "b" is dispatched to b's authenticator only when RelayState=="b".
func TestACS_MultiSP_DispatchByRelayName(t *testing.T) {
	handler, idp := buildMultiSPACS(t,
		spParams{name: "a", entityID: spEntity, acsURL: acsURL},
		spParams{name: "b", entityID: spBEntity, acsURL: spBACS})

	respB := mintSignedResponseFor(t, idp, spBEntity, spBACS, "alice@example.com")
	rec := postACSTo(handler, spBACS, respB, "b")
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch-by-name status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestACS_MultiSP_DispatchByColonPrefix proves the "<provider>:<opaque-state>"
// relay convention: RelayState "b:some-opaque-login-state" still dispatches to
// SP "b" (first colon segment is the provider hint).
func TestACS_MultiSP_DispatchByColonPrefix(t *testing.T) {
	handler, idp := buildMultiSPACS(t,
		spParams{name: "a", entityID: spEntity, acsURL: acsURL},
		spParams{name: "b", entityID: spBEntity, acsURL: spBACS})

	respB := mintSignedResponseFor(t, idp, spBEntity, spBACS, "carol@example.com")
	rec := postACSTo(handler, spBACS, respB, "b:opaque-login-state-xyz")
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch-by-colon status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
}

// TestACS_MultiSP_NoHint_Rejected proves that with several SPs and an
// UNRESOLVABLE RelayState (no name match, no colon segment), dispatch fails and
// the ACS collapses to the oracle-safe assertion-invalid code — no
// provider-enumeration leak, and the wrong SP is never picked.
func TestACS_MultiSP_NoHint_Rejected(t *testing.T) {
	handler, idp := buildMultiSPACS(t,
		spParams{name: "a", entityID: spEntity, acsURL: acsURL},
		spParams{name: "b", entityID: spBEntity, acsURL: spBACS})

	respB := mintSignedResponseFor(t, idp, spBEntity, spBACS, "dave@example.com")
	rec := postACSTo(handler, spBACS, respB, "no-such-provider")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no-hint dispatch status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLAssertionInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLAssertionInvalid)
	}
}

// TestSPSLO_SessionIndexNarrowsTermination proves terminateLocalSessions honors
// the LogoutRequest's SessionIndex: with the subject holding TWO local sessions,
// a LogoutRequest carrying ONE session's id as its SessionIndex terminates ONLY
// that session; the subject's other session survives. (The handler compares
// SessionIndex to the local session id.)
func TestSPSLO_SessionIndexNarrowsTermination(t *testing.T) {
	handler, sessions, idp := buildSLOServer(t)
	const nameID = "multi@example.com"

	s1, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session 1: %v", err)
	}
	s2, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session 2: %v", err)
	}

	// LogoutRequest narrowed to s1's id.
	q := mintLogoutRedirectQuery(t, idp, idpEntity, nameID, s1.ID, spSLOURL, "")
	if rec := postSPSLO(handler, q); rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	// s1 gone, s2 survives (session-index scoping, not a blanket subject wipe).
	if _, err := sessions.Get(context.Background(), s1.ID); err == nil {
		t.Fatalf("session %q (matching SessionIndex) should be terminated", s1.ID)
	}
	if _, err := sessions.Get(context.Background(), s2.ID); err != nil {
		t.Fatalf("session %q (non-matching SessionIndex) wrongly terminated: %v", s2.ID, err)
	}
}
