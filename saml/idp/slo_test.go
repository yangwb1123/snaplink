package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

// spSLOURL is the SP's registered Single Logout Service URL the IdP returns the
// LogoutResponse to (the allowlisted destination).
const spSLOURL = "https://sp.example.com/saml/slo"

// spKeypair is a self-signed RSA cert + key standing in for the SP signing key
// (the IdP pins its cert via saml_sp_signing_cert to authenticate SP
// LogoutRequests).
type spKeypair struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// newSPKeypair generates a fresh RSA keypair + self-signed cert with a wide
// validity window so goxmldsig's cert-validity check never trips on the clock.
func newSPKeypair(t *testing.T) *spKeypair {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen SP key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "test-sp"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create SP cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse SP cert: %v", err)
	}
	return &spKeypair{key: key, cert: cert}
}

func (k *spKeypair) certPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.cert.Raw}))
}

// registerSPWithSLO registers an SP client carrying the signing cert + SLO URL
// (and the entity id / ACS allowlist) so the IdP can authenticate + respond to a
// SP-initiated LogoutRequest.
func registerSPWithSLO(t *testing.T, clients *defaultimpl.MemoryClientStore, signer *spKeypair) {
	t.Helper()
	err := clients.Add(context.Background(), &sso.Client{
		ID:     spClientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID:    spEntityID,
			AttrSPACSURLs:     spACSURL,
			AttrSPSigningCert: signer.certPEM(),
			AttrSPSLOUrls:     spSLOURL,
		},
	})
	if err != nil {
		t.Fatalf("register SP with SLO: %v", err)
	}
}

// buildLogoutRequestXML builds a LogoutRequest with the given issuer + NameID
// and, when signer != nil, enveloped-signs it with the SP key. Returns the
// base64 raw-DEFLATE (HTTP-Redirect binding) encoding for ?SAMLRequest=.
func buildLogoutRequestXML(t *testing.T, issuer, nameID, sessionIndex string, signer *spKeypair) string {
	t.Helper()
	req := &saml.LogoutRequest{
		ID:           "id-lo-" + randHex(),
		Version:      "2.0",
		IssueInstant: fixedNow,
		Destination:  testIssuer + "/saml/slo",
		Issuer:       &saml.Issuer{Value: issuer},
		NameID:       &saml.NameID{Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
	}
	el := req.Element()
	if signer != nil {
		el = signLogoutRequestEl(t, req, signer)
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize logout request: %v", err)
	}
	return base64.StdEncoding.EncodeToString(deflate(t, raw))
}

// signLogoutRequestEl enveloped-signs the LogoutRequest element with the SP key
// (the shape verifyLogoutRequestSignature validates).
func signLogoutRequestEl(t *testing.T, req *saml.LogoutRequest, signer *spKeypair) *etree.Element {
	t.Helper()
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("new signing context: %v", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	signedEl, err := ctx.SignEnveloped(req.Element())
	if err != nil {
		t.Fatalf("sign enveloped logout request: %v", err)
	}
	return signedEl
}

// getSLO drives GET /saml/slo with a DEFLATEd base64 SAMLRequest (the
// HTTP-Redirect binding an SP uses for SP-initiated SLO).
func (hh *harness) getSLO(samlRequest string) *httptest.ResponseRecorder {
	u := "/saml/slo?" + url.Values{"SAMLRequest": {samlRequest}}.Encode()
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	hh.h.SLO(rec, req)
	return rec
}

// newSLOHarness builds a harness with the SP registered WITH its signing cert +
// SLO URL, and seeds a user+session for nameID; returns the harness + the SP
// keypair + the live session id.
func newSLOHarness(t *testing.T, nameID string) (*harness, *spKeypair, string) {
	t.Helper()
	issuer, pub := newIssuer(t, issuerRSA)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	spKey := newSPKeypair(t)
	registerSPWithSLO(t, clients, spKey)

	h, err := NewHandlers(Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "test", issuer, nil },
		Issuer:          testIssuer,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	h.deps.now = func() time.Time { return fixedNow }
	hh := &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
	sid := hh.seedUserSession(t, nameID)
	return hh, spKey, sid
}

// TestSLO_SignedRequest_TerminatesSessionAndReturnsResponse is the happy path:
// a SIGNED SP LogoutRequest terminates the matching subject session and the IdP
// returns a SIGNED LogoutResponse (auto-POST form) to the SP's REGISTERED SLO
// URL.
func TestSLO_SignedRequest_TerminatesSessionAndReturnsResponse(t *testing.T) {
	const nameID = "alice@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	// Sanity: the session is live before the logout.
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("precondition: session %q should exist: %v", sid, err)
	}

	samlReq := buildLogoutRequestXML(t, spEntityID, nameID, "", spKey)
	rec := hh.getSLO(samlReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("SLO status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	assertNoStore(t, rec)

	// The matching session is GONE (terminated via SessionManager).
	if s, err := hh.sessions.Get(context.Background(), sid); err == nil && s != nil {
		t.Fatalf("session %q should be terminated by SLO, still present", sid)
	}

	// A LogoutResponse auto-POST form to the REGISTERED SLO URL.
	body := rec.Body.String()
	if !strings.Contains(body, `action="`+spSLOURL+`"`) {
		t.Fatalf("response form does not POST to registered SLO URL %q; body=%s", spSLOURL, body)
	}
	respB64 := extractInputValue(t, body, "SAMLResponse")
	if respB64 == "" {
		t.Fatalf("no SAMLResponse in form")
	}

	// The LogoutResponse is SIGNED (validates against the IdP signing cert) and
	// carries Status Success + InResponseTo binding.
	respEl := parseLogoutResponseEl(t, respB64)
	verifyElementSignature(t, respEl, hh.signerFor(t))
	if got := respEl.SelectAttrValue("InResponseTo", ""); got == "" {
		t.Errorf("LogoutResponse missing InResponseTo")
	}
	assertStatusSuccess(t, respEl)
}

// TestSLO_UnsignedRequest_Rejected_NoTermination is THE SECURITY CRUX: an
// UNSIGNED LogoutRequest is rejected (saml_request_invalid) and the session is
// NOT terminated. No session termination without a verified signature.
func TestSLO_UnsignedRequest_Rejected_NoTermination(t *testing.T) {
	const nameID = "bob@example.com"
	hh, _, sid := newSLOHarness(t, nameID)

	samlReq := buildLogoutRequestXML(t, spEntityID, nameID, "", nil) // nil signer ⇒ unsigned
	rec := hh.getSLO(samlReq)

	assertRequestInvalidOnly(t, rec)

	// The session MUST survive — an unsigned logout terminates nothing.
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q was terminated by an UNSIGNED logout (security violation): %v", sid, err)
	}
}

// TestSLO_AttackerSignedRequest_Rejected_NoTermination: a LogoutRequest signed
// by a DIFFERENT key (not the SP's registered cert) is rejected and the session
// is NOT terminated.
func TestSLO_AttackerSignedRequest_Rejected_NoTermination(t *testing.T) {
	const nameID = "carol@example.com"
	hh, _, sid := newSLOHarness(t, nameID)

	attacker := newSPKeypair(t) // NOT the registered SP cert
	samlReq := buildLogoutRequestXML(t, spEntityID, nameID, "", attacker)
	rec := hh.getSLO(samlReq)

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q was terminated by an ATTACKER-signed logout (security violation): %v", sid, err)
	}
}

// TestSLO_UnregisteredSP_Rejected: a (well-formed, signed) LogoutRequest whose
// Issuer is not a registered SP is rejected.
func TestSLO_UnregisteredSP_Rejected(t *testing.T) {
	const nameID = "dave@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	samlReq := buildLogoutRequestXML(t, "https://evil.example.com/saml", nameID, "", spKey)
	rec := hh.getSLO(samlReq)

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q terminated for an unregistered SP: %v", sid, err)
	}
}

// TestSLO_SLOURLNotRegistered_TerminatesButNoResponse: when the SP registered NO
// SLO URL, a valid signed LogoutRequest still terminates the session (the kill
// is authenticated) but the IdP sends NO LogoutResponse (nowhere allowlisted to
// send it) — proving the response goes ONLY to a registered URL, never a
// request-supplied one.
func TestSLO_SLOURLNotRegistered_TerminatesButNoResponse(t *testing.T) {
	const nameID = "erin@example.com"
	issuer, pub := newIssuer(t, issuerRSA)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	spKey := newSPKeypair(t)

	// Register WITHOUT a SLO URL.
	if err := clients.Add(context.Background(), &sso.Client{
		ID:     spClientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID:    spEntityID,
			AttrSPACSURLs:     spACSURL,
			AttrSPSigningCert: spKey.certPEM(),
			// AttrSPSLOUrls deliberately omitted.
		},
	}); err != nil {
		t.Fatalf("register SP: %v", err)
	}
	h, err := NewHandlers(Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "test", issuer, nil },
		Issuer:          testIssuer,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	h.deps.now = func() time.Time { return fixedNow }
	hh := &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
	sid := hh.seedUserSession(t, nameID)

	samlReq := buildLogoutRequestXML(t, spEntityID, nameID, "", spKey)
	rec := hh.getSLO(samlReq)

	if rec.Code != http.StatusOK {
		t.Fatalf("SLO status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// Session terminated (the request was authenticated).
	if _, err := hh.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("session %q should be terminated even without a registered SLO URL", sid)
	}
	// NO LogoutResponse emitted (empty body — nowhere allowlisted to send it).
	if b := strings.TrimSpace(rec.Body.String()); b != "" {
		t.Fatalf("expected empty body (no response without a registered SLO URL), got: %s", b)
	}
}

// TestSLO_OnlyMatchingSubjectTerminated proves a logout for one subject does NOT
// terminate another subject's session — the termination is scoped to the
// request's NameID, never a global wipe.
func TestSLO_OnlyMatchingSubjectTerminated(t *testing.T) {
	const target = "frank@example.com"
	hh, spKey, targetSID := newSLOHarness(t, target)

	// A second, unrelated subject with a live session.
	otherSID := hh.seedUserSession(t, "grace@example.com")

	samlReq := buildLogoutRequestXML(t, spEntityID, target, "", spKey)
	if rec := hh.getSLO(samlReq); rec.Code != http.StatusOK {
		t.Fatalf("SLO status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Target gone, the other subject's session UNTOUCHED.
	if _, err := hh.sessions.Get(context.Background(), targetSID); err == nil {
		t.Fatalf("target session %q should be terminated", targetSID)
	}
	if _, err := hh.sessions.Get(context.Background(), otherSID); err != nil {
		t.Fatalf("UNRELATED subject's session %q was terminated by SLO (global-wipe bug): %v", otherSID, err)
	}
}

// TestSLO_NonexistentSession_StillSuccess_NoOracle proves the
// no-session-existence-oracle property: a SIGNED logout for a subject with NO
// live session still returns a Success LogoutResponse (not a distinguishable
// error), so SLO cannot enumerate live sessions.
func TestSLO_NonexistentSession_StillSuccess_NoOracle(t *testing.T) {
	const nameID = "ghost@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	// Destroy the session first so there is nothing to terminate.
	if err := hh.sessions.Destroy(context.Background(), sid); err != nil {
		t.Fatalf("pre-destroy session: %v", err)
	}

	samlReq := buildLogoutRequestXML(t, spEntityID, nameID, "", spKey)
	rec := hh.getSLO(samlReq)

	// Still 200 with a Success LogoutResponse — identical to the case where a
	// session existed (no oracle).
	if rec.Code != http.StatusOK {
		t.Fatalf("SLO status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	respB64 := extractInputValue(t, rec.Body.String(), "SAMLResponse")
	respEl := parseLogoutResponseEl(t, respB64)
	assertStatusSuccess(t, respEl)
}

// TestSLO_Malformed_Rejected: a structurally-broken SAMLRequest collapses to the
// one oracle-safe code.
func TestSLO_Malformed_Rejected(t *testing.T) {
	hh, _, _ := newSLOHarness(t, "h@example.com")
	rec := hh.getSLO("not-valid-base64-$$$")
	assertRequestInvalidOnly(t, rec)
}

// TestSLO_LogoutResponse_ValidatesAtSP is the cross-side interop proof: the
// signed LogoutResponse this IdP emits at /saml/slo is accepted by crewjam's
// SP-side ValidateLogoutResponseForm (the SAME validator a real SP runs),
// pinning the IdP's signing cert. This guarantees the two halves of SLO agree on
// the wire format + signature.
func TestSLO_LogoutResponse_ValidatesAtSP(t *testing.T) {
	const nameID = "interop@example.com"
	hh, spKey, _ := newSLOHarness(t, nameID)

	samlReq := buildLogoutRequestXML(t, spEntityID, nameID, "", spKey)
	rec := hh.getSLO(samlReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("SLO status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	respB64 := extractInputValue(t, rec.Body.String(), "SAMLResponse")

	// Build a crewjam SP that pins THIS IdP's signing cert + the entity id, with
	// its SloURL == the registered destination (spSLOURL). Freeze crewjam's clock
	// to the IdP's issue instant so the IssueInstant freshness check passes.
	idpSigner := hh.signerFor(t)
	idpCert, err := idpSigner.Certificate()
	if err != nil {
		t.Fatalf("idp signer cert: %v", err)
	}
	sloURL, _ := url.Parse(spSLOURL)
	spSvc := &saml.ServiceProvider{
		EntityID: spEntityID,
		SloURL:   *sloURL,
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: testEntityID, // = the IdP entity id (Issuer + "/saml")
			IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{
						KeyDescriptors: []saml.KeyDescriptor{{
							Use: "signing",
							KeyInfo: saml.KeyInfo{
								X509Data: saml.X509Data{
									X509Certificates: []saml.X509Certificate{
										{Data: base64.StdEncoding.EncodeToString(idpCert.Raw)},
									},
								},
							},
						}},
					},
				},
			}},
		},
	}

	// crewjam validateLogoutResponse uses TimeNow() for the IssueInstant
	// freshness check; pin it to the IdP's fixed clock so the response (minted at
	// fixedNow) is fresh.
	saml.TimeNow = func() time.Time { return fixedNow }
	saml.Clock = dsig.NewFakeClockAt(fixedNow)
	defer func() { saml.TimeNow = time.Now; saml.Clock = nil }()

	if err := spSvc.ValidateLogoutResponseForm(respB64); err != nil {
		t.Fatalf("SP rejected the IdP's LogoutResponse (interop break): %v", err)
	}
}

// --- LogoutResponse parsing/verification helpers ---

func parseLogoutResponseEl(t *testing.T, respB64 string) *etree.Element {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(respB64)
	if err != nil {
		t.Fatalf("base64 decode LogoutResponse: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("parse LogoutResponse xml: %v", err)
	}
	return doc.Root()
}

// verifyElementSignature validates an enveloped signature on el against the
// signer's cert (used to prove the LogoutResponse is signed by the IdP key).
func verifyElementSignature(t *testing.T, el *etree.Element, signer *AssertionSigner) {
	t.Helper()
	cert, err := signer.Certificate()
	if err != nil {
		t.Fatalf("signer cert: %v", err)
	}
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(store)
	ctx.Clock = dsig.NewFakeClockAt(fixedNow)
	if _, err := ctx.Validate(el); err != nil {
		t.Fatalf("LogoutResponse signature INVALID: %v", err)
	}
}

func assertStatusSuccess(t *testing.T, respEl *etree.Element) {
	t.Helper()
	status := respEl.FindElement("//StatusCode")
	if status == nil {
		t.Fatalf("LogoutResponse has no StatusCode; xml=%s", elementString(respEl))
	}
	if v := status.SelectAttrValue("Value", ""); v != saml.StatusSuccess {
		t.Errorf("StatusCode = %q, want %q", v, saml.StatusSuccess)
	}
}

func elementString(el *etree.Element) string {
	doc := etree.NewDocument()
	doc.SetRoot(el.Copy())
	s, _ := doc.WriteToString()
	return s
}
