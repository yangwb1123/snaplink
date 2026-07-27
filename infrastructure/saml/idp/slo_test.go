package idp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"io"
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

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
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

// spLogoutReq is the knobs for a test SP-initiated LogoutRequest (so
// freshness/replay tests can pin the ID + IssueInstant). Zero IssueInstant ⇒
// fixedNow (the harness clock).
type spLogoutReq struct {
	id           string
	issuer       string
	nameID       string
	sessionIndex string
	issueInstant time.Time
}

// buildSPLogoutRedirectQuery builds a LogoutRequest per p and, when signer !=
// nil, signs it with the SAML-standard DETACHED §3.4.4.1 redirect-binding
// signature (UNSIGNED XML body + SigAlg+Signature query params over the
// URL-encoded octet string) using the SP key — exactly what a real SP sends for
// SP-initiated SLO. Returns the FULL raw query string. An unsigned request
// (signer == nil) carries no SigAlg/Signature (the fail-closed-rejection case).
func buildSPLogoutRedirectQuery(t *testing.T, p spLogoutReq, relayState string, signer *spKeypair) string {
	t.Helper()
	id := p.id
	if id == "" {
		id = "id-lo-" + randHex()
	}
	issued := p.issueInstant
	if issued.IsZero() {
		issued = fixedNow
	}
	req := &saml.LogoutRequest{
		ID:           id,
		Version:      "2.0",
		IssueInstant: issued,
		Destination:  testIssuer + "/saml/slo",
		Issuer:       &saml.Issuer{Value: p.issuer},
		NameID:       &saml.NameID{Value: p.nameID},
	}
	if p.sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: p.sessionIndex}
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize logout request: %v", err)
	}
	samlReq := base64.StdEncoding.EncodeToString(deflate(t, raw))

	query := "SAMLRequest=" + url.QueryEscape(samlReq)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if signer == nil {
		return query
	}
	const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	query += "&SigAlg=" + url.QueryEscape(rsaSHA256)
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("new signing context: %v", err)
	}
	if err := ctx.SetSignatureMethod(rsaSHA256); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	sig, err := ctx.SignString(query)
	if err != nil {
		t.Fatalf("sign detached: %v", err)
	}
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return query
}

// getSLO drives GET /saml/slo over the HTTP-Redirect binding using a FULL raw
// query string (so the detached §3.4.4.1 signature is preserved byte-for-byte —
// re-encoding via url.Values would break it).
func (hh *harness) getSLO(rawQuery string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/saml/slo?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	hh.h.SLO(rec, req)
	return rec
}

// buildSPLogoutPostBody builds an ENVELOPED-XML-DSig-signed LogoutRequest (the
// HTTP-POST binding: the signed XML body is base64'd, NOT deflated) for the POST
// SLO path. The enveloped form is what the POST binding keeps (the redirect
// binding moved to detached §3.4.4.1).
func buildSPLogoutPostBody(t *testing.T, p spLogoutReq, signer *spKeypair) string {
	t.Helper()
	id := p.id
	if id == "" {
		id = "id-lo-" + randHex()
	}
	issued := p.issueInstant
	if issued.IsZero() {
		issued = fixedNow
	}
	req := &saml.LogoutRequest{
		ID:           id,
		Version:      "2.0",
		IssueInstant: issued,
		Destination:  testIssuer + "/saml/slo",
		Issuer:       &saml.Issuer{Value: p.issuer},
		NameID:       &saml.NameID{Value: p.nameID},
	}
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("new signing context: %v", err)
	}
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatalf("set signature method: %v", err)
	}
	signed, err := ctx.SignEnveloped(req.Element())
	if err != nil {
		t.Fatalf("sign enveloped: %v", err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// postSLO drives POST /saml/slo over the HTTP-POST binding (form body).
func (hh *harness) postSLO(samlRequest, relayState string) *httptest.ResponseRecorder {
	form := url.Values{"SAMLRequest": {samlRequest}}
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	req := httptest.NewRequest(http.MethodPost, "/saml/slo", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
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
// a DETACHED-signed SP LogoutRequest terminates the matching subject session and
// the IdP returns a 302 DETACHED-signed LogoutResponse redirect to the SP's
// REGISTERED SLO URL.
func TestSLO_SignedRequest_TerminatesSessionAndReturnsResponse(t *testing.T) {
	t.Parallel()
	const nameID = "alice@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	// Sanity: the session is live before the logout.
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("precondition: session %q should exist: %v", sid, err)
	}

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", spKey)
	rec := hh.getSLO(q)

	if rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	assertNoStore(t, rec)

	// The matching session is GONE (terminated via SessionManager).
	if s, err := hh.sessions.Get(context.Background(), sid); err == nil && s != nil {
		t.Fatalf("session %q should be terminated by SLO, still present", sid)
	}

	// A 302 LogoutResponse redirect to the REGISTERED SLO URL.
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != spSLOURL {
		t.Fatalf("response redirect points at %q, want %q", u.Scheme+"://"+u.Host+u.Path, spSLOURL)
	}
	respB64 := u.Query().Get("SAMLResponse")
	if respB64 == "" {
		t.Fatalf("no SAMLResponse in redirect")
	}
	// The LogoutResponse carries a DETACHED signature (validates against the IdP
	// signing cert) and the body is UNSIGNED with Status Success + InResponseTo.
	idpCert := idpSignerCert(t, hh.signerFor(t))
	assertIDPDetachedSigVerifies(t, u.RawQuery, "SAMLResponse", idpCert)
	respEl := inflateLogoutResponseEl(t, respB64)
	if sig := respEl.FindElement("//Signature"); sig != nil {
		t.Error("redirect SAMLResponse body must be UNSIGNED (detached binding), found an enveloped Signature")
	}
	if got := respEl.SelectAttrValue("InResponseTo", ""); got == "" {
		t.Errorf("LogoutResponse missing InResponseTo")
	}
	assertStatusSuccess(t, respEl)
}

// TestSLO_UnsignedRequest_Rejected_NoTermination is THE SECURITY CRUX: a
// redirect LogoutRequest WITHOUT a detached signature (no SigAlg/Signature) is
// rejected (saml_request_invalid) and the session is NOT terminated. No session
// termination without a verified signature — the fail-closed property preserved
// through the detached path.
func TestSLO_UnsignedRequest_Rejected_NoTermination(t *testing.T) {
	t.Parallel()
	const nameID = "bob@example.com"
	hh, _, sid := newSLOHarness(t, nameID)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", nil) // unsigned
	rec := hh.getSLO(q)

	assertRequestInvalidOnly(t, rec)

	// The session MUST survive — an unsigned logout terminates nothing.
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q was terminated by an UNSIGNED logout (security violation): %v", sid, err)
	}
}

// TestSLO_AttackerSignedRequest_Rejected_NoTermination: a LogoutRequest detached-
// signed by a DIFFERENT key (not the SP's registered cert) is rejected and the
// session is NOT terminated.
func TestSLO_AttackerSignedRequest_Rejected_NoTermination(t *testing.T) {
	t.Parallel()
	const nameID = "carol@example.com"
	hh, _, sid := newSLOHarness(t, nameID)

	attacker := newSPKeypair(t) // NOT the registered SP cert
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", attacker)
	rec := hh.getSLO(q)

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q was terminated by an ATTACKER-signed logout (security violation): %v", sid, err)
	}
}

// TestSLO_TamperedRequest_Rejected_NoTermination: a VALID detached signature but
// the SAMLRequest bytes are swapped after signing — the reconstructed octet
// string no longer matches, so verification fails and nothing is terminated.
func TestSLO_TamperedRequest_Rejected_NoTermination(t *testing.T) {
	t.Parallel()
	const nameID = "trent@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	good := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", spKey)
	other := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: "mallory@example.com"}, "", nil)
	gv, _ := url.ParseQuery(good)
	ov, _ := url.ParseQuery(other)
	tampered := "SAMLRequest=" + url.QueryEscape(ov.Get("SAMLRequest")) +
		"&SigAlg=" + url.QueryEscape(gv.Get("SigAlg")) +
		"&Signature=" + url.QueryEscape(gv.Get("Signature"))
	rec := hh.getSLO(tampered)

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q was terminated by a TAMPERED logout (security violation): %v", sid, err)
	}
}

// TestSLO_UnregisteredSP_Rejected: a (well-formed, signed) LogoutRequest whose
// Issuer is not a registered SP is rejected.
func TestSLO_UnregisteredSP_Rejected(t *testing.T) {
	t.Parallel()
	const nameID = "dave@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: "https://evil.example.com/saml", nameID: nameID}, "", spKey)
	rec := hh.getSLO(q)

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q terminated for an unregistered SP: %v", sid, err)
	}
}

// TestSLO_Replay_Rejected: the SAME detached-signed LogoutRequest replayed is
// rejected (its ID is deduped within the freshness window). The session
// re-established after the first logout is NOT re-terminated by the replay.
func TestSLO_Replay_Rejected(t *testing.T) {
	t.Parallel()
	const nameID = "rachel@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{id: "id-fixed-idp-1", issuer: spEntityID, nameID: nameID}, "", spKey)
	if rec := hh.getSLO(q); rec.Code != http.StatusFound {
		t.Fatalf("first (fresh) SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := hh.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("session %q should be terminated by the first logout", sid)
	}

	// Re-establish a session for the same subject, then REPLAY the exact request.
	sid2 := hh.seedUserSession(t, nameID)
	rec := hh.getSLO(q)
	assertRequestInvalidOnly(t, rec)
	// The replay must NOT terminate the re-established session.
	if _, err := hh.sessions.Get(context.Background(), sid2); err != nil {
		t.Fatalf("re-established session %q was terminated by a REPLAYED logout (replay violation): %v", sid2, err)
	}
}

// TestSLO_StaleIssueInstant_Rejected: a validly-signed LogoutRequest whose
// IssueInstant predates the freshness window is rejected, nothing terminated.
func TestSLO_StaleIssueInstant_Rejected(t *testing.T) {
	t.Parallel()
	const nameID = "sam@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	stale := fixedNow.Add(-(DefaultLogoutRequestWindow + time.Minute))
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID, issueInstant: stale}, "", spKey)
	rec := hh.getSLO(q)

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q terminated by a STALE logout: %v", sid, err)
	}
}

// TestSLO_FutureIssueInstant_Rejected: a validly-signed LogoutRequest whose
// IssueInstant is far in the FUTURE (beyond skew) is rejected.
func TestSLO_FutureIssueInstant_Rejected(t *testing.T) {
	t.Parallel()
	const nameID = "fiona@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	future := fixedNow.Add(logoutMaxClockSkew + time.Minute)
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID, issueInstant: future}, "", spKey)
	rec := hh.getSLO(q)

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q terminated by a FUTURE logout: %v", sid, err)
	}
}

// TestSLO_PostBinding_Enveloped_TerminatesAndAutoPosts proves the HTTP-POST
// binding still works with ENVELOPED XML-DSig (the redirect binding moved to
// detached §3.4.4.1; POST keeps the enveloped form): a POSTed enveloped-signed
// LogoutRequest terminates the session and the IdP returns the enveloped
// auto-POST LogoutResponse form to the registered SLO URL.
func TestSLO_PostBinding_Enveloped_TerminatesAndAutoPosts(t *testing.T) {
	t.Parallel()
	const nameID = "post@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	body := buildSPLogoutPostBody(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, spKey)
	rec := hh.postSLO(body, "rs")

	if rec.Code != http.StatusOK {
		t.Fatalf("POST SLO status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := hh.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("session %q should be terminated by the POST enveloped SLO", sid)
	}
	// The enveloped auto-POST form to the REGISTERED SLO URL.
	form := rec.Body.String()
	if !strings.Contains(form, `action="`+spSLOURL+`"`) {
		t.Fatalf("POST response form does not target the registered SLO URL %q; body=%s", spSLOURL, form)
	}
	if extractInputValue(t, form, "SAMLResponse") == "" {
		t.Fatalf("no SAMLResponse in POST response form")
	}
}

// TestSLO_PostBinding_Unsigned_Rejected: an UNSIGNED POST LogoutRequest is
// rejected (no enveloped Signature) — the fail-closed property holds on the POST
// binding too.
func TestSLO_PostBinding_Unsigned_Rejected(t *testing.T) {
	t.Parallel()
	const nameID = "postbob@example.com"
	hh, _, sid := newSLOHarness(t, nameID)

	// Unsigned plain base64 (no enveloped Signature).
	req := &saml.LogoutRequest{
		ID:           "id-lo-" + randHex(),
		Version:      "2.0",
		IssueInstant: fixedNow,
		Destination:  testIssuer + "/saml/slo",
		Issuer:       &saml.Issuer{Value: spEntityID},
		NameID:       &saml.NameID{Value: nameID},
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, _ := doc.WriteToBytes()
	rec := hh.postSLO(base64.StdEncoding.EncodeToString(raw), "")

	assertRequestInvalidOnly(t, rec)
	if _, err := hh.sessions.Get(context.Background(), sid); err != nil {
		t.Fatalf("session %q terminated by an UNSIGNED POST logout (security violation): %v", sid, err)
	}
}

// TestSLO_SLOURLNotRegistered_TerminatesButNoResponse: when the SP registered NO
// SLO URL, a valid signed LogoutRequest still terminates the session (the kill
// is authenticated) but the IdP sends NO LogoutResponse (nowhere allowlisted to
// send it) — proving the response goes ONLY to a registered URL, never a
// request-supplied one.
func TestSLO_SLOURLNotRegistered_TerminatesButNoResponse(t *testing.T) {
	t.Parallel()
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

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", spKey)
	rec := hh.getSLO(q)

	// No registered SLO URL ⇒ 200 with no body (the kill happened; nowhere
	// allowlisted to redirect the LogoutResponse to).
	if rec.Code != http.StatusOK {
		t.Fatalf("SLO status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// Session terminated (the request was authenticated).
	if _, err := hh.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("session %q should be terminated even without a registered SLO URL", sid)
	}
	// NO LogoutResponse emitted (no Location, empty body — nowhere to send it).
	if loc := rec.Header().Get("Location"); loc != "" {
		t.Fatalf("expected no Location (no registered SLO URL), got: %s", loc)
	}
	if b := strings.TrimSpace(rec.Body.String()); b != "" {
		t.Fatalf("expected empty body (no response without a registered SLO URL), got: %s", b)
	}
}

// TestSLO_OnlyMatchingSubjectTerminated proves a logout for one subject does NOT
// terminate another subject's session — the termination is scoped to the
// request's NameID, never a global wipe.
func TestSLO_OnlyMatchingSubjectTerminated(t *testing.T) {
	t.Parallel()
	const target = "frank@example.com"
	hh, spKey, targetSID := newSLOHarness(t, target)

	// A second, unrelated subject with a live session.
	otherSID := hh.seedUserSession(t, "grace@example.com")

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: target}, "", spKey)
	if rec := hh.getSLO(q); rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
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
	t.Parallel()
	const nameID = "ghost@example.com"
	hh, spKey, sid := newSLOHarness(t, nameID)

	// Destroy the session first so there is nothing to terminate.
	if err := hh.sessions.Destroy(context.Background(), sid); err != nil {
		t.Fatalf("pre-destroy session: %v", err)
	}

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", spKey)
	rec := hh.getSLO(q)

	// Still a 302 Success LogoutResponse — identical to the case where a session
	// existed (no oracle).
	if rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	respEl := inflateLogoutResponseEl(t, u.Query().Get("SAMLResponse"))
	assertStatusSuccess(t, respEl)
}

// TestSLO_Malformed_Rejected: a structurally-broken SAMLRequest collapses to the
// one oracle-safe code.
func TestSLO_Malformed_Rejected(t *testing.T) {
	t.Parallel()
	hh, _, _ := newSLOHarness(t, "h@example.com")
	rec := hh.getSLO("SAMLRequest=" + url.QueryEscape("not-valid-base64-$$$"))
	assertRequestInvalidOnly(t, rec)
}

// TestSLO_LogoutResponse_DetachedSigValidates is the SP-facing interop proof:
// the LogoutResponse this IdP emits at /saml/slo carries a DETACHED §3.4.4.1
// signature (SigAlg+Signature query params, UNSIGNED body) that verifies against
// the IdP's pinned signing cert — the format a real SP validates. (crewjam's own
// ValidateLogoutResponse* does NOT validate detached redirect signatures — it
// re-inflates the body and checks an ENVELOPED sig — so it cannot be the
// reference here; see TestSLO_AcceptsCrewjamDetachedRedirectSig for the genuine
// crewjam cross-validation, which uses the one message crewjam DOES detached-
// sign: the AuthnRequest redirect.)
func TestSLO_LogoutResponse_DetachedSigValidates(t *testing.T) {
	t.Parallel()
	const nameID = "interop@example.com"
	hh, spKey, _ := newSLOHarness(t, nameID)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", spKey)
	rec := hh.getSLO(q)
	if rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	idpCert := idpSignerCert(t, hh.signerFor(t))
	// The IdP's detached LogoutResponse signature verifies against the IdP cert.
	assertIDPDetachedSigVerifies(t, u.RawQuery, "SAMLResponse", idpCert)
	// And the body is UNSIGNED with Status Success.
	respEl := inflateLogoutResponseEl(t, u.Query().Get("SAMLResponse"))
	if sig := respEl.FindElement("//Signature"); sig != nil {
		t.Error("redirect SAMLResponse body must be UNSIGNED (detached binding)")
	}
	assertStatusSuccess(t, respEl)
}

// TestSLO_AcceptsCrewjamDetachedRedirectSig cross-validates this module's
// detached §3.4.4.1 verifier against CREWJAM's own spec-compliant detached
// redirect signer. crewjam v0.5.1 produces a detached query-param signature ONLY
// for the AuthnRequest redirect (its MakeRedirectLogoutRequest/Response instead
// EMBED an enveloped sig in the deflated body — the non-interoperable form this
// fix replaces, and the reason we hand-roll §3.4.4.1 for SLO). So we drive
// crewjam's AuthnRequest.Redirect (signed with an SP key), then prove this
// module's verifyRedirectSignature accepts the resulting SigAlg+Signature over
// the octet string — confirming our reconstruction byte-matches crewjam's.
func TestSLO_AcceptsCrewjamDetachedRedirectSig(t *testing.T) {
	t.Parallel()
	spKey := newSPKeypair(t)

	// A crewjam ServiceProvider that signs its AuthnRequest redirect (detached)
	// with the SP key, pointed at this IdP's SSO endpoint.
	ssoURL, _ := url.Parse(testIssuer + "/saml/sso")
	acsURL, _ := url.Parse(spACSURL)
	spSvc := &saml.ServiceProvider{
		EntityID:        spEntityID,
		Key:             spKey.key,
		Certificate:     spKey.cert,
		AcsURL:          *acsURL,
		SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
		IDPMetadata: &saml.EntityDescriptor{
			EntityID: testEntityID,
			IDPSSODescriptors: []saml.IDPSSODescriptor{{
				SSODescriptor: saml.SSODescriptor{
					RoleDescriptor: saml.RoleDescriptor{},
				},
				SingleSignOnServices: []saml.Endpoint{{
					Binding:  saml.HTTPRedirectBinding,
					Location: ssoURL.String(),
				}},
			}},
		},
	}

	u, err := spSvc.MakeRedirectAuthenticationRequest("relay-xyz")
	if err != nil {
		t.Fatalf("crewjam MakeRedirectAuthenticationRequest: %v", err)
	}
	if u.Query().Get("Signature") == "" || u.Query().Get("SigAlg") == "" {
		t.Fatalf("crewjam did not emit a detached redirect signature; query=%s", u.RawQuery)
	}

	// This module's verifier must accept crewjam's detached signature over the
	// AuthnRequest octet string (param name "SAMLRequest").
	if err := verifyRedirectSignature(spKey.cert, u.RawQuery, "SAMLRequest"); err != nil {
		t.Fatalf("module verifier REJECTED crewjam's spec-compliant detached signature (interop break): %v", err)
	}
	// Sanity: stripping the Signature must fail closed.
	stripped := stripIDPQueryParam(u.RawQuery, "Signature")
	if err := verifyRedirectSignature(spKey.cert, stripped, "SAMLRequest"); err == nil {
		t.Fatal("module verifier accepted crewjam request with NO Signature (must fail closed)")
	}
}

// --- LogoutResponse parsing/verification helpers (detached redirect binding) ---

// inflateLogoutResponseEl base64-decodes + raw-inflates a redirect-binding
// SAMLResponse query value into its root element.
func inflateLogoutResponseEl(t *testing.T, respB64 string) *etree.Element {
	t.Helper()
	comp, err := base64.StdEncoding.DecodeString(respB64)
	if err != nil {
		t.Fatalf("base64 decode LogoutResponse: %v", err)
	}
	fr := flate.NewReader(bytes.NewReader(comp))
	defer func() { _ = fr.Close() }()
	raw, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("inflate LogoutResponse: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("parse LogoutResponse xml: %v", err)
	}
	return doc.Root()
}

// idpSignerCert returns the IdP signer's certificate (the detached-signature
// trust anchor a real SP would pin).
func idpSignerCert(t *testing.T, signer *AssertionSigner) *x509.Certificate {
	t.Helper()
	cert, err := signer.Certificate()
	if err != nil {
		t.Fatalf("idp signer cert: %v", err)
	}
	return cert
}

// assertIDPDetachedSigVerifies confirms the DETACHED §3.4.4.1 signature in
// rawQuery (param = "SAMLResponse") verifies against the IdP cert.
func assertIDPDetachedSigVerifies(t *testing.T, rawQuery, param string, cert *x509.Certificate) {
	t.Helper()
	if err := verifyRedirectSignature(cert, rawQuery, param); err != nil {
		t.Fatalf("detached %s signature did not verify: %v", param, err)
	}
}

// stripIDPQueryParam removes the named parameter from a raw query string (for
// fail-closed "missing Signature" assertions).
func stripIDPQueryParam(rawQuery, key string) string {
	parts := strings.Split(rawQuery, "&")
	out := parts[:0]
	for _, p := range parts {
		name := p
		if i := strings.IndexByte(p, '='); i >= 0 {
			name = p[:i]
		}
		if name == key {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, "&")
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
