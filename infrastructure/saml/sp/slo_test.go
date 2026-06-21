package sp

import (
	"bytes"
	"compress/flate"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	tIDPSLOURL         = "https://idp.example.com/saml/slo"
	tIDPSLOContinueURL = "https://idp.example.com/saml/slo/continue"
	tSPSLOURL          = "https://sp.example.com/auth/saml/slo"
)

// newSPSigner generates an RSA keypair + self-signed cert and returns them
// PEM-encoded for SPConfig.SPPrivateKey/SPCert (the SP signing material used to
// sign outbound LogoutRequest/LogoutResponse).
func newSPSigner(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen SP key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "sp-signer"},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create SP cert: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return keyPEM, certPEM
}

// newSLOSP builds an SPAuthenticator pinned to the IdP signer's cert, WITH an SP
// signing key + the SP/IdP SLO URLs, at a fixed clock. This is the SP that both
// receives IdP-initiated LogoutRequests and initiates SP logout.
func newSLOSP(t *testing.T, idpSigner *idpKeypair, now time.Time) *SPAuthenticator {
	t.Helper()
	keyPEM, certPEM := newSPSigner(t)
	a, err := NewSPAuthenticator(SPConfig{
		Name:         "test-idp",
		EntityID:     tSPEntity,
		ACSURL:       tACSURL,
		IDPCert:      idpSigner.certPEM(),
		IDPEntityID:  tIDPEntity,
		SPPrivateKey: keyPEM,
		SPCert:       certPEM,
		SPSLOURL:     tSPSLOURL,
		IDPSLOURL:    tIDPSLOURL,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	a.now = func() time.Time { return now }
	return a
}

// logoutReq is the knobs for a test LogoutRequest (so freshness/replay tests can
// pin the ID + IssueInstant). Zero IssueInstant ⇒ time.Now() at build.
type logoutReq struct {
	id           string
	issuer       string
	nameID       string
	sessionIndex string
	dest         string
	issueInstant time.Time
}

// buildIDPLogoutRedirectQuery builds an IdP-initiated LogoutRequest per p and,
// when signer != nil, signs it with the SAML-standard DETACHED §3.4.4.1
// redirect-binding signature (UNSIGNED XML body + SigAlg+Signature query params
// over the URL-encoded octet string) using the IdP key — exactly what a real IdP
// (Okta/Azure/Shibboleth) sends. Returns the FULL raw query string (SAMLRequest
// [+ RelayState] [+ SigAlg + Signature]) ready to drive ProcessLogoutRequest's
// rawQuery param. An unsigned request (signer == nil) carries no SigAlg/Signature
// (the fail-closed-rejection case).
func buildIDPLogoutRedirectQuery(t *testing.T, p logoutReq, relayState string, signer *idpKeypair) string {
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
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize logout request: %v", err)
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write(raw)
	_ = fw.Close()
	samlReq := base64.StdEncoding.EncodeToString(buf.Bytes())

	// Octet string per §3.4.4.1: SAMLRequest=<v>[&RelayState=<v>]&SigAlg=<v>, all
	// URL-encoded, in this exact order.
	query := "SAMLRequest=" + url.QueryEscape(samlReq)
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if signer == nil {
		return query // unsigned: no SigAlg/Signature
	}
	query += "&SigAlg=" + url.QueryEscape(rsaSHA256)
	ctx, err := dsig.NewSigningContext(signer.key, [][]byte{signer.cert.Raw})
	if err != nil {
		t.Fatalf("signing context: %v", err)
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

// processRedirectLogout drives ProcessLogoutRequest over the HTTP-Redirect
// binding from a full raw query string: it extracts the SAMLRequest + RelayState
// values and passes the raw query through (so the detached signature is
// reconstructed from the exact wire bytes).
func processRedirectLogout(a *SPAuthenticator, rawQuery string) (*LogoutSubject, error) {
	vals, _ := url.ParseQuery(rawQuery)
	return a.ProcessLogoutRequest(vals.Get("SAMLRequest"), vals.Get("RelayState"), true, rawQuery)
}

// TestSP_ProcessLogoutRequest_Signed_ReturnsSubject is the SP-side happy path: a
// LogoutRequest carrying a DETACHED §3.4.4.1 signature under the PINNED IdP cert
// validates and yields the subject.
func TestSP_ProcessLogoutRequest_Signed_ReturnsSubject(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", sessionIndex: "sess-1", dest: tSPSLOURL}, "rs", idp)
	subj, err := processRedirectLogout(a, q)
	if err != nil {
		t.Fatalf("ProcessLogoutRequest valid signed = %v, want nil", err)
	}
	if subj.NameID != "alice@example.com" {
		t.Errorf("NameID = %q, want alice@example.com", subj.NameID)
	}
	if subj.SessionIndex != "sess-1" {
		t.Errorf("SessionIndex = %q, want sess-1", subj.SessionIndex)
	}
	if subj.RequestID == "" {
		t.Errorf("RequestID empty, want the inbound LogoutRequest ID")
	}
}

// TestSP_ProcessLogoutRequest_Unsigned_Rejected is the SP-side crux: a redirect
// LogoutRequest WITHOUT a detached signature (no SigAlg/Signature) is rejected
// (ErrLogoutInvalid) — the SP must not log out on an unauthenticated request.
// This is the fail-closed property preserved through the detached path.
func TestSP_ProcessLogoutRequest_Unsigned_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, "", nil) // unsigned
	_, err := processRedirectLogout(a, q)
	if !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("unsigned ProcessLogoutRequest err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_AttackerCert_Rejected: a LogoutRequest detached-
// signed by a DIFFERENT (attacker) key — not the pinned IdP cert — is rejected.
func TestSP_ProcessLogoutRequest_AttackerCert_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	attacker := newIDPKeypair(t) // a different key the SP did NOT pin
	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, "", attacker)
	_, err := processRedirectLogout(a, q)
	if !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("attacker-signed ProcessLogoutRequest err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_TamperedRequest_Rejected: a VALID detached
// signature, but the SAMLRequest bytes are swapped for a different request after
// signing — the reconstructed octet string no longer matches, so verification
// fails (signature-over-different-bytes detection).
func TestSP_ProcessLogoutRequest_TamperedRequest_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	good := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, "", idp)
	// A DIFFERENT (unsigned) request whose SAMLRequest we splice in under the good
	// SigAlg/Signature.
	otherQ := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "mallory@example.com", dest: tSPSLOURL}, "", nil)
	goodVals, _ := url.ParseQuery(good)
	otherVals, _ := url.ParseQuery(otherQ)
	tampered := "SAMLRequest=" + url.QueryEscape(otherVals.Get("SAMLRequest")) +
		"&SigAlg=" + url.QueryEscape(goodVals.Get("SigAlg")) +
		"&Signature=" + url.QueryEscape(goodVals.Get("Signature"))

	if _, err := processRedirectLogout(a, tampered); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("tampered SAMLRequest err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_WrongIssuer_Rejected: a request detached-signed by
// the pinned key but claiming a DIFFERENT Issuer is rejected (issuer-binding).
func TestSP_ProcessLogoutRequest_WrongIssuer_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: "https://rogue-idp.example.com", nameID: "alice@example.com", dest: tSPSLOURL}, "", idp)
	_, err := processRedirectLogout(a, q)
	if !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("wrong-issuer ProcessLogoutRequest err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_Malformed_Rejected: garbage base64 collapses to
// the one code.
func TestSP_ProcessLogoutRequest_Malformed_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	if _, err := a.ProcessLogoutRequest("not-base64-$$$", "", true, "SAMLRequest=not-base64-%24%24%24"); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("malformed err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_Replay_Rejected: the SAME signed LogoutRequest
// replayed is rejected (its ID is deduped within the freshness window), while a
// fresh distinct request still succeeds.
func TestSP_ProcessLogoutRequest_Replay_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	q := buildIDPLogoutRedirectQuery(t, logoutReq{id: "id-fixed-1", issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, "", idp)
	if _, err := processRedirectLogout(a, q); err != nil {
		t.Fatalf("first (fresh) logout = %v, want nil", err)
	}
	// EXACT same request bytes again ⇒ replay ⇒ rejected.
	if _, err := processRedirectLogout(a, q); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("replayed logout err = %v, want ErrLogoutInvalid", err)
	}
	// A distinct fresh request still works (the store dedups by ID, not blanket).
	q2 := buildIDPLogoutRedirectQuery(t, logoutReq{id: "id-fixed-2", issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, "", idp)
	if _, err := processRedirectLogout(a, q2); err != nil {
		t.Fatalf("second distinct logout = %v, want nil", err)
	}
}

// TestSP_ProcessLogoutRequest_StaleIssueInstant_Rejected: a validly-signed
// LogoutRequest whose IssueInstant is older than the freshness window is
// rejected (a captured-then-stale logout can't terminate a session).
func TestSP_ProcessLogoutRequest_StaleIssueInstant_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	stale := now.Add(-(DefaultLogoutRequestWindow + time.Minute))
	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL, issueInstant: stale}, "", idp)
	if _, err := processRedirectLogout(a, q); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("stale-IssueInstant logout err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_FutureIssueInstant_Rejected: a validly-signed
// LogoutRequest whose IssueInstant is far in the FUTURE (beyond skew) is
// rejected (a clock-forward forgery minted to outlive the window).
func TestSP_ProcessLogoutRequest_FutureIssueInstant_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	future := now.Add(logoutMaxClockSkew + time.Minute)
	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL, issueInstant: future}, "", idp)
	if _, err := processRedirectLogout(a, q); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("future-IssueInstant logout err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_LogoutURL_BuildsDetachedSignedRedirect: SP-initiated logout builds a
// redirect to the IdP SLO endpoint carrying a DETACHED §3.4.4.1 signature
// (SigAlg+Signature query params over the octet string), NOT an enveloped body
// signature — the form a real IdP validates. The XML body is UNSIGNED.
func TestSP_LogoutURL_BuildsDetachedSignedRedirect(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	raw := a.LogoutURL("alice@example.com", "sess-1", "relay-xyz")
	if raw == "" {
		t.Fatal("LogoutURL returned empty (want a signed redirect URL)")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse LogoutURL: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != tIDPSLOURL {
		t.Errorf("LogoutURL points at %q, want %q", u.Scheme+"://"+u.Host+u.Path, tIDPSLOURL)
	}
	if u.Query().Get("RelayState") != "relay-xyz" {
		t.Errorf("RelayState = %q, want relay-xyz", u.Query().Get("RelayState"))
	}
	samlReq := u.Query().Get("SAMLRequest")
	if samlReq == "" {
		t.Fatal("LogoutURL missing SAMLRequest")
	}
	// DETACHED signature present + carries the standard SigAlg URI.
	if got := u.Query().Get("SigAlg"); got != rsaSHA256 {
		t.Errorf("SigAlg = %q, want %q", got, rsaSHA256)
	}
	if u.Query().Get("Signature") == "" {
		t.Fatal("LogoutURL missing detached Signature query param")
	}
	// The detached signature verifies against the SP's own signing cert over the
	// exact octet string (the SP's verifier accepts what the SP signed).
	assertDetachedSigVerifies(t, u.RawQuery, "SAMLRequest", a.sloSigCert)
	// The XML body is UNSIGNED (no enveloped <Signature> child) and carries the
	// subject.
	el := inflateAndParse(t, samlReq)
	if sig := el.FindElement("//Signature"); sig != nil {
		t.Error("redirect SAMLRequest body must be UNSIGNED (detached binding), found an enveloped Signature")
	}
	if got := el.FindElement("//NameID"); got == nil || got.Text() != "alice@example.com" {
		t.Errorf("LogoutRequest NameID wrong; xml has no/incorrect NameID")
	}
}

// TestSP_BuildLogoutResponseURL_BuildsDetachedSignedRedirect: the SP's
// acknowledgement to an IdP-initiated logout is a DETACHED-signed LogoutResponse
// redirect to the IdP SLO.
func TestSP_BuildLogoutResponseURL_BuildsDetachedSignedRedirect(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	raw, err := a.BuildLogoutResponseURL("id-req-123", "relay-abc")
	if err != nil {
		t.Fatalf("BuildLogoutResponseURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse response URL: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != tIDPSLOURL {
		t.Errorf("response URL points at %q, want %q", u.Scheme+"://"+u.Host+u.Path, tIDPSLOURL)
	}
	samlResp := u.Query().Get("SAMLResponse")
	if samlResp == "" {
		t.Fatal("missing SAMLResponse")
	}
	if u.Query().Get("Signature") == "" {
		t.Fatal("BuildLogoutResponseURL missing detached Signature query param")
	}
	assertDetachedSigVerifies(t, u.RawQuery, "SAMLResponse", a.sloSigCert)
	el := inflateAndParse(t, samlResp)
	if sig := el.FindElement("//Signature"); sig != nil {
		t.Error("redirect SAMLResponse body must be UNSIGNED (detached binding), found an enveloped Signature")
	}
	if got := el.SelectAttrValue("InResponseTo", ""); got != "id-req-123" {
		t.Errorf("InResponseTo = %q, want id-req-123", got)
	}
}

// newFrontChannelSLOSP builds an SP like newSLOSP but ALSO configured for the
// IdP's FRONT-channel chain: IDPSLOResponseURL points at the IdP's
// /saml/slo/continue resume endpoint, so the SP redirects its LogoutResponse
// THERE (not the request endpoint).
func newFrontChannelSLOSP(t *testing.T, idpSigner *idpKeypair, now time.Time) *SPAuthenticator {
	t.Helper()
	keyPEM, certPEM := newSPSigner(t)
	a, err := NewSPAuthenticator(SPConfig{
		Name:              "test-idp-fc",
		EntityID:          tSPEntity,
		ACSURL:            tACSURL,
		IDPCert:           idpSigner.certPEM(),
		IDPEntityID:       tIDPEntity,
		SPPrivateKey:      keyPEM,
		SPCert:            certPEM,
		SPSLOURL:          tSPSLOURL,
		IDPSLOURL:         tIDPSLOURL,
		IDPSLOResponseURL: tIDPSLOContinueURL,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator (front-channel): %v", err)
	}
	a.now = func() time.Time { return now }
	return a
}

// TestSP_FrontChannel_ProcessRequest_RedirectsResponseToContinue is the SP-side
// front-channel proof: an inbound front-channel (redirect-binding) IdP
// LogoutRequest is validated + yields the subject, and the SP's LogoutResponse
// (built for the chain) redirects to the IdP's /saml/slo/continue RESUME endpoint
// (not the request endpoint), carrying a detached signature + the ECHOED
// RelayState (the chain-state id the IdP resumes on) + the InResponseTo binding.
func TestSP_FrontChannel_ProcessRequest_RedirectsResponseToContinue(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newFrontChannelSLOSP(t, idp, now)

	const chainState = "chain-state-id-xyz"
	// Inbound front-channel LogoutRequest (the IdP redirected the browser here),
	// carrying the chain-state id as RelayState.
	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, chainState, idp)
	subj, err := processRedirectLogout(a, q)
	if err != nil {
		t.Fatalf("ProcessLogoutRequest (front-channel) = %v, want nil", err)
	}

	// The SP builds its LogoutResponse for the chain: echoing the RelayState
	// verbatim so the IdP can resume.
	raw, err := a.BuildLogoutResponseURL(subj.RequestID, chainState)
	if err != nil {
		t.Fatalf("BuildLogoutResponseURL (front-channel): %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse response URL: %v", err)
	}
	// Target is the IdP's /continue RESUME endpoint, NOT the request endpoint.
	if got := u.Scheme + "://" + u.Host + u.Path; got != tIDPSLOContinueURL {
		t.Fatalf("front-channel response target = %q, want the continue endpoint %q", got, tIDPSLOContinueURL)
	}
	// RelayState echoed VERBATIM (the chain id).
	if rs := u.Query().Get("RelayState"); rs != chainState {
		t.Errorf("response RelayState = %q, want the echoed chain id %q", rs, chainState)
	}
	// Detached signature present + verifies against the SP cert; body unsigned.
	if u.Query().Get("Signature") == "" {
		t.Fatal("front-channel LogoutResponse missing detached Signature")
	}
	assertDetachedSigVerifies(t, u.RawQuery, "SAMLResponse", a.sloSigCert)
	el := inflateAndParse(t, u.Query().Get("SAMLResponse"))
	if sig := el.FindElement("//Signature"); sig != nil {
		t.Error("front-channel LogoutResponse body must be UNSIGNED (detached binding)")
	}
	if got := el.SelectAttrValue("InResponseTo", ""); got != subj.RequestID {
		t.Errorf("InResponseTo = %q, want the inbound request id %q", got, subj.RequestID)
	}
}

// TestSP_BackChannel_ResponseTargetsRequestEndpoint_Unchanged proves the
// back-channel / IdP-initiated default is UNCHANGED: with NO IDPSLOResponseURL
// configured, the SP's LogoutResponse still targets the IdP's request-side SLO
// endpoint (the pre-front-channel behavior).
func TestSP_BackChannel_ResponseTargetsRequestEndpoint_Unchanged(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now) // no IDPSLOResponseURL

	raw, err := a.BuildLogoutResponseURL("id-req-1", "rs")
	if err != nil {
		t.Fatalf("BuildLogoutResponseURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != tIDPSLOURL {
		t.Fatalf("back-channel response target = %q, want the request endpoint %q (unchanged)", got, tIDPSLOURL)
	}
}

// TestSP_RoundTrip_OwnDetachedSigVerifies: an SP-built outbound LogoutRequest's
// detached signature is accepted by the module's own redirect verifier against
// the SP cert (sign/verify symmetry within this module — the basis for SP↔IdP
// interop since both sides share these helpers).
func TestSP_RoundTrip_OwnDetachedSigVerifies(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	raw := a.LogoutURL("alice@example.com", "", "rs")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if err := verifyRedirectSignature([]*x509.Certificate{a.sloSigCert}, u.RawQuery, "SAMLRequest"); err != nil {
		t.Fatalf("SP's own detached LogoutRequest signature did not verify: %v", err)
	}
	// A missing-Signature query must fail closed (drop the Signature param).
	stripped := stripQueryParam(u.RawQuery, "Signature")
	if err := verifyRedirectSignature([]*x509.Certificate{a.sloSigCert}, stripped, "SAMLRequest"); err == nil {
		t.Fatal("verifyRedirectSignature accepted a query with NO Signature (must fail closed)")
	}
}

// TestSP_LogoutURL_NoKey_ReturnsEmpty: without an SP signing key the SLO helpers
// are inert (no unsigned logout is ever emitted).
func TestSP_LogoutURL_NoKey_ReturnsEmpty(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	// No SP key, but an IdP SLO URL set.
	a, err := NewSPAuthenticator(SPConfig{
		Name:        "test-idp",
		EntityID:    tSPEntity,
		ACSURL:      tACSURL,
		IDPCert:     idp.certPEM(),
		IDPEntityID: tIDPEntity,
		IDPSLOURL:   tIDPSLOURL,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}
	a.now = func() time.Time { return now }
	if got := a.LogoutURL("alice@example.com", "", ""); got != "" {
		t.Errorf("LogoutURL without SP key = %q, want empty", got)
	}
	if _, err := a.BuildLogoutResponseURL("id", ""); !errors.Is(err, ErrLogoutInvalid) {
		t.Errorf("BuildLogoutResponseURL without SP key err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_PeekLogoutRequestIssuer_ReadsIssuer proves PeekLogoutRequestIssuer
// decodes the Issuer from a wire (redirect-binding) LogoutRequest WITHOUT
// verifying the signature — the lookup key the SP-side multi-IdP SLO dispatcher
// uses. It reads the Issuer off an UNSIGNED request (peeking is signature-free).
func TestSP_PeekLogoutRequestIssuer_ReadsIssuer(t *testing.T) {
	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: tIDPEntity, nameID: "alice@example.com", dest: tSPSLOURL}, "rs", nil)
	vals, _ := url.ParseQuery(q)
	got, err := PeekLogoutRequestIssuer(vals.Get("SAMLRequest"), true)
	if err != nil {
		t.Fatalf("PeekLogoutRequestIssuer = %v, want nil", err)
	}
	if got != tIDPEntity {
		t.Errorf("peeked Issuer = %q, want %q", got, tIDPEntity)
	}
}

// TestSP_PeekLogoutRequestIssuer_Rejects covers the decode-failure + missing-Issuer
// cases — all collapse to ErrLogoutInvalid (oracle-safe), the same code the
// dispatcher maps to a 400.
func TestSP_PeekLogoutRequestIssuer_Rejects(t *testing.T) {
	// Garbage base64.
	if _, err := PeekLogoutRequestIssuer("not-base64-$$$", true); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("malformed peek err = %v, want ErrLogoutInvalid", err)
	}
	// A well-formed LogoutRequest with an EMPTY Issuer value.
	q := buildIDPLogoutRedirectQuery(t, logoutReq{issuer: "", nameID: "alice@example.com", dest: tSPSLOURL}, "", nil)
	vals, _ := url.ParseQuery(q)
	if _, err := PeekLogoutRequestIssuer(vals.Get("SAMLRequest"), true); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("empty-Issuer peek err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_IDPEntityID_ReturnsPinnedEntity proves the accessor returns the pinned
// upstream-IdP entity id (the value the dispatcher matches the inbound Issuer
// against, and the same one ProcessLogoutRequest checks the Issuer against).
func TestSP_IDPEntityID_ReturnsPinnedEntity(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)
	if got := a.IDPEntityID(); got != tIDPEntity {
		t.Errorf("IDPEntityID() = %q, want the pinned IdP entity id %q", got, tIDPEntity)
	}
}

// --- helpers ---

// inflateAndParse base64-decodes + raw-inflates a redirect-binding SAML message
// into its root element.
func inflateAndParse(t *testing.T, b64 string) *etree.Element {
	t.Helper()
	comp, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	fr := flate.NewReader(bytes.NewReader(comp))
	defer func() { _ = fr.Close() }()
	raw, err := io.ReadAll(fr)
	if err != nil {
		t.Fatalf("inflate: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("parse xml: %v", err)
	}
	return doc.Root()
}

// assertDetachedSigVerifies confirms the DETACHED §3.4.4.1 signature carried in
// rawQuery (param = "SAMLRequest"/"SAMLResponse") verifies against cert — i.e.
// the module's redirect verifier accepts what the SP signed.
func assertDetachedSigVerifies(t *testing.T, rawQuery, param string, cert *x509.Certificate) {
	t.Helper()
	if err := verifyRedirectSignature([]*x509.Certificate{cert}, rawQuery, param); err != nil {
		t.Fatalf("detached %s signature did not verify: %v", param, err)
	}
}

// stripQueryParam removes the named parameter from a raw query string (for the
// fail-closed "missing Signature" assertions).
func stripQueryParam(rawQuery, key string) string {
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
