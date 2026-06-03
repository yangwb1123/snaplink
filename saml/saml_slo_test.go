package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	samlmod "github.com/snaplink/sso/saml"
	"github.com/snaplink/sso/saml/idp"
	"github.com/snaplink/sso/saml/sp"
)

const (
	idpSLOURL = "https://idp.example.com/saml/slo"
	spSLOURL  = "https://sp.example.com/auth/saml/slo"
)

// buildSLOServer wires saml.Build with one cert-pinned SP that ALSO carries an
// SP signing key + the SP/IdP SLO URLs, returning the mounted SP-SLO handler +
// the session manager + the IdP keypair (whose cert is pinned, so it signs the
// IdP-initiated LogoutRequest).
func buildSLOServer(t *testing.T) (http.HandlerFunc, sso.SessionManager, *idpKey) {
	t.Helper()
	idp := newIDPKey(t)
	spKeyPEM, spCertPEM := newSPSLOKey(t)
	sessions := defaultimpl.NewMemorySessionManager()

	res, err := samlmod.Build(samlmod.Deps{
		SessionManager: sessions,
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
		ClientStore:    defaultimpl.NewMemoryClientStore(),
	}, samlmod.Config{
		SPs: []sp.SPConfig{{
			Name:         "test-idp",
			EntityID:     spEntity,
			ACSURL:       acsURL,
			IDPCert:      idp.certPEM(),
			IDPEntityID:  idpEntity,
			SPPrivateKey: spKeyPEM,
			SPCert:       spCertPEM,
			SPSLOURL:     spSLOURL,
			IDPSLOURL:    idpSLOURL,
		}},
	})
	if err != nil {
		t.Fatalf("saml.Build: %v", err)
	}

	// The SP SLO handler is identical for GET+POST (the serve method switches on
	// method internally); grab the GET one — the tests exercise the HTTP-Redirect
	// binding the IdP uses for SLO (DEFLATEd SAMLRequest).
	var slo *samlmod.HandlerSpec
	for i := range res.Handlers {
		h := &res.Handlers[i]
		if h.Path == sso.PathSAMLSPSLO && h.Method == http.MethodGet {
			slo = h
		}
	}
	if slo == nil {
		t.Fatalf("Build mounted no GET %s handler", sso.PathSAMLSPSLO)
	}
	return slo.Handler, sessions, idp
}

// TestSPSLO_EndToEnd_SignedRequest_TerminatesLocalSession proves the wired SP
// SLO handler terminates the LOCAL session for the IdP-initiated LogoutRequest's
// subject (asserted gone via the real Memory SessionManager) and returns a 302
// signed LogoutResponse redirect to the IdP.
func TestSPSLO_EndToEnd_SignedRequest_TerminatesLocalSession(t *testing.T) {
	handler, sessions, idp := buildSLOServer(t)

	const nameID = "alice@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	q := mintLogoutRedirectQuery(t, idp, idpEntity, nameID, "", spSLOURL, "rs")
	rec := postSPSLO(handler, q)

	// no-store on every SLO path.
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	// The LOCAL session is GONE.
	if s, err := sessions.Get(context.Background(), sess.ID); err == nil && s != nil {
		t.Fatalf("local session %q should be terminated by IdP-initiated SLO", sess.ID)
	}

	// The 302 Location is a signed LogoutResponse redirect to the IdP SLO.
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if u.Scheme+"://"+u.Host+u.Path != idpSLOURL {
		t.Errorf("Location = %q, want a redirect to %q", loc, idpSLOURL)
	}
	if u.Query().Get("SAMLResponse") == "" {
		t.Errorf("Location missing SAMLResponse: %q", loc)
	}
}

// TestSPSLO_EndToEnd_UnsignedRequest_NoTermination is the wired-path crux: an
// UNSIGNED IdP LogoutRequest is rejected and the local session SURVIVES.
func TestSPSLO_EndToEnd_UnsignedRequest_NoTermination(t *testing.T) {
	handler, sessions, _ := buildSLOServer(t)

	const nameID = "bob@example.com"
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	q := mintLogoutRedirectQuery(t, nil, idpEntity, nameID, "", spSLOURL, "") // unsigned
	rec := postSPSLO(handler, q)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unsigned logout; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLRequestInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLRequestInvalid)
	}
	// The session MUST survive an unsigned logout.
	if _, err := sessions.Get(context.Background(), sess.ID); err != nil {
		t.Fatalf("local session %q terminated by an UNSIGNED logout (security violation): %v", sess.ID, err)
	}
}

// TestSPSLO_EndToEnd_OnlySubjectTerminated proves the wired handler scopes
// termination to the request's subject — a second subject's session is
// untouched.
func TestSPSLO_EndToEnd_OnlySubjectTerminated(t *testing.T) {
	handler, sessions, idp := buildSLOServer(t)

	target, err := sessions.Create(context.Background(), "carol@example.com")
	if err != nil {
		t.Fatalf("create target session: %v", err)
	}
	other, err := sessions.Create(context.Background(), "dave@example.com")
	if err != nil {
		t.Fatalf("create other session: %v", err)
	}

	q := mintLogoutRedirectQuery(t, idp, idpEntity, "carol@example.com", "", spSLOURL, "")
	if rec := postSPSLO(handler, q); rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	if _, err := sessions.Get(context.Background(), target.ID); err == nil {
		t.Fatalf("target session %q should be terminated", target.ID)
	}
	if _, err := sessions.Get(context.Background(), other.ID); err != nil {
		t.Fatalf("unrelated session %q terminated (global-wipe bug): %v", other.ID, err)
	}
}

// TestSLO_SPtoIdPtoSP_RoundTrip is the full snaplink SP→IdP→SP interop proof on
// the NEW detached §3.4.4.1 format: the repo's OWN SP side builds a SP-initiated
// LogoutRequest redirect (detached-signed with the SP key), the repo's OWN IdP
// side (pinned to that SP's cert) validates it, terminates the session, and
// returns a detached-signed LogoutResponse redirect whose signature verifies
// against the IdP's signing cert the SP pinned. Both halves speak §3.4.4.1.
func TestSLO_SPtoIdPtoSP_RoundTrip(t *testing.T) {
	const nameID = "roundtrip@example.com"
	idpEntityID := asIssuer + "/saml"
	idpSLOURL := asIssuer + sso.PathSAMLSLO

	issuer, _ := newRSAIssuer(t)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()

	// The IdP's signing cert (wraps the issuer key) — what the SP pins as its IdP
	// trust anchor. The detached signature verifies against the key, so a cert
	// built independently over the same key validates the handler's signature.
	idpCert := idpSigningCert(t, issuer, idpEntityID)

	// The SP's signing material (the IdP pins its cert to authenticate the SP's
	// LogoutRequest).
	spKeyPEM, spCertPEM := newSPSLOKey(t)

	// Register the SP at the IdP WITH its signing cert + SLO URL.
	if err := clients.Add(context.Background(), &sso.Client{
		ID:     "rt-sp",
		Active: true,
		Attributes: map[string]string{
			idp.AttrSPEntityID:    spEntity,
			idp.AttrSPACSURLs:     acsURL,
			idp.AttrSPSigningCert: string(spCertPEM),
			idp.AttrSPSLOUrls:     spSLOURL,
		},
	}); err != nil {
		t.Fatalf("register SP: %v", err)
	}

	res, err := samlmod.Build(samlmod.Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    defaultimpl.NewMemoryUserProvider(),
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "t", issuer, nil },
		Issuer:          asIssuer,
	}, samlmod.Config{IdP: samlmod.IdPConfig{Enabled: true}})
	if err != nil {
		t.Fatalf("saml.Build: %v", err)
	}
	idpSLO := findHandler(t, res, http.MethodGet, sso.PathSAMLSLO)

	// The SP, pinned to the IdP cert + entity id, with the IdP SLO URL.
	spAuth, err := sp.NewSPAuthenticator(sp.SPConfig{
		Name:         "rt-idp",
		EntityID:     spEntity,
		ACSURL:       acsURL,
		IDPCert:      pemCert(idpCert),
		IDPEntityID:  idpEntityID,
		SPPrivateKey: spKeyPEM,
		SPCert:       spCertPEM,
		SPSLOURL:     spSLOURL,
		IDPSLOURL:    idpSLOURL,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator: %v", err)
	}

	// A live session for the subject at the IdP.
	sess, err := sessions.Create(context.Background(), nameID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// SP builds the SP-initiated LogoutRequest redirect (detached-signed).
	logoutURL := spAuth.LogoutURL(nameID, "", "rs-roundtrip")
	if logoutURL == "" {
		t.Fatal("SP LogoutURL returned empty")
	}
	lu, err := url.Parse(logoutURL)
	if err != nil {
		t.Fatalf("parse LogoutURL: %v", err)
	}
	if lu.Scheme+"://"+lu.Host+lu.Path != idpSLOURL {
		t.Fatalf("SP LogoutURL points at %q, want IdP SLO %q", lu.Scheme+"://"+lu.Host+lu.Path, idpSLOURL)
	}

	// Drive the IdP's /saml/slo with the SP's exact raw query (detached sig).
	req := httptest.NewRequest(http.MethodGet, idpSLOURL+"?"+lu.RawQuery, nil)
	rec := httptest.NewRecorder()
	idpSLO(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("IdP SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	// The IdP terminated the session.
	if _, err := sessions.Get(context.Background(), sess.ID); err == nil {
		t.Fatalf("session %q should be terminated by the SP-initiated SLO", sess.ID)
	}
	// The IdP's LogoutResponse redirect goes back to the SP's registered SLO URL
	// and its detached signature verifies against the IdP cert the SP pinned.
	resp, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP response Location: %v", err)
	}
	if resp.Scheme+"://"+resp.Host+resp.Path != spSLOURL {
		t.Fatalf("IdP LogoutResponse redirect points at %q, want SP SLO %q", resp.Scheme+"://"+resp.Host+resp.Path, spSLOURL)
	}
	verifyDetachedAgainstCert(t, resp.RawQuery, "SAMLResponse", idpCert)
}

// --- helpers ---

// findHandler returns the mounted handler for the given method+path.
func findHandler(t *testing.T, res *samlmod.BuildResult, method, path string) http.HandlerFunc {
	t.Helper()
	for i := range res.Handlers {
		h := &res.Handlers[i]
		if h.Path == path && h.Method == method {
			return h.Handler
		}
	}
	t.Fatalf("Build mounted no %s %s handler", method, path)
	return nil
}

// idpSigningCert builds the IdP signing cert that wraps the issuer's key (the
// trust anchor a downstream SP pins). It resolves the issuer's CryptoSigner the
// same way the IdP handler does, then mints the self-signed cert via the
// exported AssertionSigner — the detached signature verifies against the key, so
// this independently-built cert validates the handler's LogoutResponse.
func idpSigningCert(t *testing.T, issuer sso.TokenIssuer, idpEntityID string) *x509.Certificate {
	t.Helper()
	cs, ok := issuer.(interface {
		CryptoSigner() (crypto.Signer, crypto.PublicKey, string)
	})
	if !ok {
		t.Fatalf("issuer does not expose CryptoSigner")
	}
	signer, pub, kid := cs.CryptoSigner()
	as, err := idp.NewAssertionSigner(signer, pub, kid, idpEntityID)
	if err != nil {
		t.Fatalf("NewAssertionSigner: %v", err)
	}
	cert, err := as.Certificate()
	if err != nil {
		t.Fatalf("AssertionSigner cert: %v", err)
	}
	return cert
}

// pemCert PEM-encodes a certificate (for SPConfig.IDPCert).
func pemCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// verifyDetachedAgainstCert verifies a DETACHED §3.4.4.1 signature in rawQuery
// (param = "SAMLResponse"/"SAMLRequest") against cert via x509.CheckSignature —
// the same primitive each side's verifier uses. Asserts the signature is present
// and valid (and that a missing Signature fails).
func verifyDetachedAgainstCert(t *testing.T, rawQuery, param string, cert *x509.Certificate) {
	t.Helper()
	vals, _ := url.ParseQuery(rawQuery)
	sigB64 := vals.Get("Signature")
	sigAlg := vals.Get("SigAlg")
	if sigB64 == "" || sigAlg == "" {
		t.Fatalf("detached signature missing (SigAlg=%q Signature present=%v)", sigAlg, sigB64 != "")
	}
	if sigAlg != "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" {
		t.Fatalf("unexpected SigAlg %q", sigAlg)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode Signature: %v", err)
	}
	// Reconstruct the signed octet string from the RAW values in §3.4.4.1 order.
	octet := param + "=" + rawRedirectVal(rawQuery, param)
	if rs, ok := rawRedirectValOK(rawQuery, "RelayState"); ok {
		octet += "&RelayState=" + rs
	}
	octet += "&SigAlg=" + rawRedirectVal(rawQuery, "SigAlg")
	if err := cert.CheckSignature(x509.SHA256WithRSA, []byte(octet), sig); err != nil {
		t.Fatalf("detached %s signature did not verify against the pinned IdP cert: %v", param, err)
	}
}

// rawRedirectVal / rawRedirectValOK extract a RAW (still-encoded) query value.
func rawRedirectVal(rawQuery, key string) string {
	v, _ := rawRedirectValOK(rawQuery, key)
	return v
}

func rawRedirectValOK(rawQuery, key string) (string, bool) {
	for _, pair := range strings.Split(rawQuery, "&") {
		if pair == "" {
			continue
		}
		name := pair
		val := ""
		if i := strings.IndexByte(pair, '='); i >= 0 {
			name, val = pair[:i], pair[i+1:]
		}
		if name == key {
			return val, true
		}
	}
	return "", false
}

// postSPSLO drives the SP SLO handler over the HTTP-Redirect binding (GET) using
// a FULL raw query string (so the detached §3.4.4.1 signature survives
// byte-for-byte — re-encoding via url.Values would break it), matching what a
// real IdP sends for SLO.
func postSPSLO(handler http.HandlerFunc, rawQuery string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, spSLOURL+"?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// newSPSLOKey returns a fresh RSA key + self-signed cert PEM-encoded for the SP
// signing material (SLO signing).
func newSPSLOKey(t *testing.T) (keyPEM, certPEM []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen SP key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "sp-slo-signer"},
		NotBefore:             time.Now().Add(-time.Hour),
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

// mintLogoutRedirectQuery builds an IdP-initiated LogoutRequest for nameID and,
// when signer != nil, signs it with the SAML-standard DETACHED §3.4.4.1
// redirect-binding signature (UNSIGNED XML body + SigAlg+Signature query params
// over the URL-encoded octet string) using the IdP key (the cert the SP pins) —
// exactly what a real IdP sends. Returns the FULL raw query string. An unsigned
// request (signer == nil) carries no SigAlg/Signature.
func mintLogoutRedirectQuery(t *testing.T, signer *idpKey, issuer, nameID, sessionIndex, dest, relayState string) string {
	t.Helper()
	req := &crewjam.LogoutRequest{
		ID:           "id-lo-" + randHex(),
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  dest,
		Issuer:       &crewjam.Issuer{Value: issuer},
		NameID:       &crewjam.NameID{Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &crewjam.SessionIndex{Value: sessionIndex}
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
		t.Fatalf("signing context: %v", err)
	}
	if err := ctx.SetSignatureMethod(rsaSHA256); err != nil {
		t.Fatalf("set sig method: %v", err)
	}
	sig, err := ctx.SignString(query)
	if err != nil {
		t.Fatalf("sign detached: %v", err)
	}
	query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	return query
}
