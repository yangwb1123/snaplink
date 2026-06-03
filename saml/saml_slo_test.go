package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
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

	samlReq := mintLogoutRequest(t, idp, idpEntity, nameID, "", spSLOURL)
	rec := postSPSLO(handler, samlReq, "rs")

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

	samlReq := mintLogoutRequest(t, nil, idpEntity, nameID, "", spSLOURL) // unsigned
	rec := postSPSLO(handler, samlReq, "")

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

	samlReq := mintLogoutRequest(t, idp, idpEntity, "carol@example.com", "", spSLOURL)
	if rec := postSPSLO(handler, samlReq, ""); rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	if _, err := sessions.Get(context.Background(), target.ID); err == nil {
		t.Fatalf("target session %q should be terminated", target.ID)
	}
	if _, err := sessions.Get(context.Background(), other.ID); err != nil {
		t.Fatalf("unrelated session %q terminated (global-wipe bug): %v", other.ID, err)
	}
}

// --- helpers ---

// postSPSLO drives the SP SLO handler over the HTTP-Redirect binding (GET): the
// DEFLATEd base64 SAMLRequest rides as a query parameter, matching what an IdP
// sends for SLO.
func postSPSLO(handler http.HandlerFunc, samlRequest, relayState string) *httptest.ResponseRecorder {
	q := url.Values{}
	q.Set("SAMLRequest", samlRequest)
	if relayState != "" {
		q.Set("RelayState", relayState)
	}
	req := httptest.NewRequest(http.MethodGet, spSLOURL+"?"+q.Encode(), nil)
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

// mintLogoutRequest builds an IdP-initiated LogoutRequest for nameID and, when
// signer != nil, enveloped-signs it with the IdP key (the cert the SP pins).
// Returns the base64 raw-DEFLATE redirect-binding encoding.
func mintLogoutRequest(t *testing.T, signer *idpKey, issuer, nameID, sessionIndex, dest string) string {
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
		el, err = ctx.SignEnveloped(req.Element())
		if err != nil {
			t.Fatalf("sign enveloped: %v", err)
		}
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize logout request: %v", err)
	}
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	_, _ = fw.Write(raw)
	_ = fw.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
