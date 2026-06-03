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
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"
)

const (
	tIDPSLOURL = "https://idp.example.com/saml/slo"
	tSPSLOURL  = "https://sp.example.com/auth/saml/slo"
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

// buildIDPLogoutRequest builds an IdP-initiated LogoutRequest for nameID and,
// when signer != nil, enveloped-signs it with the IdP key. Returns the base64
// raw-DEFLATE redirect-binding encoding.
func buildIDPLogoutRequest(t *testing.T, issuer, nameID, sessionIndex string, dest string, signer *idpKeypair) string {
	t.Helper()
	req := &saml.LogoutRequest{
		ID:           "id-lo-" + randHex(),
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  dest,
		Issuer:       &saml.Issuer{Value: issuer},
		NameID:       &saml.NameID{Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &saml.SessionIndex{Value: sessionIndex}
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

// TestSP_ProcessLogoutRequest_Signed_ReturnsSubject is the SP-side happy path: a
// LogoutRequest signed by the PINNED IdP cert validates and yields the subject.
func TestSP_ProcessLogoutRequest_Signed_ReturnsSubject(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	req := buildIDPLogoutRequest(t, tIDPEntity, "alice@example.com", "sess-1", tSPSLOURL, idp)
	subj, err := a.ProcessLogoutRequest(req, "rs", true)
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

// TestSP_ProcessLogoutRequest_Unsigned_Rejected is the SP-side crux: an unsigned
// IdP LogoutRequest is rejected (ErrLogoutInvalid) — the SP must not log out on
// an unauthenticated request.
func TestSP_ProcessLogoutRequest_Unsigned_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	req := buildIDPLogoutRequest(t, tIDPEntity, "alice@example.com", "", tSPSLOURL, nil) // unsigned
	_, err := a.ProcessLogoutRequest(req, "", true)
	if !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("unsigned ProcessLogoutRequest err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_AttackerCert_Rejected: a LogoutRequest signed by a
// DIFFERENT (attacker) key — not the pinned IdP cert — is rejected.
func TestSP_ProcessLogoutRequest_AttackerCert_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	attacker := newIDPKeypair(t) // a different key the SP did NOT pin
	req := buildIDPLogoutRequest(t, tIDPEntity, "alice@example.com", "", tSPSLOURL, attacker)
	_, err := a.ProcessLogoutRequest(req, "", true)
	if !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("attacker-signed ProcessLogoutRequest err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_ProcessLogoutRequest_WrongIssuer_Rejected: a request signed by the
// pinned key but claiming a DIFFERENT Issuer is rejected (issuer-binding check).
func TestSP_ProcessLogoutRequest_WrongIssuer_Rejected(t *testing.T) {
	now := time.Now()
	idp := newIDPKeypair(t)
	a := newSLOSP(t, idp, now)

	req := buildIDPLogoutRequest(t, "https://rogue-idp.example.com", "alice@example.com", "", tSPSLOURL, idp)
	_, err := a.ProcessLogoutRequest(req, "", true)
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

	if _, err := a.ProcessLogoutRequest("not-base64-$$$", "", true); !errors.Is(err, ErrLogoutInvalid) {
		t.Fatalf("malformed err = %v, want ErrLogoutInvalid", err)
	}
}

// TestSP_LogoutURL_BuildsSignedRedirect: SP-initiated logout builds a signed
// LogoutRequest redirect to the IdP SLO endpoint that the IdP could validate
// against the SP's cert.
func TestSP_LogoutURL_BuildsSignedRedirect(t *testing.T) {
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
	// The embedded LogoutRequest is SIGNED with the SP key (validates against the
	// SP cert) and carries the subject.
	el := inflateAndParse(t, samlReq)
	verifySPSignedElement(t, el, a)
	if got := el.FindElement("//NameID"); got == nil || got.Text() != "alice@example.com" {
		t.Errorf("LogoutRequest NameID wrong; xml has no/incorrect NameID")
	}
}

// TestSP_BuildLogoutResponseURL_BuildsSignedRedirect: the SP's acknowledgement
// to an IdP-initiated logout is a signed LogoutResponse redirect to the IdP SLO.
func TestSP_BuildLogoutResponseURL_BuildsSignedRedirect(t *testing.T) {
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
	el := inflateAndParse(t, samlResp)
	verifySPSignedElement(t, el, a)
	if got := el.SelectAttrValue("InResponseTo", ""); got != "id-req-123" {
		t.Errorf("InResponseTo = %q, want id-req-123", got)
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
	defer fr.Close()
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

// verifySPSignedElement validates the enveloped signature on el against the SP's
// own signing cert (proving the SP signed its outbound LogoutRequest/Response).
func verifySPSignedElement(t *testing.T, el *etree.Element, a *SPAuthenticator) {
	t.Helper()
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{a.sloSigCert}}
	ctx := dsig.NewDefaultValidationContext(store)
	ctx.IdAttribute = "ID"
	if a.now != nil {
		ctx.Clock = dsig.NewFakeClockAt(a.now())
	}
	if _, err := ctx.Validate(el); err != nil {
		t.Fatalf("SP-signed element signature INVALID: %v", err)
	}
}
