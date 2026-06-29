package saml_test

import (
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

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	samlmod "github.com/snaplink/sso/saml"
	"github.com/snaplink/sso/saml/sp"
)

const (
	idpEntity = "https://idp.example.com"
	spEntity  = "https://sp.example.com/saml/metadata"
	acsURL    = "https://sp.example.com/auth/saml/callback"
)

// buildTestServer wires saml.Build with memory stores + one cert-pinned SP, and
// returns the mounted ACS handler plus the stores for assertions. The minted
// assertions (mintSignedResponse) are signed by idpKey, whose cert is pinned.
func buildTestServer(t *testing.T) (http.HandlerFunc, sso.SessionManager, sso.UserProvider, *idpKey) {
	t.Helper()
	idp := newIDPKey(t)
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	res, err := samlmod.Build(samlmod.Deps{
		SessionManager: sessions,
		UserProvider:   users,
		ClientStore:    defaultimpl.NewMemoryClientStore(),
	}, samlmod.Config{
		SPs: []sp.SPConfig{{
			Name:        "test-idp",
			EntityID:    spEntity,
			ACSURL:      acsURL,
			IDPCert:     idp.certPEM(),
			IDPEntityID: idpEntity,
		}},
	})
	if err != nil {
		t.Fatalf("saml.Build: %v", err)
	}
	// SP-only Build now mounts the ACS (POST /auth/saml/callback) PLUS the SP
	// SLO receiver (GET+POST /auth/saml/slo) — three routes. Find the ACS by
	// path (robust to route order) and assert the SLO routes are present.
	var acs *samlmod.HandlerSpec
	sloMethods := map[string]bool{}
	for i := range res.Handlers {
		h := &res.Handlers[i]
		switch h.Path {
		case sso.PathSAMLSSOCallback:
			if h.Method == http.MethodPost {
				acs = h
			}
		case sso.PathSAMLSPSLO:
			sloMethods[h.Method] = true
		}
	}
	if acs == nil {
		t.Fatalf("Build produced no POST %s handler; got %d handlers", sso.PathSAMLSSOCallback, len(res.Handlers))
	}
	if !sloMethods[http.MethodGet] || !sloMethods[http.MethodPost] {
		t.Fatalf("Build did not mount GET+POST %s (got %v)", sso.PathSAMLSPSLO, sloMethods)
	}
	if len(res.Authenticators) != 1 || res.Authenticators[0].Name() != "test-idp" {
		t.Fatalf("Build authenticators = %v, want one named test-idp", res.Authenticators)
	}
	return acs.Handler, sessions, users, idp
}

func TestACS_ValidAssertion_CreatesSession(t *testing.T) {
	t.Parallel()
	handler, sessions, users, idp := buildTestServer(t)

	resp := mintSignedResponse(t, idp, "alice@example.com", map[string]string{"email": "alice@example.com"})

	rec := postACS(handler, resp, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// no-store headers on the success path.
	assertNoStore(t, rec)

	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	sid := body[sso.KeySessionID]
	if sid == "" {
		t.Fatalf("response missing session_id: %v", body)
	}
	if body[sso.KeyStatus] != sso.StatusAuthenticated {
		t.Errorf("status = %q, want %q", body[sso.KeyStatus], sso.StatusAuthenticated)
	}

	// The session really exists in the manager.
	if _, err := sessions.Get(context.Background(), sid); err != nil {
		t.Errorf("session %q not found in manager: %v", sid, err)
	}
	// The user was upserted under the NameID.
	if _, err := users.GetByID(context.Background(), "alice@example.com"); err != nil {
		t.Errorf("user not upserted: %v", err)
	}
}

func TestACS_InvalidAssertion_400AndNoStore(t *testing.T) {
	t.Parallel()
	handler, sessions, _, _ := buildTestServer(t)

	// A structurally-valid base64 that is not a valid signed assertion.
	bogus := base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`))
	rec := postACS(handler, bogus, "")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	// no-store headers on the error path too (catastrophic to cache a cross-user 4xx).
	assertNoStore(t, rec)

	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLAssertionInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLAssertionInvalid)
	}
	// Body must carry ONLY the error code (no cause detail — oracle-safe).
	if len(body) != 1 {
		t.Errorf("error body = %v, want exactly {error:...} (no detail leak)", body)
	}
	// No session created on failure.
	all, _ := sessions.ListAll(context.Background())
	if len(all) != 0 {
		t.Errorf("a session was created on an invalid assertion: %d", len(all))
	}
}

func TestACS_MissingSAMLResponse_400(t *testing.T) {
	t.Parallel()
	handler, _, _, _ := buildTestServer(t)
	rec := postACS(handler, "", "") // empty SAMLResponse
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
	assertNoStore(t, rec)
}

func TestACS_GET_405(t *testing.T) {
	t.Parallel()
	handler, _, _, _ := buildTestServer(t)
	req := httptest.NewRequest(http.MethodGet, acsURL, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", rec.Code)
	}
	assertNoStore(t, rec) // no-store stamped before the method check
}

func TestACS_ReplayedAssertion_Rejected(t *testing.T) {
	t.Parallel()
	handler, _, _, idp := buildTestServer(t)
	resp := mintSignedResponse(t, idp, "carol@example.com", nil)

	if rec := postACS(handler, resp, ""); rec.Code != http.StatusOK {
		t.Fatalf("first POST status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// Same assertion again => replay => 400 saml_assertion_invalid.
	rec := postACS(handler, resp, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replay POST status = %d, want 400", rec.Code)
	}
}

func TestBuild_RejectsMissingDeps(t *testing.T) {
	t.Parallel()
	_, err := samlmod.Build(samlmod.Deps{
		UserProvider: defaultimpl.NewMemoryUserProvider(),
	}, samlmod.Config{SPs: []sp.SPConfig{{Name: "x"}}})
	if err == nil || !strings.Contains(err.Error(), "SessionManager required") {
		t.Errorf("Build without SessionManager err = %v, want SessionManager required", err)
	}

	_, err = samlmod.Build(samlmod.Deps{
		SessionManager: defaultimpl.NewMemorySessionManager(),
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
	}, samlmod.Config{})
	if err == nil || !strings.Contains(err.Error(), "at least one SP") {
		t.Errorf("Build with no SPs err = %v, want at-least-one-SP", err)
	}
}

func TestBuild_RejectsDuplicateSPNames(t *testing.T) {
	t.Parallel()
	idp := newIDPKey(t)
	spc := sp.SPConfig{
		Name: "dup", EntityID: spEntity, ACSURL: acsURL,
		IDPCert: idp.certPEM(), IDPEntityID: idpEntity,
	}
	_, err := samlmod.Build(samlmod.Deps{
		SessionManager: defaultimpl.NewMemorySessionManager(),
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
	}, samlmod.Config{SPs: []sp.SPConfig{spc, spc}})
	if err == nil || !strings.Contains(err.Error(), "duplicate SP name") {
		t.Errorf("Build with duplicate SP names err = %v, want duplicate-name", err)
	}
}

// --- helpers (a compact signed-assertion minter for the black-box ACS test) ---

func postACS(handler http.HandlerFunc, samlResponse, relayState string) *httptest.ResponseRecorder {
	form := url.Values{}
	form.Set("SAMLResponse", samlResponse)
	if relayState != "" {
		form.Set("RelayState", relayState)
	}
	req := httptest.NewRequest(http.MethodPost, acsURL, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func assertNoStore(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
}

type idpKey struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func newIDPKey(t *testing.T) *idpKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "idp"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &idpKey{key: key, cert: cert}
}

func (k *idpKey) certPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: k.cert.Raw})
}

// mintSignedResponse builds + signs (with the IdP key) a valid assertion for
// nameID with the given attributes, wrapped in a base64 SAMLResponse destined
// for the SP ACS, carrying an InResponseTo (SP-initiated posture).
func mintSignedResponse(t *testing.T, idp *idpKey, nameID string, attrs map[string]string) string {
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
					Recipient:    acsURL,
				},
			}},
		},
		Conditions: &crewjam.Conditions{
			NotBefore:    now.Add(-time.Minute),
			NotOnOrAfter: now.Add(5 * time.Minute),
			AudienceRestrictions: []crewjam.AudienceRestriction{{
				Audience: crewjam.Audience{Value: spEntity},
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
	if len(attrs) > 0 {
		stmt := crewjam.AttributeStatement{}
		for name, val := range attrs {
			stmt.Attributes = append(stmt.Attributes, crewjam.Attribute{
				Name:   name,
				Values: []crewjam.AttributeValue{{Type: "xs:string", Value: val}},
			})
		}
		a.AttributeStatements = []crewjam.AttributeStatement{stmt}
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
		Destination:  acsURL,
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

func randHex() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	const hexd = "0123456789abcdef"
	out := make([]byte, 24)
	for i, x := range b {
		out[i*2] = hexd[x>>4]
		out[i*2+1] = hexd[x&0x0f]
	}
	return string(out)
}
