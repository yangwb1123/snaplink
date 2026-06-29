package saml_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	samlmod "github.com/snaplink/sso/saml"
	"github.com/snaplink/sso/saml/idp"
	"github.com/snaplink/sso/saml/sp"
)

// deflateBytes raw-DEFLATEs b for the SAML HTTP-Redirect binding.
func deflateBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	if _, err := fw.Write(b); err != nil {
		t.Fatalf("deflate: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}
	return buf.Bytes()
}

const (
	asIssuer = "https://sso.example.com"
	// The downstream SP that THIS server issues assertions to.
	dsSPEntity = "https://downstream.example.com/saml/metadata"
	dsSPACS    = "https://downstream.example.com/saml/acs"
	dsSPClient = "downstream-sp"
)

// TestBuild_IdPEnabled_MountsThreeHandlers proves cfg.IdP.Enabled appends the
// three IdP routes (metadata + sso GET/POST + sso/finish) on top of the SP ACS.
func TestBuild_IdPEnabled_MountsThreeHandlers(t *testing.T) {
	t.Parallel()
	issuer, _ := newRSAIssuer(t)
	clients := defaultimpl.NewMemoryClientStore()

	res, err := samlmod.Build(samlmod.Deps{
		ClientStore:     clients,
		SessionManager:  defaultimpl.NewMemorySessionManager(),
		UserProvider:    defaultimpl.NewMemoryUserProvider(),
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "t", issuer, nil },
		Issuer:          asIssuer,
	}, samlmod.Config{
		IdP: samlmod.IdPConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("Build IdP-only: %v", err)
	}

	want := map[string]bool{
		"GET " + sso.PathSAMLMetadata:         false,
		"GET " + sso.PathSAMLSSO:              false,
		"POST " + sso.PathSAMLSSO:             false,
		"POST " + sso.PathSAMLSSO + "/finish": false,
	}
	for _, h := range res.Handlers {
		want[h.Method+" "+h.Path] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("IdP handler %q not mounted", k)
		}
	}
}

// TestBuild_NothingRequested_Errors proves Build refuses a config with neither
// SPs nor the IdP enabled.
func TestBuild_NothingRequested_Errors(t *testing.T) {
	t.Parallel()
	_, err := samlmod.Build(samlmod.Deps{
		SessionManager: defaultimpl.NewMemorySessionManager(),
		UserProvider:   defaultimpl.NewMemoryUserProvider(),
	}, samlmod.Config{})
	if err == nil || !strings.Contains(err.Error(), "nothing to build") {
		t.Errorf("err = %v, want nothing-to-build", err)
	}
}

// TestIdPToSP_RoundTrip is the end-to-end interop proof: THIS server's IdP
// issues a signed assertion, and the repo's OWN SP side (saml/sp) — pinned to
// the IdP's published metadata cert — validates it. This proves the issued
// assertion is byte-shaped + signed exactly as a downstream SP expects (the
// metadata cert matches the signing key; the assertion signature verifies
// through crewjam's XSW-resistant ParseXMLResponse).
func TestIdPToSP_RoundTrip(t *testing.T) {
	t.Parallel()
	issuer, _ := newRSAIssuer(t)

	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	// Register the downstream SP as a client with SAML attributes.
	if err := clients.Add(context.Background(), &sso.Client{
		ID:     dsSPClient,
		Active: true,
		Attributes: map[string]string{
			idp.AttrSPEntityID: dsSPEntity,
			idp.AttrSPACSURLs:  dsSPACS,
		},
	}); err != nil {
		t.Fatalf("add SP client: %v", err)
	}

	res, err := samlmod.Build(samlmod.Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "t", issuer, nil },
		Issuer:          asIssuer,
	}, samlmod.Config{
		IdP: samlmod.IdPConfig{Enabled: true},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	mux := handlerMux(res.Handlers)

	// 1) Fetch IdP metadata → the SP's pinned trust anchor.
	metaRec := httptest.NewRecorder()
	mux.ServeHTTP(metaRec, httptest.NewRequest(http.MethodGet, sso.PathSAMLMetadata, nil))
	if metaRec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d", metaRec.Code)
	}
	metadataXML := metaRec.Body.Bytes()

	// 2) Build the downstream SP authenticator, pinned to that metadata. Its
	// EntityID = the audience the IdP stamps (the SP's registered entity id);
	// its ACSURL = the recipient.
	spAuth, err := sp.NewSPAuthenticator(sp.SPConfig{
		Name:           "downstream",
		EntityID:       dsSPEntity,
		ACSURL:         dsSPACS,
		IDPMetadataXML: metadataXML,
	})
	if err != nil {
		t.Fatalf("NewSPAuthenticator from IdP metadata: %v", err)
	}

	// 3) Authenticate a user + drive the IdP SSO → finish to mint an assertion.
	if err := users.CreateOrUpdate(context.Background(), &sso.User{ID: "alice@example.com", Email: "alice@example.com"}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	sess, err := sessions.Create(context.Background(), "alice@example.com")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// SSO leg: an AuthnRequest from the downstream SP (HTTP-Redirect).
	requestID := "id-req-roundtrip"
	samlRequest := makeRedirectAuthnRequest(t, dsSPEntity, dsSPACS, requestID)
	ssoRec := httptest.NewRecorder()
	ssoReq := httptest.NewRequest(http.MethodGet, sso.PathSAMLSSO+"?"+url.Values{"SAMLRequest": {samlRequest}}.Encode(), nil)
	mux.ServeHTTP(ssoRec, ssoReq)
	if ssoRec.Code != http.StatusFound {
		t.Fatalf("SSO status = %d, want 302; body=%s", ssoRec.Code, ssoRec.Body.String())
	}
	// Extract the saml_request_id (state) the IdP minted.
	loc, _ := url.Parse(ssoRec.Header().Get("Location"))
	samlReqID := loc.Query().Get("state")
	if samlReqID == "" {
		t.Fatal("SSO redirect carried no state")
	}

	// Finish leg: POST session_id + saml_request_id.
	finRec := httptest.NewRecorder()
	finForm := url.Values{sso.KeySessionID: {sess.ID}, sso.KeyState: {samlReqID}}
	finReq := httptest.NewRequest(http.MethodPost, sso.PathSAMLSSO+"/finish", strings.NewReader(finForm.Encode()))
	finReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(finRec, finReq)
	if finRec.Code != http.StatusOK {
		t.Fatalf("finish status = %d, want 200; body=%s", finRec.Code, finRec.Body.String())
	}

	// 4) Pull the SAMLResponse out of the auto-POST form and feed it to the SP.
	samlResponse := inputValue(t, finRec.Body.String(), "SAMLResponse")
	if samlResponse == "" {
		t.Fatal("no SAMLResponse in finish form")
	}

	// THE INTEROP ASSERTION: the repo's own SP validates the IdP's assertion
	// against the IdP's published metadata cert.
	result, err := spAuth.ProcessAssertion(context.Background(), samlResponse, "")
	if err != nil {
		t.Fatalf("SP REJECTED the IdP-issued assertion: %v", err)
	}
	if result.UserID != "alice@example.com" {
		t.Errorf("SP got UserID = %q, want alice@example.com", result.UserID)
	}
	if result.ExternalID != "alice@example.com" {
		t.Errorf("SP got ExternalID = %q, want alice@example.com", result.ExternalID)
	}
}

// --- helpers ---

func newRSAIssuer(t *testing.T) (sso.TokenIssuer, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	return defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAKey(key)), &key.PublicKey
}

// handlerMux maps the saml.HandlerSpec list onto an http.ServeMux keyed by
// method+path (so GET vs POST on the same path dispatch correctly).
func handlerMux(specs []samlmod.HandlerSpec) *http.ServeMux {
	mux := http.NewServeMux()
	// Group handlers by path; dispatch by method.
	byPath := map[string]map[string]http.HandlerFunc{}
	for _, s := range specs {
		if byPath[s.Path] == nil {
			byPath[s.Path] = map[string]http.HandlerFunc{}
		}
		byPath[s.Path][s.Method] = s.Handler
	}
	for path, byMethod := range byPath {
		bm := byMethod
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			if h, ok := bm[r.Method]; ok {
				h(w, r)
				return
			}
			w.WriteHeader(http.StatusMethodNotAllowed)
		})
	}
	return mux
}

// makeRedirectAuthnRequest builds a base64+raw-deflate AuthnRequest for the
// HTTP-Redirect binding.
func makeRedirectAuthnRequest(t *testing.T, spEntity, acsURL, requestID string) string {
	t.Helper()
	req := &crewjam.AuthnRequest{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                time.Now(),
		Destination:                 asIssuer + "/saml/sso",
		AssertionConsumerServiceURL: acsURL,
		ProtocolBinding:             crewjam.HTTPPostBinding,
		Issuer:                      &crewjam.Issuer{Value: spEntity},
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize authn request: %v", err)
	}
	return base64.StdEncoding.EncodeToString(deflateBytes(t, raw))
}

func inputValue(t *testing.T, html, name string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(html); err != nil {
		t.Fatalf("parse form html: %v", err)
	}
	for _, in := range doc.FindElements("//input") {
		if in.SelectAttrValue("name", "") == name {
			return in.SelectAttrValue("value", "")
		}
	}
	return ""
}
