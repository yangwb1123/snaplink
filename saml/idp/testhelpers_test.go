package idp

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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

// deflate raw-DEFLATEs b (the SAML HTTP-Redirect binding encoding) for a
// SAMLRequest the SSO handler will inflate.
func deflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatalf("flate writer: %v", err)
	}
	if _, err := fw.Write(b); err != nil {
		t.Fatalf("deflate write: %v", err)
	}
	if err := fw.Close(); err != nil {
		t.Fatalf("deflate close: %v", err)
	}
	return buf.Bytes()
}

const (
	testIssuer   = "https://sso.example.com"
	testEntityID = "https://sso.example.com/saml" // = testIssuer + "/saml"
	spEntityID   = "https://sp.example.com/saml/metadata"
	spACSURL     = "https://sp.example.com/saml/acs"
	spClientID   = "acme-sp"
)

// fixedNow is a stable clock for deterministic assertions.
var fixedNow = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

// testIssuerKind selects which signing-key issuer a harness wires.
type testIssuerKind int

const (
	issuerRSA testIssuerKind = iota
	issuerECDSA
	issuerEd25519
)

// harness bundles a constructed *Handlers with the stores + the issuer it signs
// with, so tests can drive the flow and validate against the same key.
type harness struct {
	h        *Handlers
	clients  *defaultimpl.MemoryClientStore
	sessions *defaultimpl.MemorySessionManager
	users    *defaultimpl.MemoryUserProvider
	issuer   sso.TokenIssuer
	// signerPub is the public key the issuer signs with (== the JWKS key == the
	// metadata cert key). Tests verify assertion signatures against it.
	signerPub crypto.PublicKey
}

// newHarness builds a Handlers wired to one in-memory issuer of the given kind,
// with the default SP client (spClientID) registered. The IssuerForClient
// closure returns the SAME issuer for every client (single-tenant); multi-tenant
// isolation is exercised by newMultiTenantHarness.
func newHarness(t *testing.T, kind testIssuerKind) *harness {
	t.Helper()
	issuer, pub := newIssuer(t, kind)

	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	registerSP(t, clients, spClientID, spEntityID, spACSURL)

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
	return &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
}

// newIssuer constructs an in-memory issuer of the given kind with a freshly
// generated key, returning it + its public key.
func newIssuer(t *testing.T, kind testIssuerKind) (sso.TokenIssuer, crypto.PublicKey) {
	t.Helper()
	switch kind {
	case issuerRSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("gen rsa: %v", err)
		}
		return defaultimpl.NewRSAJWTIssuer(defaultimpl.WithRSAKey(key)), &key.PublicKey
	case issuerECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("gen ecdsa: %v", err)
		}
		return defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSAKey(key)), &key.PublicKey
	case issuerEd25519:
		// Ed25519 issuer — used to prove the IdP fails closed (no XML-DSig).
		return defaultimpl.NewEd25519JWTIssuer(), nil
	default:
		t.Fatalf("unknown issuer kind")
		return nil, nil
	}
}

// registerSP adds an SP client with the SAML registration attributes.
func registerSP(t *testing.T, clients *defaultimpl.MemoryClientStore, clientID, entityID, acsURLs string) {
	t.Helper()
	err := clients.Add(context.Background(), &sso.Client{
		ID:     clientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID: entityID,
			AttrSPACSURLs:  acsURLs,
		},
	})
	if err != nil {
		t.Fatalf("add SP client %q: %v", clientID, err)
	}
}

// seedUserSession creates a user + a live session and returns the session id.
func (hh *harness) seedUserSession(t *testing.T, userID string) string {
	t.Helper()
	if err := hh.users.CreateOrUpdate(context.Background(), &sso.User{ID: userID, Email: userID}); err != nil {
		t.Fatalf("create user: %v", err)
	}
	sess, err := hh.sessions.Create(context.Background(), userID)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess.ID
}

// insertPending stores a pending request directly (bypassing the SSO leg) and
// returns the saml_request_id — for finish-handler tests that don't need the
// full redirect leg.
func (hh *harness) insertPending(t *testing.T, requestID string) string {
	t.Helper()
	id, err := hh.h.pending.Insert(PendingRequest{
		SPClientID: spClientID,
		SPEntityID: spEntityID,
		ACSURL:     spACSURL,
		RequestID:  requestID,
	})
	if err != nil {
		t.Fatalf("insert pending: %v", err)
	}
	return id
}

// postFinish drives POST /saml/sso/finish with the given session + request ids.
func (hh *harness) postFinish(sessionID, samlRequestID string) *httptest.ResponseRecorder {
	form := url.Values{
		sso.KeySessionID: {sessionID},
		sso.KeyState:     {samlRequestID},
	}
	req := httptest.NewRequest(http.MethodPost, "/saml/sso/finish", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	hh.h.Finish(rec, req)
	return rec
}

// --- AuthnRequest minting (drives the SSO leg) ---

// makeAuthnRequest builds a minimal AuthnRequest XML and returns it
// base64+raw-deflate encoded (HTTP-Redirect binding) ready for ?SAMLRequest=.
func makeAuthnRequest(t *testing.T, issuer, acsURL, requestID string) string {
	t.Helper()
	req := &saml.AuthnRequest{
		ID:                          requestID,
		Version:                     "2.0",
		IssueInstant:                fixedNow,
		Destination:                 testIssuer + "/saml/sso",
		AssertionConsumerServiceURL: acsURL,
		ProtocolBinding:             saml.HTTPPostBinding,
		Issuer:                      &saml.Issuer{Value: issuer},
	}
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize authn request: %v", err)
	}
	return base64.StdEncoding.EncodeToString(deflate(t, raw))
}

// getSSO drives GET /saml/sso with a SAMLRequest and returns the recorder.
func (hh *harness) getSSO(samlRequest string) *httptest.ResponseRecorder {
	u := "/saml/sso?" + url.Values{"SAMLRequest": {samlRequest}}.Encode()
	req := httptest.NewRequest(http.MethodGet, u, nil)
	rec := httptest.NewRecorder()
	hh.h.SSO(rec, req)
	return rec
}

// --- assertion validation helpers ---

// decodeResponse base64-decodes a SAMLResponse into an etree document.
func decodeResponse(t *testing.T, samlResponseB64 string) *etree.Document {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(samlResponseB64)
	if err != nil {
		t.Fatalf("base64 decode response: %v", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("parse response xml: %v", err)
	}
	return doc
}

// extractSAMLResponseFromForm pulls the base64 SAMLResponse out of the
// auto-POST HTML form the finish handler returns.
func extractSAMLResponseFromForm(t *testing.T, body string) string {
	t.Helper()
	val := extractInputValue(t, body, "SAMLResponse")
	return val
}

func extractInputValue(t *testing.T, body, name string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(body); err != nil {
		t.Fatalf("parse form html: %v", err)
	}
	for _, in := range doc.FindElements("//input") {
		if in.SelectAttrValue("name", "") == name {
			return in.SelectAttrValue("value", "")
		}
	}
	t.Fatalf("input %q not found in form: %s", name, body)
	return ""
}

// assertionElement returns the <Assertion> element inside the response.
func assertionElement(t *testing.T, doc *etree.Document) *etree.Element {
	t.Helper()
	root := doc.Root()
	for _, child := range root.ChildElements() {
		if child.Tag == "Assertion" {
			return child
		}
	}
	t.Fatalf("no Assertion element in response")
	return nil
}

// verifyAssertionSignature validates the assertion's enveloped XML-DSig against
// the IdP signing cert (resolved from the harness signer), using goxmldsig's
// ValidationContext — exactly the engine crewjam/the SP side uses. It returns
// the validated (signature-stripped) element. A validation failure fails the
// test. This proves the ASSERTION (the element passed in) is the signed one.
func verifyAssertionSignature(t *testing.T, assertionEl *etree.Element, signer *AssertionSigner) {
	t.Helper()
	cert, err := signer.Certificate()
	if err != nil {
		t.Fatalf("signer cert: %v", err)
	}
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(store)
	// Pin the validation clock inside the cert window so cert-validity never
	// trips (the synthetic cert is valid for 10y around now anyway).
	ctx.Clock = dsig.NewFakeClockAt(fixedNow)
	if _, err := ctx.Validate(assertionEl); err != nil {
		t.Fatalf("assertion signature INVALID: %v", err)
	}
}

// signerFor returns the EXACT AssertionSigner the handler uses for the default
// SP client (the cached one, so its cert byte-matches what assertions +
// metadata embed). Tests validate issued assertions against it.
func (hh *harness) signerFor(t *testing.T) *AssertionSigner {
	t.Helper()
	c, err := hh.clients.Get(context.Background(), spClientID)
	if err != nil {
		t.Fatalf("get SP client: %v", err)
	}
	s, err := hh.h.signerForClient(c)
	if err != nil {
		t.Fatalf("signerForClient: %v", err)
	}
	return s
}

// newSignerForClient returns the handler's cached AssertionSigner for an
// arbitrary registered SP client id (for the multi-tenant key-isolation test,
// where each tenant's SP resolves a distinct key).
func newSignerForClient(t *testing.T, h *Handlers, clients *defaultimpl.MemoryClientStore, clientID string) *AssertionSigner {
	t.Helper()
	c, err := clients.Get(context.Background(), clientID)
	if err != nil {
		t.Fatalf("get client %q: %v", clientID, err)
	}
	s, err := h.signerForClient(c)
	if err != nil {
		t.Fatalf("signerForClient(%q): %v", clientID, err)
	}
	return s
}

// assertionValidatesAgainst reports whether assertionEl's signature validates
// against signer's cert (used to PROVE a tenant-A assertion does NOT validate
// against tenant-B's key). Returns false on any validation error.
func assertionValidatesAgainst(assertionEl *etree.Element, signer *AssertionSigner) bool {
	cert, err := signer.Certificate()
	if err != nil {
		return false
	}
	store := &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}}
	ctx := dsig.NewDefaultValidationContext(store)
	ctx.Clock = dsig.NewFakeClockAt(fixedNow)
	_, err = ctx.Validate(assertionEl)
	return err == nil
}

// newClientStore / newSessionManager / newUserProvider are thin typed
// constructors for the multi-tenant test (which builds a Handlers by hand).
func newClientStore(t *testing.T) *defaultimpl.MemoryClientStore {
	t.Helper()
	return defaultimpl.NewMemoryClientStore()
}
func newSessionManager(t *testing.T) *defaultimpl.MemorySessionManager {
	t.Helper()
	return defaultimpl.NewMemorySessionManager()
}
func newUserProvider(t *testing.T) *defaultimpl.MemoryUserProvider {
	t.Helper()
	return defaultimpl.NewMemoryUserProvider()
}

// addTenantSP registers an SP client bound to a tenant (for key-isolation).
func addTenantSP(t *testing.T, clients *defaultimpl.MemoryClientStore, clientID, entityID, acsURL, tenantID string) {
	t.Helper()
	err := clients.Add(context.Background(), &sso.Client{
		ID:       clientID,
		Active:   true,
		TenantID: tenantID,
		Attributes: map[string]string{
			AttrSPEntityID: entityID,
			AttrSPACSURLs:  acsURL,
		},
	})
	if err != nil {
		t.Fatalf("add tenant SP %q: %v", clientID, err)
	}
}
