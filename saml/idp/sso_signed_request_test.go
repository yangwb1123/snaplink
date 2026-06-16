package idp

import (
	"context"
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

// registerSPRequireSigned registers an SP client that REQUIRES signed
// AuthnRequests, pinning signer's cert via saml_sp_signing_cert. This drives the
// IdP's verifyAuthnRequestSignature gate.
func registerSPRequireSigned(t *testing.T, clients *defaultimpl.MemoryClientStore, signer *spKeypair) {
	t.Helper()
	err := clients.Add(context.Background(), &sso.Client{
		ID:     spClientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID:             spEntityID,
			AttrSPACSURLs:              spACSURL,
			AttrSPRequireSignedRequest: "true",
			AttrSPSigningCert:          signer.certPEM(),
		},
	})
	if err != nil {
		t.Fatalf("register signed-required SP: %v", err)
	}
}

// buildSignedAuthnPOST builds an AuthnRequest carrying an ENVELOPED XML-DSig
// (signed with signer's key when signer != nil) and returns the base64 SAMLRequest
// for the HTTP-POST binding (plain base64, no deflate — that's the path the IdP's
// POST handler + verifyAuthnRequestSignature take). It also returns the raw signed
// bytes for tamper tests.
func buildSignedAuthnPOST(t *testing.T, issuer, acsURL, requestID string, signer *spKeypair) (samlRequestB64 string, raw []byte) {
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
		signed, err := ctx.SignEnveloped(el)
		if err != nil {
			t.Fatalf("sign enveloped: %v", err)
		}
		el = signed
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize authn request: %v", err)
	}
	return base64.StdEncoding.EncodeToString(b), b
}

// postSSO drives POST /saml/sso (the binding the enveloped-signature path uses).
func (hh *harness) postSSO(samlRequest string) *httptest.ResponseRecorder {
	form := url.Values{"SAMLRequest": {samlRequest}}
	req := httptest.NewRequest(http.MethodPost, "/saml/sso", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	hh.h.SSO(rec, req)
	return rec
}

// rsaSHA256 is the XML-DSig SignatureMethod URI used throughout the suite.
const rsaSHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

// newHarnessWithClients builds a harness over a PRE-POPULATED client store (so a
// test can register an SP with custom attributes — require-signed-request, pinned
// cert — before construction). Mirrors newHarness's wiring otherwise.
func newHarnessWithClients(t *testing.T, clients *defaultimpl.MemoryClientStore) *harness {
	t.Helper()
	issuer, pub := newIssuer(t, issuerRSA)
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
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

// TestSSO_SignedRequest_Valid_RedirectsToLogin is the IdP happy path for a
// require-signed SP: an AuthnRequest carrying a valid enveloped signature under
// the SP's PINNED cert passes verifyAuthnRequestSignature and yields the 302 to
// login.
func TestSSO_SignedRequest_Valid_RedirectsToLogin(t *testing.T) {
	clients := newClientStore(t)
	spKey := newSPKeypair(t)
	registerSPRequireSigned(t, clients, spKey)
	hh := newHarnessWithClients(t, clients)

	b64, _ := buildSignedAuthnPOST(t, spEntityID, spACSURL, "id-req-signed", spKey)
	rec := hh.postSSO(b64)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/auth/login?") {
		t.Fatalf("Location = %q, want /auth/login?...", loc)
	}
}

// TestSSO_SignedRequest_Unsigned_Rejected: a require-signed SP that sends NO
// enveloped signature is rejected (verifyAuthnRequestSignature finds nothing to
// validate) → oracle-safe saml_request_invalid, no pending stored.
func TestSSO_SignedRequest_Unsigned_Rejected(t *testing.T) {
	clients := newClientStore(t)
	spKey := newSPKeypair(t)
	registerSPRequireSigned(t, clients, spKey)
	hh := newHarnessWithClients(t, clients)

	b64, _ := buildSignedAuthnPOST(t, spEntityID, spACSURL, "id-req-unsigned", nil)
	rec := hh.postSSO(b64)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unsigned require-signed request", rec.Code)
	}
	assertErrorCode(t, rec, sso.ErrSAMLRequestInvalid)
	if n := hh.h.pending.len(); n != 0 {
		t.Errorf("a pending request was stored for an unsigned request: %d", n)
	}
}

// TestSSO_SignedRequest_AttackerKey_Rejected: an enveloped signature by a
// DIFFERENT key (not the SP's pinned cert) does not verify against the registered
// trust anchor → rejected. This is the alg/key-confusion defense — the verifier
// uses the PINNED cert, never one embedded in the request's KeyInfo.
func TestSSO_SignedRequest_AttackerKey_Rejected(t *testing.T) {
	clients := newClientStore(t)
	spKey := newSPKeypair(t)
	registerSPRequireSigned(t, clients, spKey)
	hh := newHarnessWithClients(t, clients)

	attacker := newSPKeypair(t) // the IdP pinned spKey, not this
	b64, _ := buildSignedAuthnPOST(t, spEntityID, spACSURL, "id-req-attacker", attacker)
	rec := hh.postSSO(b64)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for attacker-key signature", rec.Code)
	}
	assertErrorCode(t, rec, sso.ErrSAMLRequestInvalid)
}

// TestSSO_SignedRequest_Tampered_Rejected: a validly enveloped-signed request
// whose ACS URL is mutated AFTER signing breaks the XML-DSig digest → rejected.
// (Also note: even if the signature somehow passed, the mutated ACS would have to
// survive the ACS allowlist — this asserts the signature gate catches it first.)
func TestSSO_SignedRequest_Tampered_Rejected(t *testing.T) {
	clients := newClientStore(t)
	spKey := newSPKeypair(t)
	registerSPRequireSigned(t, clients, spKey)
	hh := newHarnessWithClients(t, clients)

	_, raw := buildSignedAuthnPOST(t, spEntityID, spACSURL, "id-req-tamper", spKey)
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatalf("parse signed: %v", err)
	}
	// Mutate the AssertionConsumerServiceURL attribute after signing.
	doc.Root().CreateAttr("AssertionConsumerServiceURL", "https://attacker.example.com/steal")
	tampered, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("re-serialize: %v", err)
	}
	rec := hh.postSSO(base64.StdEncoding.EncodeToString(tampered))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for tampered signed request", rec.Code)
	}
	assertErrorCode(t, rec, sso.ErrSAMLRequestInvalid)
}

// TestSSO_SignedRequest_NoPinnedCert_Rejected: a require-signed SP with an EMPTY
// pinned cert can never validate a signature → every signed request is rejected
// (covers verifyAuthnRequestSignature's empty-cert guard).
func TestSSO_SignedRequest_NoPinnedCert_Rejected(t *testing.T) {
	clients := newClientStore(t)
	if err := clients.Add(context.Background(), &sso.Client{
		ID:     spClientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID:             spEntityID,
			AttrSPACSURLs:              spACSURL,
			AttrSPRequireSignedRequest: "true",
			// AttrSPSigningCert deliberately omitted.
		},
	}); err != nil {
		t.Fatalf("add SP: %v", err)
	}
	hh := newHarnessWithClients(t, clients)

	spKey := newSPKeypair(t)
	b64, _ := buildSignedAuthnPOST(t, spEntityID, spACSURL, "id-req-nocert", spKey)
	rec := hh.postSSO(b64)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (no pinned cert)", rec.Code)
	}
	assertErrorCode(t, rec, sso.ErrSAMLRequestInvalid)
}

// TestVerifyAuthnRequestSignature_BadCertPEM directly exercises the cert-parse
// guards: a non-PEM and a PEM whose bytes aren't a cert both return an error.
func TestVerifyAuthnRequestSignature_BadCertPEM(t *testing.T) {
	if err := verifyAuthnRequestSignature([]byte("<x/>"), ""); err == nil {
		t.Fatal("empty cert PEM accepted")
	}
	if err := verifyAuthnRequestSignature([]byte("<x/>"), "not pem at all"); err == nil {
		t.Fatal("non-PEM cert accepted")
	}
	// Well-formed PEM block but garbage DER inside.
	badPEM := "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"
	if err := verifyAuthnRequestSignature([]byte("<x/>"), badPEM); err == nil {
		t.Fatal("PEM with non-cert bytes accepted")
	}
}
