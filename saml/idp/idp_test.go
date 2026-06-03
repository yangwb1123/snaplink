package idp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"

	"github.com/snaplink/sso"
)

// --- Issued-assertion correctness + signature (the trust root) ---

// TestFinish_IssuesSignedAssertion_RSA drives the finish handler with an RSA
// issuer and asserts: 200, an auto-POST form to the REGISTERED ACS, a base64
// SAMLResponse whose ASSERTION (not just the Response) is XML-DSig signed and
// validates against the issuer's published cert, with the right audience,
// recipient, and InResponseTo.
func TestFinish_IssuesSignedAssertion_RSA(t *testing.T) {
	testFinishIssuesSignedAssertion(t, issuerRSA)
}

// TestFinish_IssuesSignedAssertion_ECDSA proves the ECDSA (ES256) path —
// crucially that the ASN.1-DER signature goxmldsig emits validates (the
// DER-vs-R‖S finding: no conversion, goxmldsig validates DER).
func TestFinish_IssuesSignedAssertion_ECDSA(t *testing.T) {
	testFinishIssuesSignedAssertion(t, issuerECDSA)
}

func testFinishIssuesSignedAssertion(t *testing.T, kind testIssuerKind) {
	t.Helper()
	hh := newHarness(t, kind)
	sessionID := hh.seedUserSession(t, "alice@example.com")
	requestID := "id-req-12345"
	pendingID := hh.insertPending(t, requestID)

	rec := hh.postFinish(sessionID, pendingID)
	if rec.Code != http.StatusOK {
		t.Fatalf("finish status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	assertNoStore(t, rec)
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	// The form action MUST be the REGISTERED ACS (assertion-exfil defense).
	body := rec.Body.String()
	if !strings.Contains(body, `action="`+spACSURL+`"`) {
		t.Errorf("form action is not the registered ACS %q; body=%s", spACSURL, body)
	}

	samlResponse := extractSAMLResponseFromForm(t, body)
	doc := decodeResponse(t, samlResponse)
	assertionEl := assertionElement(t, doc)

	// PROVE the assertion itself is signed: it carries a Signature child AND it
	// validates against the issuer's published cert via goxmldsig (the engine an
	// SP uses).
	if assertionEl.FindElement("./Signature") == nil {
		t.Fatalf("assertion has NO Signature child — it must be signed")
	}
	verifyAssertionSignature(t, assertionEl, hh.signerFor(t))

	// Audience == SP entity id.
	aud := assertionEl.FindElement(".//AudienceRestriction/Audience")
	if aud == nil || aud.Text() != spEntityID {
		t.Errorf("AudienceRestriction = %v, want %q", textOf(aud), spEntityID)
	}
	// Recipient == registered ACS.
	scd := assertionEl.FindElement(".//SubjectConfirmationData")
	if scd == nil || scd.SelectAttrValue("Recipient", "") != spACSURL {
		t.Errorf("Recipient = %q, want %q", attrOf(scd, "Recipient"), spACSURL)
	}
	// InResponseTo == request id (on both SubjectConfirmationData and Response).
	if got := scd.SelectAttrValue("InResponseTo", ""); got != requestID {
		t.Errorf("SubjectConfirmationData InResponseTo = %q, want %q", got, requestID)
	}
	if got := doc.Root().SelectAttrValue("InResponseTo", ""); got != requestID {
		t.Errorf("Response InResponseTo = %q, want %q", got, requestID)
	}
	// Issuer == IdP entity id.
	iss := assertionEl.FindElement("./Issuer")
	if iss == nil || iss.Text() != testEntityID {
		t.Errorf("Assertion Issuer = %q, want %q", textOf(iss), testEntityID)
	}
	// NotOnOrAfter is in the future (short bearer window).
	conds := assertionEl.FindElement("./Conditions")
	if conds == nil {
		t.Fatalf("no Conditions element")
	}
	noa := conds.SelectAttrValue("NotOnOrAfter", "")
	ts, err := time.Parse(time.RFC3339, noa)
	if err != nil {
		t.Fatalf("parse NotOnOrAfter %q: %v", noa, err)
	}
	if !ts.After(fixedNow) {
		t.Errorf("Conditions NotOnOrAfter %v is not after now %v", ts, fixedNow)
	}
}

// --- ACS allowlist enforcement (assertion-exfiltration defense) ---

// TestSSO_ACSNotInAllowlist_Rejected proves an AuthnRequest whose ACS URL is
// NOT in the SP's registered saml_sp_acs_urls is rejected at /saml/sso BEFORE
// any pending request is stored (so no assertion can ever be issued to it).
func TestSSO_ACSNotInAllowlist_Rejected(t *testing.T) {
	hh := newHarness(t, issuerRSA)

	evilACS := "https://attacker.example.com/steal"
	authnReq := makeAuthnRequest(t, spEntityID, evilACS, "id-req-evil")
	rec := hh.getSSO(authnReq)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unregistered ACS; body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec, sso.ErrSAMLRequestInvalid)
	// No pending request was stored (rejection happened before Insert).
	if n := hh.h.pending.len(); n != 0 {
		t.Errorf("a pending request was stored for an unregistered ACS: %d", n)
	}
}

// TestSSO_ACSInAllowlist_RedirectsToLogin proves the happy SSO leg: a
// registered ACS yields a stored pending request + a 302 to /auth/login with
// client_id + state.
func TestSSO_ACSInAllowlist_RedirectsToLogin(t *testing.T) {
	hh := newHarness(t, issuerRSA)

	authnReq := makeAuthnRequest(t, spEntityID, spACSURL, "id-req-ok")
	rec := hh.getSSO(authnReq)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	assertNoStore(t, rec)
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/auth/login?") {
		t.Fatalf("Location = %q, want /auth/login?...", loc)
	}
	if !strings.Contains(loc, "client_id="+spClientID) {
		t.Errorf("Location missing client_id=%s: %q", spClientID, loc)
	}
	if !strings.Contains(loc, "state=") {
		t.Errorf("Location missing state=<saml_request_id>: %q", loc)
	}
	if n := hh.h.pending.len(); n != 1 {
		t.Errorf("pending count = %d, want 1", n)
	}
}

// TestSSO_UnknownSP_Rejected proves an AuthnRequest from an Issuer not
// registered as any client's saml_sp_entity_id is rejected (oracle-safe).
func TestSSO_UnknownSP_Rejected(t *testing.T) {
	hh := newHarness(t, issuerRSA)
	authnReq := makeAuthnRequest(t, "https://unknown.example.com/saml", spACSURL, "id-req-x")
	rec := hh.getSSO(authnReq)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for unknown SP", rec.Code)
	}
	assertErrorCode(t, rec, sso.ErrSAMLRequestInvalid)
}

// --- Oracle-safety: pending unknown/expired/consumed + invalid session ---

// TestFinish_OracleSafe_AllCollapseToOneCode enumerates the four failure modes
// (unknown saml_request_id, expired pending, replayed/consumed pending, invalid
// session) and asserts each yields the IDENTICAL 400 saml_request_invalid with
// no distinguishing detail.
func TestFinish_OracleSafe_AllCollapseToOneCode(t *testing.T) {
	t.Run("unknown_request_id", func(t *testing.T) {
		hh := newHarness(t, issuerRSA)
		sessionID := hh.seedUserSession(t, "bob@example.com")
		rec := hh.postFinish(sessionID, "nonexistent-request-id")
		assertRequestInvalidOnly(t, rec)
	})

	t.Run("expired_pending", func(t *testing.T) {
		hh := newHarness(t, issuerRSA)
		sessionID := hh.seedUserSession(t, "bob@example.com")
		// Insert a pending request already past its deadline.
		id, err := hh.h.pending.Insert(PendingRequest{
			SPClientID: spClientID, SPEntityID: spEntityID, ACSURL: spACSURL,
			RequestID: "id-req-exp", ExpiresAt: time.Now().Add(-time.Minute),
		})
		if err != nil {
			t.Fatalf("insert: %v", err)
		}
		rec := hh.postFinish(sessionID, id)
		assertRequestInvalidOnly(t, rec)
	})

	t.Run("consumed_replay", func(t *testing.T) {
		hh := newHarness(t, issuerRSA)
		sessionID := hh.seedUserSession(t, "bob@example.com")
		pendingID := hh.insertPending(t, "id-req-replay")
		// First finish consumes it (success).
		if rec := hh.postFinish(sessionID, pendingID); rec.Code != http.StatusOK {
			t.Fatalf("first finish status = %d, want 200; body=%s", rec.Code, rec.Body.String())
		}
		// Replay the SAME saml_request_id → single-use → collapsed code.
		rec := hh.postFinish(sessionID, pendingID)
		assertRequestInvalidOnly(t, rec)
	})

	t.Run("invalid_session", func(t *testing.T) {
		hh := newHarness(t, issuerRSA)
		// A live pending request, but a bogus session id.
		pendingID := hh.insertPending(t, "id-req-badsess")
		rec := hh.postFinish("not-a-real-session", pendingID)
		assertRequestInvalidOnly(t, rec)
	})

	t.Run("revoked_session", func(t *testing.T) {
		hh := newHarness(t, issuerRSA)
		sessionID := hh.seedUserSession(t, "carol@example.com")
		// Revoke the session, then try to finish.
		if err := hh.sessions.Destroy(context.Background(), sessionID); err != nil {
			t.Fatalf("destroy session: %v", err)
		}
		pendingID := hh.insertPending(t, "id-req-revoked")
		rec := hh.postFinish(sessionID, pendingID)
		assertRequestInvalidOnly(t, rec)
	})
}

// --- Per-tenant key isolation ---

// TestPerTenantKeyIsolation_TenantASignedByTenantAKey proves a tenant-A SP's
// assertion is signed by tenant-A's key (the one in tenant-A's metadata), NOT
// tenant-B's / a shared key. Two tenants get distinct issuer keys; the
// IssuerForClient closure routes by client's TenantID.
func TestPerTenantKeyIsolation_TenantASignedByTenantAKey(t *testing.T) {
	issuerA, pubA := newIssuer(t, issuerRSA)
	issuerB, pubB := newIssuer(t, issuerRSA)
	if pubA == nil || pubB == nil {
		t.Fatal("nil pub")
	}

	clients := newClientStore(t)
	sessions := newSessionManager(t)
	users := newUserProvider(t)

	// Two SP clients, one per tenant.
	addTenantSP(t, clients, "sp-a", "https://a.example.com/saml", "https://a.example.com/acs", "tenant-a")
	addTenantSP(t, clients, "sp-b", "https://b.example.com/saml", "https://b.example.com/acs", "tenant-b")

	h, err := NewHandlers(Deps{
		ClientStore:    clients,
		SessionManager: sessions,
		UserProvider:   users,
		IssuerForClient: func(c *sso.Client) (string, sso.TokenIssuer, error) {
			switch c.TenantID {
			case "tenant-a":
				return "a", issuerA, nil
			case "tenant-b":
				return "b", issuerB, nil
			default:
				return "", nil, context.DeadlineExceeded // unreachable in this test
			}
		},
		Issuer: testIssuer,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	h.deps.now = func() time.Time { return fixedNow }

	hh := &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuerA, signerPub: pubA}
	sessionID := hh.seedUserSession(t, "alice@a.example.com")

	// Pending request for the tenant-A SP.
	pendingID, err := h.pending.Insert(PendingRequest{
		SPClientID: "sp-a", SPEntityID: "https://a.example.com/saml", ACSURL: "https://a.example.com/acs",
		RequestID: "id-req-a",
	})
	if err != nil {
		t.Fatalf("insert pending: %v", err)
	}

	rec := hh.postFinish(sessionID, pendingID)
	if rec.Code != http.StatusOK {
		t.Fatalf("finish status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	samlResponse := extractSAMLResponseFromForm(t, rec.Body.String())
	doc := decodeResponse(t, samlResponse)
	assertionEl := assertionElement(t, doc)

	// Signed by tenant-A's key (validates against the SP-A signer cert) ...
	signerA := newSignerForClient(t, h, clients, "sp-a")
	verifyAssertionSignature(t, assertionEl, signerA)

	// ... and NOT by tenant-B's key (validation against B's cert MUST fail).
	signerB := newSignerForClient(t, h, clients, "sp-b")
	if assertionValidatesAgainst(assertionEl, signerB) {
		t.Fatal("tenant-A assertion validated against tenant-B's key — KEY ISOLATION BROKEN")
	}
	// Sanity: the two tenant signers really hold different keys/certs.
	cA, _ := signerA.Certificate()
	cB, _ := signerB.Certificate()
	if string(cA.Raw) == string(cB.Raw) {
		t.Fatal("tenant A and B resolved the same cert — test setup is not isolating keys")
	}
	_ = pubA
	_ = pubB
}

// TestFinish_Ed25519Issuer_FailsClosed proves an Ed25519 signing key (no
// XML-DSig method) fails CLOSED with saml_assertion_failed (500), never an
// unsigned assertion or a cross-key fallback.
func TestFinish_Ed25519Issuer_FailsClosed(t *testing.T) {
	hh := newHarness(t, issuerEd25519)
	sessionID := hh.seedUserSession(t, "dave@example.com")
	pendingID := hh.insertPending(t, "id-req-ed")

	rec := hh.postFinish(sessionID, pendingID)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 for Ed25519 issuer; body=%s", rec.Code, rec.Body.String())
	}
	assertErrorCode(t, rec, sso.ErrSAMLAssertionFailed)
	// Absolutely no SAMLResponse leaked.
	if strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Error("a SAMLResponse was emitted despite the signing key being unusable")
	}
}

// --- Metadata ---

// TestMetadata_ContainsSigningCertMatchingAssertionKey proves /saml/metadata
// publishes a signing cert that wraps the same key assertions are signed with:
// the cert validates an assertion the IdP issues.
func TestMetadata_ContainsSigningCertMatchingAssertionKey(t *testing.T) {
	hh := newHarness(t, issuerRSA)

	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	rec := httptest.NewRecorder()
	hh.h.Metadata(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("metadata status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "public") {
		t.Errorf("Cache-Control = %q, want public", cc)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("metadata missing ETag")
	}

	// Parse the metadata, pull the signing cert, and confirm it equals the
	// AssertionSigner's cert (the assertion-signing key).
	var meta saml.EntityDescriptor
	if err := xmlUnmarshalStrict(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	certB64 := signingCertFromMetadata(t, &meta)
	wantCert, err := hh.signerFor(t).Certificate()
	if err != nil {
		t.Fatalf("signer cert: %v", err)
	}
	if certB64 != base64.StdEncoding.EncodeToString(wantCert.Raw) {
		t.Error("metadata signing cert does NOT match the assertion-signing key cert")
	}
}

// TestMetadata_ConditionalRequest_304 proves the ETag/If-None-Match path.
func TestMetadata_ConditionalRequest_304(t *testing.T) {
	hh := newHarness(t, issuerRSA)

	rec1 := httptest.NewRecorder()
	hh.h.Metadata(rec1, httptest.NewRequest(http.MethodGet, "/saml/metadata", nil))
	etag := rec1.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}

	req := httptest.NewRequest(http.MethodGet, "/saml/metadata", nil)
	req.Header.Set("If-None-Match", etag)
	rec2 := httptest.NewRecorder()
	hh.h.Metadata(rec2, req)
	if rec2.Code != http.StatusNotModified {
		t.Errorf("conditional status = %d, want 304", rec2.Code)
	}
}

// --- helpers local to this file ---

func textOf(e *etree.Element) string {
	if e == nil {
		return "<nil>"
	}
	return e.Text()
}

func attrOf(e *etree.Element, k string) string {
	if e == nil {
		return "<nil>"
	}
	return e.SelectAttrValue(k, "")
}

// assertNoStore checks the credential-endpoint cache headers.
func assertNoStore(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma = %q, want no-cache", got)
	}
}

// assertErrorCode asserts the JSON body's error == code.
func assertErrorCode(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != code {
		t.Errorf("error = %q, want %q (body=%s)", body[sso.KeyError], code, rec.Body.String())
	}
}

// assertRequestInvalidOnly asserts 400 + EXACTLY {error: saml_request_invalid}
// (no distinguishing detail — the oracle-safety contract).
func assertRequestInvalidOnly(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body[sso.KeyError] != sso.ErrSAMLRequestInvalid {
		t.Errorf("error = %q, want %q", body[sso.KeyError], sso.ErrSAMLRequestInvalid)
	}
	if len(body) != 1 {
		t.Errorf("body = %v, want exactly {error:...} (no detail leak)", body)
	}
}

// signingCertFromMetadata extracts the base64 signing cert from parsed metadata.
func signingCertFromMetadata(t *testing.T, meta *saml.EntityDescriptor) string {
	t.Helper()
	if len(meta.IDPSSODescriptors) == 0 {
		t.Fatal("metadata has no IDPSSODescriptor")
	}
	for _, kd := range meta.IDPSSODescriptors[0].KeyDescriptors {
		if kd.Use == "signing" && len(kd.KeyInfo.X509Data.X509Certificates) > 0 {
			return kd.KeyInfo.X509Data.X509Certificates[0].Data
		}
	}
	t.Fatal("no signing KeyDescriptor cert in metadata")
	return ""
}
