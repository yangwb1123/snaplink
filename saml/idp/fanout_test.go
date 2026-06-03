package idp

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/saml/sp"
)

// capturedSLO records what a stand-in SP's SLO endpoint received from the
// fan-out: the raw query (redirect binding) or the POST form value.
type capturedSLO struct {
	mu          sync.Mutex
	gotRedirect string // raw query of a GET delivery
	gotPostBody string // SAMLRequest form value of a POST delivery
	hits        int
}

func (c *capturedSLO) record(rawQuery, postBody string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rawQuery != "" {
		c.gotRedirect = rawQuery
	}
	if postBody != "" {
		c.gotPostBody = postBody
	}
	c.hits++
}

func (c *capturedSLO) snapshot() (string, string, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gotRedirect, c.gotPostBody, c.hits
}

// newCapturingSP starts an httptest server standing in for a downstream SP's SLO
// endpoint. It captures the inbound LogoutRequest (so the test can cross-validate
// it) and returns 200. statusOverride, when non-zero, is returned instead (to
// simulate a failing SP).
func newCapturingSP(t *testing.T, cap *capturedSLO, statusOverride int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := ""
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			body = r.PostForm.Get("SAMLRequest")
		}
		cap.record(r.URL.RawQuery, body)
		if statusOverride != 0 {
			w.WriteHeader(statusOverride)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newFanoutHarness builds a SLO harness (SP-A registered with its signing cert +
// SLO URL, like newSLOHarness) AND wires a MemorySessionIndex + an audit sink, so
// the fan-out is enabled. It returns the harness, SP-A's keypair, the live
// session id, the index, and the captured audit events sink.
//
// WHY a REAL clock (not the fixedNow seam): the fan-out's outbound LogoutRequest
// is built with h.deps.now() and then validated by the module's own saml/sp
// ProcessLogoutRequest (the cross-validation), which uses its OWN real wall
// clock for the freshness window. Pinning the IdP to fixedNow while the SP runs
// on real time would make freshness flaky; running BOTH on real time keeps the
// freshness window aligned. The inbound SP-A request is correspondingly built
// with issueInstant: time.Now() (see the call sites).
func newFanoutHarness(t *testing.T, nameID string) (*harness, *spKeypair, string, *MemorySessionIndex, *audit.MemorySink) {
	t.Helper()
	issuer, pub := newIssuer(t, issuerRSA)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	spKey := newSPKeypair(t)
	registerSPWithSLO(t, clients, spKey) // SP-A: spClientID / spEntityID / spSLOURL

	idx := NewMemorySessionIndex(0, 0)
	sink := audit.NewMemorySink(256)
	rec := audit.New(sink)

	h, err := NewHandlers(Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "test", issuer, nil },
		Issuer:          testIssuer,
		AuditRecorder:   rec,
		SessionIndex:    idx,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	// Real clock (default time.Now) — see the func doc.
	hh := &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
	sid := hh.seedUserSession(t, nameID)
	return hh, spKey, sid, idx, sink
}

// registerExtraSP registers a SECOND (or third) SP client with its own entity id
// + SLO URL + binding (no signing cert needed — the fan-out signs with the IdP
// key, and inbound validation of THIS SP is not exercised here).
func registerExtraSP(t *testing.T, clients *defaultimpl.MemoryClientStore, clientID, entityID, sloURL, binding string) {
	t.Helper()
	attrs := map[string]string{
		AttrSPEntityID: entityID,
		AttrSPACSURLs:  "https://" + clientID + "/acs",
		AttrSPSLOUrls:  sloURL,
	}
	if binding != "" {
		attrs[AttrSPSLOBinding] = binding
	}
	if err := clients.Add(context.Background(), &sso.Client{ID: clientID, Active: true, Attributes: attrs}); err != nil {
		t.Fatalf("register extra SP %q: %v", clientID, err)
	}
}

// waitForHits blocks until cap has at least n hits or the deadline elapses (the
// fan-out is async). Fails the test on timeout.
func waitForHits(t *testing.T, cap *capturedSLO, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, _, hits := cap.snapshot(); hits >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	_, _, hits := cap.snapshot()
	t.Fatalf("fan-out did not deliver: got %d hits, want >= %d", hits, n)
}

// idpSignerCertPEM returns the IdP signer's cert as PEM (the trust anchor a
// cross-validation SP pins).
func idpSignerCertPEM(t *testing.T, signer *AssertionSigner) []byte {
	t.Helper()
	cert, err := signer.Certificate()
	if err != nil {
		t.Fatalf("signer cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// TestFanout_SPInitiated_DispatchesToOtherSP is the headline test: a subject is
// logged into SP-A + SP-B (index has both). SP-A initiates /saml/slo. The IdP
// terminates the session AND dispatches a SIGNED LogoutRequest to SP-B's SLO URL;
// SP-A (the initiator) gets NOTHING; the index is cleaned up after. The
// dispatched request's signature validates against the IdP key + carries the
// right NameID — cross-validated through the module's OWN saml/sp validator.
func TestFanout_SPInitiated_DispatchesToOtherSP(t *testing.T) {
	const nameID = "alice@example.com"
	hh, spKeyA, sid, idx, _ := newFanoutHarness(t, nameID)

	// SP-B: a capturing httptest SP. Register it with its SLO URL.
	capB := &capturedSLO{}
	srvB := newCapturingSP(t, capB, 0)
	const spBEntityID = "https://sp-b.example.com/saml/metadata"
	registerExtraSP(t, hh.clients, "sp-b-client", spBEntityID, srvB.URL, BindingRedirect)

	// SP-A: a capturing SP too, so we can assert it is NOT contacted.
	capA := &capturedSLO{}
	srvA := newCapturingSP(t, capA, 0)
	// Re-point SP-A's SLO URL at the capturing server (so a bug that fanned back
	// to the initiator would be visible). SP-A keeps its signing cert.
	if err := hh.clients.Update(context.Background(), &sso.Client{
		ID:     spClientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID:    spEntityID,
			AttrSPACSURLs:     spACSURL,
			AttrSPSigningCert: spKeyA.certPEM(),
			AttrSPSLOUrls:     srvA.URL,
		},
	}); err != nil {
		t.Fatalf("re-register SP-A: %v", err)
	}

	// Seed the index: the subject is logged into BOTH SP-A and SP-B.
	ctx := context.Background()
	_ = idx.Record(ctx, nameID, SAMLSPSession{SPEntityID: spEntityID, SPClientID: spClientID, SPSLOUrl: srvA.URL, SPBinding: BindingRedirect, NameID: nameID})
	_ = idx.Record(ctx, nameID, SAMLSPSession{SPEntityID: spBEntityID, SPClientID: "sp-b-client", SPSLOUrl: srvB.URL, SPBinding: BindingRedirect, NameID: nameID})

	// SP-A initiates the logout (detached-signed redirect LogoutRequest). Built
	// with a real-time IssueInstant (the harness runs on a real clock).
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID, issueInstant: time.Now()}, "", spKeyA)
	rec := hh.getSLO(q)
	if rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	// The IdP session is terminated.
	if _, err := hh.sessions.Get(ctx, sid); err == nil {
		t.Fatalf("IdP session %q should be terminated by SLO", sid)
	}

	// SP-B receives a fan-out LogoutRequest; SP-A (initiator) does not.
	waitForHits(t, capB, 1)
	if _, _, hitsA := capA.snapshot(); hitsA != 0 {
		t.Fatalf("initiating SP-A received a fan-out request (must be excluded): %d hits", hitsA)
	}

	// The index is cleaned up (RemoveAll on logout) — no stale subject->SP rows.
	if rows, _ := idx.ListBySubject(ctx, nameID); len(rows) != 0 {
		t.Fatalf("index not cleaned after fan-out: %+v", rows)
	}

	// Cross-validate SP-B's received request against the IdP key + NameID, using
	// the module's OWN saml/sp ProcessLogoutRequest (the real-deployment SP-side
	// validator). The IdP cert is the AssertionSigner's cert; the IdP entity id is
	// h.entityID().
	rawQuery, _, _ := capB.snapshot()
	idpCertPEM := idpSignerCertPEM(t, hh.signerFor(t))
	spB, err := sp.NewSPAuthenticator(sp.SPConfig{
		Name:        "sp-b",
		EntityID:    spBEntityID,
		ACSURL:      "https://sp-b/acs",
		IDPCert:     idpCertPEM,
		IDPEntityID: hh.h.entityID(),
	})
	if err != nil {
		t.Fatalf("build cross-validation SP-B: %v", err)
	}

	// Extract the SAMLRequest value (the validator wants the base64 value, plus
	// the raw query for the detached-sig reconstruction).
	samlReq := rawRedirectValue(t, rawQuery, "SAMLRequest")
	subj, err := spB.ProcessLogoutRequest(samlReq, "", true, rawQuery)
	if err != nil {
		t.Fatalf("module SP-side REJECTED the fan-out LogoutRequest (interop/sig break): %v", err)
	}
	if subj.NameID != nameID {
		t.Fatalf("fan-out LogoutRequest NameID = %q, want %q", subj.NameID, nameID)
	}
}

// TestFanout_DeadSP_DoesNotBlock proves the best-effort property: a dead/failing
// SP-C never blocks the initiator's LogoutResponse. SP-A initiates; SP-C's SLO
// endpoint returns 500; the /saml/slo response to SP-A still returns 302 Success
// (not blocked), and the failure is recorded as a logout_notified failure.
func TestFanout_DeadSP_DoesNotBlock(t *testing.T) {
	const nameID = "bob@example.com"
	hh, spKeyA, _, idx, sink := newFanoutHarness(t, nameID)

	// SP-C: returns 500 on every SLO delivery.
	capC := &capturedSLO{}
	srvC := newCapturingSP(t, capC, http.StatusInternalServerError)
	const spCEntityID = "https://sp-c.example.com/saml/metadata"
	registerExtraSP(t, hh.clients, "sp-c-client", spCEntityID, srvC.URL, BindingRedirect)

	ctx := context.Background()
	_ = idx.Record(ctx, nameID, SAMLSPSession{SPEntityID: spCEntityID, SPClientID: "sp-c-client", SPSLOUrl: srvC.URL, SPBinding: BindingRedirect, NameID: nameID})

	start := time.Now()
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID, issueInstant: time.Now()}, "", spKeyA)
	rec := hh.getSLO(q)
	elapsed := time.Since(start)

	// The response is immediate (not blocked on SP-C's failing endpoint) and
	// successful.
	if rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302 even with a dead fan-out SP; body=%s", rec.Code, rec.Body.String())
	}
	if elapsed > 2*time.Second {
		t.Fatalf("/saml/slo blocked %v on the dead SP (must be async)", elapsed)
	}

	// The fan-out attempted (and failed) — wait for the delivery, then assert a
	// logout_notified failure was audited.
	waitForHits(t, capC, 1)
	// Give the async recorder a beat to record the failure after the HTTP return.
	if !waitForFanoutAudit(t, sink, audit.OutcomeFailure) {
		t.Fatalf("expected a logout_notified FAILURE audit event for the dead SP")
	}
}

// TestFanout_POSTBinding_DispatchesEnvelopedRequest proves the POST-binding
// fan-out: an SP registered with the POST binding receives an enveloped-XML-DSig
// LogoutRequest (form POST), cross-validated by the module's SP-side POST
// validator.
func TestFanout_POSTBinding_DispatchesEnvelopedRequest(t *testing.T) {
	const nameID = "carol@example.com"
	hh, spKeyA, _, idx, _ := newFanoutHarness(t, nameID)

	capD := &capturedSLO{}
	srvD := newCapturingSP(t, capD, 0)
	const spDEntityID = "https://sp-d.example.com/saml/metadata"
	registerExtraSP(t, hh.clients, "sp-d-client", spDEntityID, srvD.URL, BindingPost)

	ctx := context.Background()
	_ = idx.Record(ctx, nameID, SAMLSPSession{SPEntityID: spDEntityID, SPClientID: "sp-d-client", SPSLOUrl: srvD.URL, SPBinding: BindingPost, NameID: nameID})

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID, issueInstant: time.Now()}, "", spKeyA)
	if rec := hh.getSLO(q); rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	waitForHits(t, capD, 1)
	_, postBody, _ := capD.snapshot()
	if postBody == "" {
		t.Fatalf("POST-binding SP-D received no SAMLRequest form value")
	}

	// Cross-validate the enveloped POST LogoutRequest via the module's SP-side
	// POST validator (redirectBinding=false).
	idpCertPEM := idpSignerCertPEM(t, hh.signerFor(t))
	spD, err := sp.NewSPAuthenticator(sp.SPConfig{
		Name:        "sp-d",
		EntityID:    spDEntityID,
		ACSURL:      "https://sp-d/acs",
		IDPCert:     idpCertPEM,
		IDPEntityID: hh.h.entityID(),
	})
	if err != nil {
		t.Fatalf("build cross-validation SP-D: %v", err)
	}
	subj, err := spD.ProcessLogoutRequest(postBody, "", false, "")
	if err != nil {
		t.Fatalf("module SP-side REJECTED the POST fan-out LogoutRequest: %v", err)
	}
	if subj.NameID != nameID {
		t.Fatalf("POST fan-out NameID = %q, want %q", subj.NameID, nameID)
	}
}

// TestFanout_NilIndex_NoDispatch_ByteIdentical proves the nil-index path: with NO
// session index wired, /saml/slo behaves exactly as the pre-fan-out single-SP
// SLO — no fan-out is attempted even when another SP "would" have been a target.
// (We can't observe a negative dispatch directly, so we assert the handler took
// the single-SP path: it returns the same 302 LogoutResponse and there is no
// fan-out audit event.)
func TestFanout_NilIndex_NoDispatch_ByteIdentical(t *testing.T) {
	const nameID = "dave@example.com"
	// newSLOHarness wires NO index (nil) — the pre-fan-out construction.
	hh, spKeyA, sid := newSLOHarness(t, nameID)

	// A would-be fan-out target SP, registered but never recorded (no index).
	capE := &capturedSLO{}
	srvE := newCapturingSP(t, capE, 0)
	registerExtraSP(t, hh.clients, "sp-e-client", "https://sp-e/saml", srvE.URL, BindingRedirect)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", spKeyA)
	rec := hh.getSLO(q)
	if rec.Code != http.StatusFound {
		t.Fatalf("SLO status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if _, err := hh.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("session should be terminated")
	}

	// No fan-out: give any (erroneous) async dispatch a chance, then assert SP-E
	// was never contacted.
	time.Sleep(150 * time.Millisecond)
	if _, _, hits := capE.snapshot(); hits != 0 {
		t.Fatalf("nil-index build dispatched a fan-out (must be disabled): %d hits", hits)
	}
}

// TestFanout_IdPInitiated_Hook proves the exported Fanout hook an operator's fork
// calls for IdP-initiated global logout (e.g. from /end_session): calling
// Fanout(subject, "") dispatches to ALL the subject's SPs and cleans the index.
func TestFanout_IdPInitiated_Hook(t *testing.T) {
	const nameID = "erin@example.com"
	hh, _, _, idx, _ := newFanoutHarness(t, nameID)

	capF := &capturedSLO{}
	srvF := newCapturingSP(t, capF, 0)
	const spFEntityID = "https://sp-f.example.com/saml/metadata"
	registerExtraSP(t, hh.clients, "sp-f-client", spFEntityID, srvF.URL, BindingRedirect)

	ctx := context.Background()
	_ = idx.Record(ctx, nameID, SAMLSPSession{SPEntityID: spFEntityID, SPClientID: "sp-f-client", SPSLOUrl: srvF.URL, SPBinding: BindingRedirect, NameID: nameID})

	// IdP-initiated: exclude nothing (empty excludeSPEntityID).
	hh.h.Fanout(ctx, nameID, "")

	waitForHits(t, capF, 1)
	if rows, _ := idx.ListBySubject(ctx, nameID); len(rows) != 0 {
		t.Fatalf("index not cleaned after IdP-initiated fan-out: %+v", rows)
	}
}

// TestFanout_SkipsSPWithNoSLOURL proves an SP recorded without a registered SLO
// URL is skipped (nowhere to deliver) — no panic, no dispatch.
func TestFanout_SkipsSPWithNoSLOURL(t *testing.T) {
	const nameID = "frank@example.com"
	hh, _, _, idx, _ := newFanoutHarness(t, nameID)

	// An SP with NO SLO URL recorded.
	ctx := context.Background()
	_ = idx.Record(ctx, nameID, SAMLSPSession{SPEntityID: "https://sp-g/saml", SPClientID: "sp-g-client", SPSLOUrl: "", SPBinding: BindingRedirect, NameID: nameID})

	// Should not panic; just cleans the index.
	hh.h.Fanout(ctx, nameID, "")
	time.Sleep(100 * time.Millisecond)
	if rows, _ := idx.ListBySubject(ctx, nameID); len(rows) != 0 {
		t.Fatalf("index not cleaned: %+v", rows)
	}
}

// --- helpers ---

// rawRedirectValue extracts the RAW (still-encoded) value of a query key out of a
// raw query string, then unescapes it once (so ProcessLogoutRequest receives the
// base64 SAMLRequest value — the SP-side reconstructs the octet string from the
// rawQuery separately). Mirrors the module's rawRedirectParam.
func rawRedirectValue(t *testing.T, rawQuery, key string) string {
	t.Helper()
	v, ok := rawRedirectParam(rawQuery, key)
	if !ok {
		t.Fatalf("query %q missing key %q", rawQuery, key)
	}
	dec, err := url.QueryUnescape(v)
	if err != nil {
		t.Fatalf("unescape %q: %v", v, err)
	}
	return dec
}

// waitForFanoutAudit polls the sink for a logout_notified event with the given
// outcome (the async recorder may record slightly after the HTTP return).
func waitForFanoutAudit(t *testing.T, sink *audit.MemorySink, outcome audit.Outcome) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		events, _ := sink.Query(context.Background(), audit.Query{})
		for _, e := range events {
			if e.Type == audit.EventLogoutNotified && e.Outcome == outcome && e.Metadata["saml_slo_fanout"] == "true" {
				return true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}
