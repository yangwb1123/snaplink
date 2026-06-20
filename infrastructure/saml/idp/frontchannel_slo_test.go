package idp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/saml/sp"
)

// idpContinueURL is the IdP's front-channel chain RESUME endpoint a simulated SP
// redirects its LogoutResponse to.
const idpContinueURL = testIssuer + "/saml/slo/continue"

// fcSP describes one front-channel SP in a chain test: its entity id, client id,
// SLO URL, and signing keypair (the IdP pins its cert to authenticate BOTH its
// inbound LogoutRequests and — at /continue — its LogoutResponses).
type fcSP struct {
	entityID string
	clientID string
	sloURL   string
	key      *spKeypair
}

// registerFrontChannelSP registers a front-channel SP client with its signing
// cert + SLO URL + channel=frontchannel.
func registerFrontChannelSP(t *testing.T, clients *defaultimpl.MemoryClientStore, s fcSP) {
	t.Helper()
	if err := clients.Add(context.Background(), &sso.Client{
		ID:     s.clientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID:    s.entityID,
			AttrSPACSURLs:     "https://" + s.clientID + "/acs",
			AttrSPSigningCert: s.key.certPEM(),
			AttrSPSLOUrls:     s.sloURL,
			AttrSPSLOChannel:  ChannelFrontchannel,
		},
	}); err != nil {
		t.Fatalf("register front-channel SP %q: %v", s.clientID, err)
	}
}

// newFrontChannelHarness builds a harness with the initiator SP-A registered (its
// signing cert + SLO URL + channel=frontchannel), a wired MemorySessionIndex, and
// a REAL clock. Returns the harness, SP-A, and the live session id for nameID.
//
// WHY a REAL clock (not the fixedNow seam): every chained LogoutRequest the IdP
// builds is cross-validated by the module's OWN saml/sp ProcessLogoutRequest,
// which freshness-checks the IssueInstant against its OWN real wall clock (its
// unexported clock seam is not reachable from this package). Pinning the IdP to
// fixedNow while the SP validator runs on real time would make freshness flaky;
// running BOTH on real time keeps the window aligned. The inbound SP-A request +
// each SP's LogoutResponse are correspondingly built with time.Now() (see the
// call sites). The expiry test advances h.deps.now() explicitly AFTER the first
// hop's cross-validation.
func newFrontChannelHarness(t *testing.T, nameID string, initiatorSLO string) (*harness, fcSP, string, *MemorySessionIndex) {
	t.Helper()
	issuer, pub := newIssuer(t, issuerRSA)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	spA := fcSP{entityID: spEntityID, clientID: spClientID, sloURL: initiatorSLO, key: newSPKeypair(t)}
	registerFrontChannelSP(t, clients, spA)

	idx := NewMemorySessionIndex(0, 0)

	h, err := NewHandlers(Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "test", issuer, nil },
		Issuer:          testIssuer,
		SessionIndex:    idx,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	// Real clock (default time.Now) — see the func doc.
	hh := &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
	sid := hh.seedUserSession(t, nameID)
	return hh, spA, sid, idx
}

// recordFC records a subject->SP front-channel row in the index (as the finish
// handler would on assertion issuance).
func recordFC(t *testing.T, idx *MemorySessionIndex, nameID string, s fcSP) {
	t.Helper()
	_ = idx.Record(context.Background(), nameID, SAMLSPSession{
		SPEntityID: s.entityID,
		SPClientID: s.clientID,
		SPSLOUrl:   s.sloURL,
		SPChannel:  ChannelFrontchannel,
		NameID:     nameID,
	})
}

// getContinue drives GET /saml/slo/continue with a FULL raw query string (so the
// detached §3.4.4.1 signature over the LogoutResponse is preserved byte-for-byte).
func (hh *harness) getContinue(rawQuery string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/saml/slo/continue?"+rawQuery, nil)
	rec := httptest.NewRecorder()
	hh.h.SLOContinue(rec, req)
	return rec
}

// buildSPLogoutResponseRedirectQuery simulates a front-channel SP terminating its
// local session and redirecting its DETACHED §3.4.4.1-signed LogoutResponse back
// to the IdP's /continue endpoint: it builds a Status:Success LogoutResponse with
// the given Issuer (the SP entity id) + InResponseTo, serializes it UNSIGNED into
// the SAMLResponse param, and signs the octet string (SAMLResponse + RelayState +
// SigAlg) with the SP key. relayState is the chain-state id the SP echoes
// verbatim. signer==nil yields an unsigned response (the fail-closed case).
func buildSPLogoutResponseRedirectQuery(t *testing.T, issuer, inResponseTo, relayState string, signer *spKeypair) string {
	t.Helper()
	resp := &saml.LogoutResponse{
		ID:           "id-resp-" + randHex(),
		InResponseTo: inResponseTo,
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  idpContinueURL,
		Issuer:       &saml.Issuer{Value: issuer},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusSuccess}},
	}
	doc := etree.NewDocument()
	doc.SetRoot(resp.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatalf("serialize logout response: %v", err)
	}
	samlResp := base64.StdEncoding.EncodeToString(deflate(t, raw))

	query := "SAMLResponse=" + url.QueryEscape(samlResp)
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
		t.Fatalf("new signing context: %v", err)
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

// redirectTarget parses a 302 Location and returns scheme://host/path (the SLO
// endpoint the IdP is redirecting the browser to). It also asserts no-store on
// the hop (every front-channel chain hop is a credential-mutating redirect — §2).
func redirectTarget(t *testing.T, rec *httptest.ResponseRecorder) (*url.URL, string) {
	t.Helper()
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("chain hop Cache-Control = %q, want no-store", cc)
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return u, u.Scheme + "://" + u.Host + u.Path
}

// crossValidateLogoutRequest validates the LogoutRequest the IdP redirected to an
// SP, using the module's OWN saml/sp ProcessLogoutRequest (pinned to the IdP cert)
// — the real-deployment SP-side validator. It returns the validated subject so the
// test can assert the NameID. The raw query carries the detached signature.
func (hh *harness) crossValidateLogoutRequest(t *testing.T, spEntity, rawQuery string) *sp.LogoutSubject {
	t.Helper()
	idpCertPEM := idpSignerCertPEM(t, hh.signerFor(t))
	spv, err := sp.NewSPAuthenticator(sp.SPConfig{
		Name:        "xv-" + spEntity,
		EntityID:    spEntity,
		ACSURL:      "https://xv/acs",
		IDPCert:     idpCertPEM,
		IDPEntityID: hh.h.entityID(),
	})
	if err != nil {
		t.Fatalf("build cross-validation SP: %v", err)
	}
	samlReq := rawRedirectValue(t, rawQuery, "SAMLRequest")
	subj, err := spv.ProcessLogoutRequest(samlReq, rawRedirectValue(t, rawQuery, "RelayState"), true, rawQuery)
	if err != nil {
		t.Fatalf("module SP-side REJECTED the chained LogoutRequest (interop/sig break): %v", err)
	}
	return subj
}

// TestFrontChannel_FullChain is the headline test: a subject is logged into
// front-channel SP-A (initiator), SP-B, SP-C. SP-A initiates /saml/slo → the IdP
// terminates the session + 302s to SP-B's SLO URL with a signed LogoutRequest
// carrying a state-id RelayState. SP-B terminates + redirects to /saml/slo/continue
// with a signed LogoutResponse → the IdP advances to SP-C → SP-C acks → the IdP
// 302s to the INITIATOR's return URL with the IdP's final LogoutResponse. Every
// chained LogoutRequest is cross-validated through the module's own sp validator.
func TestFrontChannel_FullChain(t *testing.T) {
	const nameID = "alice@example.com"
	const initiatorSLO = "https://sp-a.example.com/saml/slo"
	hh, spA, sid, idx := newFrontChannelHarness(t, nameID, initiatorSLO)

	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	spC := fcSP{entityID: "https://sp-c.example.com/saml", clientID: "sp-c", sloURL: "https://sp-c.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	registerFrontChannelSP(t, hh.clients, spC)

	// The subject is logged into all three front-channel SPs.
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)
	recordFC(t, idx, nameID, spC)

	// SP-A initiates the logout (detached-signed redirect LogoutRequest).
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "rs-init", spA.key)
	rec := hh.getSLO(q)

	// The IdP session is terminated.
	if _, err := hh.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("IdP session %q should be terminated by SLO", sid)
	}
	// The index is cleaned immediately (the chain carries its own SP list).
	if rows, _ := idx.ListBySubject(context.Background(), nameID); len(rows) != 0 {
		t.Fatalf("index not cleaned after chain start: %+v", rows)
	}

	// HOP 1: 302 to SP-B (the first NON-initiator front-channel SP), signed
	// LogoutRequest + a chain-state RelayState.
	u, target := redirectTarget(t, rec)
	if target != spB.sloURL {
		t.Fatalf("hop 1 target = %q, want SP-B %q", target, spB.sloURL)
	}
	stateB := u.Query().Get("RelayState")
	if stateB == "" {
		t.Fatalf("hop 1 LogoutRequest carries no chain-state RelayState")
	}
	subjB := hh.crossValidateLogoutRequest(t, spB.entityID, u.RawQuery)
	if subjB.NameID != nameID {
		t.Fatalf("hop 1 LogoutRequest NameID = %q, want %q", subjB.NameID, nameID)
	}

	// SP-B terminates + redirects its signed LogoutResponse to /continue.
	respQ := buildSPLogoutResponseRedirectQuery(t, spB.entityID, subjB.RequestID, stateB, spB.key)
	rec = hh.getContinue(respQ)

	// HOP 2: 302 to SP-C, fresh chain-state RelayState (the id ROTATED).
	u, target = redirectTarget(t, rec)
	if target != spC.sloURL {
		t.Fatalf("hop 2 target = %q, want SP-C %q", target, spC.sloURL)
	}
	stateC := u.Query().Get("RelayState")
	if stateC == "" || stateC == stateB {
		t.Fatalf("hop 2 chain-state id = %q (prev %q): want a fresh rotated id", stateC, stateB)
	}
	subjC := hh.crossValidateLogoutRequest(t, spC.entityID, u.RawQuery)
	if subjC.NameID != nameID {
		t.Fatalf("hop 2 LogoutRequest NameID = %q, want %q", subjC.NameID, nameID)
	}

	// SP-C terminates + redirects its signed LogoutResponse to /continue.
	respQ = buildSPLogoutResponseRedirectQuery(t, spC.entityID, subjC.RequestID, stateC, spC.key)
	rec = hh.getContinue(respQ)

	// COMPLETION: 302 to the INITIATOR's (SP-A's) registered SLO URL with the IdP's
	// final LogoutResponse (Status Success, detached sig verifies against the IdP
	// cert, echoing the initiator's RelayState).
	u, target = redirectTarget(t, rec)
	if target != initiatorSLO {
		t.Fatalf("completion target = %q, want the initiator SP-A SLO %q", target, initiatorSLO)
	}
	idpCert := idpSignerCert(t, hh.signerFor(t))
	assertIDPDetachedSigVerifies(t, u.RawQuery, "SAMLResponse", idpCert)
	respEl := inflateLogoutResponseEl(t, u.Query().Get("SAMLResponse"))
	if sig := respEl.FindElement("//Signature"); sig != nil {
		t.Error("final LogoutResponse body must be UNSIGNED (detached binding)")
	}
	assertStatusSuccess(t, respEl)
	if rs := u.Query().Get("RelayState"); rs != "rs-init" {
		t.Errorf("completion RelayState = %q, want the initiator's echoed %q", rs, "rs-init")
	}
}

// TestFrontChannel_UnknownState_Rejected: a /continue hop with an UNKNOWN chain
// state id is rejected (saml_request_invalid), the chain not advanced.
func TestFrontChannel_UnknownState_Rejected(t *testing.T) {
	const nameID = "bob@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)

	// A signed LogoutResponse for a never-issued chain id.
	respQ := buildSPLogoutResponseRedirectQuery(t, spB.entityID, "id-whatever", "bogus-state-id", spB.key)
	rec := hh.getContinue(respQ)
	assertRequestInvalidOnly(t, rec)
}

// TestFrontChannel_ReplayedState_Rejected: a chain state id is SINGLE-USE —
// re-presenting a consumed one (after a valid advance) fails. The first hop
// advances; replaying the SAME state id at /continue is rejected.
func TestFrontChannel_ReplayedState_Rejected(t *testing.T) {
	const nameID = "rachel@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	spC := fcSP{entityID: "https://sp-c.example.com/saml", clientID: "sp-c", sloURL: "https://sp-c.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	registerFrontChannelSP(t, hh.clients, spC)
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)
	recordFC(t, idx, nameID, spC)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "", spA.key)
	u, _ := redirectTarget(t, hh.getSLO(q))
	stateB := u.Query().Get("RelayState")
	subjB := hh.crossValidateLogoutRequest(t, spB.entityID, u.RawQuery)

	// First /continue with stateB advances (to SP-C).
	respQ := buildSPLogoutResponseRedirectQuery(t, spB.entityID, subjB.RequestID, stateB, spB.key)
	if rec := hh.getContinue(respQ); rec.Code != http.StatusFound {
		t.Fatalf("first /continue = %d, want 302; body=%s", rec.Code, rec.Body.String())
	}

	// REPLAY the SAME stateB → rejected (single-use; the id was consumed).
	rec := hh.getContinue(respQ)
	assertRequestInvalidOnly(t, rec)
}

// TestFrontChannel_ExpiredState_Rejected: a /continue hop whose chain state has
// expired (TTL elapsed) is rejected, oracle-safe.
func TestFrontChannel_ExpiredState_Rejected(t *testing.T) {
	const nameID = "sam@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)

	// Capture the harness's REAL clock base (newFrontChannelHarness deliberately
	// uses the default time.Now, and the SP-side cross-validator below also runs on
	// the real clock) so we can advance PAST the TTL relative to the time the chain
	// is actually created. Using fixedNow here was a time-of-day bug: the chain is
	// created on the real wall clock, so a fixedNow-based advance only "expired" it
	// while the real time was still before fixedNow+1min (passed in the morning,
	// failed after 12:01 UTC); pinning everything to fixedNow instead makes the
	// chain's own LogoutRequest look stale to the real-clock cross-validator.
	base := time.Now()
	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: base}, "", spA.key)
	u, _ := redirectTarget(t, hh.getSLO(q))
	stateB := u.Query().Get("RelayState")
	subjB := hh.crossValidateLogoutRequest(t, spB.entityID, u.RawQuery)

	// Advance the IdP clock past the chain TTL relative to the real base above so
	// the stored chain is expired (deterministic, independent of wall-clock time).
	hh.h.deps.now = func() time.Time { return base.Add(DefaultLogoutChainTTL + time.Minute) }

	respQ := buildSPLogoutResponseRedirectQuery(t, spB.entityID, subjB.RequestID, stateB, spB.key)
	rec := hh.getContinue(respQ)
	assertRequestInvalidOnly(t, rec)
}

// TestFrontChannel_ForgedLogoutResponse_Rejected is a security crux: a
// LogoutResponse at /continue signed by an ATTACKER key (not the acknowledging
// SP's registered cert) is rejected and the chain is NOT advanced (no redirect to
// the next SP).
func TestFrontChannel_ForgedLogoutResponse_Rejected(t *testing.T) {
	const nameID = "carol@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	spC := fcSP{entityID: "https://sp-c.example.com/saml", clientID: "sp-c", sloURL: "https://sp-c.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	registerFrontChannelSP(t, hh.clients, spC)
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)
	recordFC(t, idx, nameID, spC)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "", spA.key)
	u, _ := redirectTarget(t, hh.getSLO(q))
	stateB := u.Query().Get("RelayState")
	subjB := hh.crossValidateLogoutRequest(t, spB.entityID, u.RawQuery)

	// Attacker signs SP-B's LogoutResponse with a DIFFERENT key (not SP-B's cert).
	attacker := newSPKeypair(t)
	respQ := buildSPLogoutResponseRedirectQuery(t, spB.entityID, subjB.RequestID, stateB, attacker)
	rec := hh.getContinue(respQ)
	assertRequestInvalidOnly(t, rec)
}

// TestFrontChannel_ForgedResponse_DoesNotBurnChain proves the peek-before-consume
// robustness: a FORGED LogoutResponse at /continue is rejected WITHOUT consuming
// the chain's single-use state, so the SP's subsequent LEGITIMATE response with
// the SAME chain id still advances the chain. (A forged response can neither
// advance nor DoS a legit chain.)
func TestFrontChannel_ForgedResponse_DoesNotBurnChain(t *testing.T) {
	const nameID = "nora@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	spC := fcSP{entityID: "https://sp-c.example.com/saml", clientID: "sp-c", sloURL: "https://sp-c.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	registerFrontChannelSP(t, hh.clients, spC)
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)
	recordFC(t, idx, nameID, spC)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "", spA.key)
	u, _ := redirectTarget(t, hh.getSLO(q))
	stateB := u.Query().Get("RelayState")
	subjB := hh.crossValidateLogoutRequest(t, spB.entityID, u.RawQuery)

	// A FORGED response (attacker key) for stateB is rejected.
	attacker := newSPKeypair(t)
	forged := buildSPLogoutResponseRedirectQuery(t, spB.entityID, subjB.RequestID, stateB, attacker)
	if rec := hh.getContinue(forged); rec.Code != http.StatusBadRequest {
		t.Fatalf("forged response status = %d, want 400", rec.Code)
	}

	// The LEGIT response with the SAME stateB still advances (the forged attempt
	// did NOT burn the chain) — 302 to SP-C.
	legit := buildSPLogoutResponseRedirectQuery(t, spB.entityID, subjB.RequestID, stateB, spB.key)
	rec := hh.getContinue(legit)
	_, target := redirectTarget(t, rec)
	if target != spC.sloURL {
		t.Fatalf("after a forged attempt, the legit response did not advance to SP-C: target=%q", target)
	}
}

// TestFrontChannel_UnsignedLogoutResponse_Rejected: a /continue LogoutResponse
// with NO detached signature (no SigAlg/Signature) is rejected — fail-closed.
func TestFrontChannel_UnsignedLogoutResponse_Rejected(t *testing.T) {
	const nameID = "trent@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "", spA.key)
	u, _ := redirectTarget(t, hh.getSLO(q))
	stateB := u.Query().Get("RelayState")
	subjB := hh.crossValidateLogoutRequest(t, spB.entityID, u.RawQuery)

	respQ := buildSPLogoutResponseRedirectQuery(t, spB.entityID, subjB.RequestID, stateB, nil) // unsigned
	rec := hh.getContinue(respQ)
	assertRequestInvalidOnly(t, rec)
}

// TestFrontChannel_WrongIssuerLogoutResponse_Rejected: a /continue LogoutResponse
// validly-signed by SP-B's key but whose Issuer names a DIFFERENT entity is
// rejected (the Issuer-must-match-the-acknowledging-SP defense-in-depth check).
func TestFrontChannel_WrongIssuerLogoutResponse_Rejected(t *testing.T) {
	const nameID = "ivan@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	recordFC(t, idx, nameID, spA)
	recordFC(t, idx, nameID, spB)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "", spA.key)
	u, _ := redirectTarget(t, hh.getSLO(q))
	stateB := u.Query().Get("RelayState")
	subjB := hh.crossValidateLogoutRequest(t, spB.entityID, u.RawQuery)

	// Signed with SP-B's key (so the sig verifies against SP-B's cert) but the
	// Issuer claims SP-C — the Issuer check rejects it.
	respQ := buildSPLogoutResponseRedirectQuery(t, "https://sp-c.example.com/saml", subjB.RequestID, stateB, spB.key)
	rec := hh.getContinue(respQ)
	assertRequestInvalidOnly(t, rec)
}

// TestFrontChannel_NonHTTPSSPSkipped: a front-channel SP whose SLO URL is NOT
// https is SKIPPED (the SSRF gate) — the chain advances past it to the next https
// SP without ever redirecting the browser to the http URL.
func TestFrontChannel_NonHTTPSSPSkipped(t *testing.T) {
	const nameID = "dave@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")

	// SP-B has a plain-http SLO URL (must be skipped). SP-C is https.
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "http://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	spC := fcSP{entityID: "https://sp-c.example.com/saml", clientID: "sp-c", sloURL: "https://sp-c.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	registerFrontChannelSP(t, hh.clients, spC)
	recordFC(t, idx, nameID, spA)
	// Record SP-B with its http SLO URL directly in the index (bypassing the
	// issuance-time gate) so the dispatch-time skip is the thing under test.
	_ = idx.Record(context.Background(), nameID, SAMLSPSession{SPEntityID: spB.entityID, SPClientID: spB.clientID, SPSLOUrl: spB.sloURL, SPChannel: ChannelFrontchannel, NameID: nameID})
	recordFC(t, idx, nameID, spC)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "", spA.key)
	rec := hh.getSLO(q)

	// The FIRST hop must skip the http SP-B and go straight to the https SP-C.
	_, target := redirectTarget(t, rec)
	if target != spC.sloURL {
		t.Fatalf("first hop target = %q, want the https SP-C %q (the http SP-B must be skipped)", target, spC.sloURL)
	}
	if strings.HasPrefix(target, "http://") {
		t.Fatalf("chain redirected the browser to a NON-https SLO URL (SSRF gate bypass): %q", target)
	}
}

// TestFrontChannel_NoFrontChannelSPs_ByteIdentical proves byte-identical behavior:
// when the subject has only BACK-channel SPs (and the initiator), NO chain runs —
// the IdP returns the immediate LogoutResponse to the initiator exactly as the
// back-channel-only build does (a 302 to the initiator's SLO URL, no /continue
// hop).
func TestFrontChannel_NoFrontChannelSPs_ByteIdentical(t *testing.T) {
	const nameID = "noop@example.com"
	// SP-A here is BACK-channel (the default): no chain should start.
	issuer, pub := newIssuer(t, issuerRSA)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()
	spKey := newSPKeypair(t)
	registerSPWithSLO(t, clients, spKey) // back-channel SP-A (no channel attr ⇒ backchannel)

	idx := NewMemorySessionIndex(0, 0)
	h, err := NewHandlers(Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "test", issuer, nil },
		Issuer:          testIssuer,
		SessionIndex:    idx,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	h.deps.now = func() time.Time { return fixedNow }
	hh := &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
	sid := hh.seedUserSession(t, nameID)

	// Index the initiator only (back-channel) — no other SPs.
	_ = idx.Record(context.Background(), nameID, SAMLSPSession{SPEntityID: spEntityID, SPClientID: spClientID, SPSLOUrl: spSLOURL, SPChannel: ChannelBackchannel, NameID: nameID})

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spEntityID, nameID: nameID}, "", spKey)
	rec := hh.getSLO(q)

	// Immediate 302 LogoutResponse to the initiator's registered SLO URL (no chain).
	u, target := redirectTarget(t, rec)
	if target != spSLOURL {
		t.Fatalf("target = %q, want the immediate initiator LogoutResponse to %q (no chain)", target, spSLOURL)
	}
	// It is a LogoutResponse (not a chained LogoutRequest), signed by the IdP.
	if u.Query().Get("SAMLResponse") == "" {
		t.Fatalf("expected an immediate SAMLResponse to the initiator, got: %q", u.RawQuery)
	}
	// The chain store was never touched.
	if n := hh.h.chains.len(); n != 0 {
		t.Fatalf("chain store has %d entries, want 0 (no front-channel SPs ⇒ no chain)", n)
	}
	if _, err := hh.sessions.Get(context.Background(), sid); err == nil {
		t.Fatalf("IdP session %q should be terminated", sid)
	}
}

// TestFrontChannel_Coexist_BackAndFront proves back-channel + front-channel SPs
// COEXIST: with one back-channel SP (fans out async to a capturing https SP) and
// one front-channel SP (the browser chain), the IdP 302s the browser to the
// front-channel SP AND delivers the back-channel LogoutRequest to the back-channel
// SP's SLO endpoint.
func TestFrontChannel_Coexist_BackAndFront(t *testing.T) {
	const nameID = "mix@example.com"
	hh, spA, _, idx := newFrontChannelHarness(t, nameID, "https://sp-a.example.com/saml/slo")

	// Back-channel SP-BK: a capturing https httptest server (the fan-out is
	// https-only). Trust its cert on the fan-out client.
	capBK := &capturedSLO{}
	srvBK := newCapturingSP(t, capBK, 0)
	const bkEntityID = "https://sp-bk.example.com/saml"
	registerExtraSP(t, hh.clients, "sp-bk", bkEntityID, srvBK.URL, BindingRedirect) // default channel = backchannel
	trustFanoutServers(t, hh, srvBK)

	// Front-channel SP-FC.
	spFC := fcSP{entityID: "https://sp-fc.example.com/saml", clientID: "sp-fc", sloURL: "https://sp-fc.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spFC)

	ctx := context.Background()
	recordFC(t, idx, nameID, spA)
	_ = idx.Record(ctx, nameID, SAMLSPSession{SPEntityID: bkEntityID, SPClientID: "sp-bk", SPSLOUrl: srvBK.URL, SPChannel: ChannelBackchannel, NameID: nameID})
	recordFC(t, idx, nameID, spFC)

	q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: nameID, issueInstant: time.Now()}, "", spA.key)
	rec := hh.getSLO(q)

	// FRONT-channel: the browser is 302'd to the front-channel SP.
	_, target := redirectTarget(t, rec)
	if target != spFC.sloURL {
		t.Fatalf("front-channel hop target = %q, want SP-FC %q", target, spFC.sloURL)
	}

	// BACK-channel: the async fan-out delivered a LogoutRequest to SP-BK.
	waitForHits(t, capBK, 1)
}

// TestFrontChannel_ConcurrentChains drives many full front-channel chains in
// PARALLEL through the HTTP handlers (getSLO → /continue → /continue → completion)
// to surface races in the handler + chain-store interaction under -race -count.
// Each goroutine logs out a DISTINCT subject through the SAME two front-channel
// SPs; the chains must not interfere (each carries its own single-use state).
func TestFrontChannel_ConcurrentChains(t *testing.T) {
	// One shared harness; SP-B + SP-C registered once. Each chain uses a DISTINCT
	// subject but the SAME initiator SP-A (harness-registered, key in spA) — SP-A
	// is excluded from each chain, so every chain visits SP-B then SP-C.
	hh, spA, _, idx := newFrontChannelHarness(t, "seed@example.com", "https://sp-a.example.com/saml/slo")
	spB := fcSP{entityID: "https://sp-b.example.com/saml", clientID: "sp-b", sloURL: "https://sp-b.example.com/saml/slo", key: newSPKeypair(t)}
	spC := fcSP{entityID: "https://sp-c.example.com/saml", clientID: "sp-c", sloURL: "https://sp-c.example.com/saml/slo", key: newSPKeypair(t)}
	registerFrontChannelSP(t, hh.clients, spB)
	registerFrontChannelSP(t, hh.clients, spC)

	const workers = 12
	var wg sync.WaitGroup
	errCh := make(chan string, workers)
	for w := 0; w < workers; w++ {
		subject := "user" + string(rune('a'+w)) + "@example.com"
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each subject is logged into SP-A (initiator), SP-B, SP-C.
			recordFC(t, idx, subject, spA)
			recordFC(t, idx, subject, spB)
			recordFC(t, idx, subject, spC)

			q := buildSPLogoutRedirectQuery(t, spLogoutReq{issuer: spA.entityID, nameID: subject, issueInstant: time.Now()}, "", spA.key)
			u, ok := redirectOK(hh.getSLO(q))
			if !ok {
				errCh <- "initiate: not a 302"
				return
			}
			// HOP to SP-B.
			if tgt := u.Scheme + "://" + u.Host + u.Path; tgt != spB.sloURL {
				errCh <- "hop1 target " + tgt
				return
			}
			stateB := u.Query().Get("RelayState")
			reqIDB := requestIDFromQuery(u.RawQuery)
			u, ok = redirectOK(hh.getContinue(buildSPLogoutResponseRedirectQuery(t, spB.entityID, reqIDB, stateB, spB.key)))
			if !ok {
				errCh <- "hop2: not a 302"
				return
			}
			// HOP to SP-C.
			if tgt := u.Scheme + "://" + u.Host + u.Path; tgt != spC.sloURL {
				errCh <- "hop2 target " + tgt
				return
			}
			stateC := u.Query().Get("RelayState")
			reqIDC := requestIDFromQuery(u.RawQuery)
			u, ok = redirectOK(hh.getContinue(buildSPLogoutResponseRedirectQuery(t, spC.entityID, reqIDC, stateC, spC.key)))
			if !ok {
				errCh <- "completion: not a 302"
				return
			}
			// COMPLETION to the initiator SP-A.
			if tgt := u.Scheme + "://" + u.Host + u.Path; tgt != "https://sp-a.example.com/saml/slo" {
				errCh <- "completion target " + tgt
				return
			}
			if u.Query().Get("SAMLResponse") == "" {
				errCh <- "completion missing SAMLResponse"
				return
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for msg := range errCh {
		t.Errorf("concurrent chain failure: %s", msg)
	}
}

// requestIDFromQuery extracts the inbound LogoutRequest's ID from a redirect query
// by inflating the SAMLRequest — used by the concurrent test (which can't call the
// heavier cross-validation per hop) to thread InResponseTo.
func requestIDFromQuery(rawQuery string) string {
	samlReq, ok := rawRedirectParam(rawQuery, "SAMLRequest")
	if !ok {
		return ""
	}
	dec, err := url.QueryUnescape(samlReq)
	if err != nil {
		return ""
	}
	comp, err := base64.StdEncoding.DecodeString(dec)
	if err != nil {
		return ""
	}
	raw, err := inflateBounded(comp)
	if err != nil {
		return ""
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return ""
	}
	if r := doc.Root(); r != nil {
		return r.SelectAttrValue("ID", "")
	}
	return ""
}

// redirectOK returns the parsed Location + true when rec is a 302, else false
// (concurrent-test variant of redirectTarget that doesn't t.Fatalf off-goroutine).
func redirectOK(rec *httptest.ResponseRecorder) (*url.URL, bool) {
	if rec.Code != http.StatusFound {
		return nil, false
	}
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		return nil, false
	}
	return u, true
}

// --- chain-store unit + concurrency tests (-race) ---

// TestLogoutChainStore_SingleUse: consume removes the entry (a second consume of
// the same id fails); unknown ids fail.
func TestLogoutChainStore_SingleUse(t *testing.T) {
	s := newLogoutChainStore(time.Minute, 100)
	now := time.Now()
	id, err := s.insert(logoutChainState{Subject: "u1"}, now)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if _, ok := s.consume("nope", now); ok {
		t.Fatal("consume of unknown id returned ok")
	}
	st, ok := s.consume(id, now)
	if !ok || st.Subject != "u1" {
		t.Fatalf("consume = (%+v, %v), want the stored state", st, ok)
	}
	if _, ok := s.consume(id, now); ok {
		t.Fatal("second consume of the same id returned ok (must be single-use)")
	}
}

// TestLogoutChainStore_Expiry: a chain past its TTL is not consumable.
func TestLogoutChainStore_Expiry(t *testing.T) {
	s := newLogoutChainStore(time.Minute, 100)
	now := time.Now()
	id, _ := s.insert(logoutChainState{Subject: "u1"}, now)
	if _, ok := s.consume(id, now.Add(2*time.Minute)); ok {
		t.Fatal("consume of an expired chain returned ok")
	}
}

// TestLogoutChainStore_Bounded: the hard capacity cap evicts the oldest insert.
func TestLogoutChainStore_Bounded(t *testing.T) {
	s := newLogoutChainStore(time.Hour, 4)
	now := time.Now()
	var ids []string
	for i := 0; i < 10; i++ {
		id, _ := s.insert(logoutChainState{Subject: "u"}, now)
		ids = append(ids, id)
	}
	if n := s.len(); n > 4 {
		t.Fatalf("store len = %d, want <= capacity 4", n)
	}
	// The oldest ids were evicted; the newest survive.
	if _, ok := s.consume(ids[0], now); ok {
		t.Fatal("oldest id survived the cap (should be evicted)")
	}
	if _, ok := s.consume(ids[9], now); !ok {
		t.Fatal("newest id was evicted (should survive)")
	}
}

// TestLogoutChainStore_Concurrent exercises the store under concurrent
// insert/consume to surface races (-race -count). Each id is consumed exactly
// once across goroutines.
func TestLogoutChainStore_Concurrent(t *testing.T) {
	s := newLogoutChainStore(time.Hour, 100000)
	now := time.Now()
	const workers = 16
	const per = 200

	// Pre-insert ids, then race to consume them — each must be consumed exactly
	// once total.
	ids := make([]string, 0, workers*per)
	for i := 0; i < workers*per; i++ {
		id, _ := s.insert(logoutChainState{Subject: "u"}, now)
		ids = append(ids, id)
	}

	var consumed int64
	var mu sync.Mutex
	var wg sync.WaitGroup
	chunk := len(ids) / workers
	for w := 0; w < workers; w++ {
		lo := w * chunk
		hi := lo + chunk
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := 0
			for _, id := range ids[lo:hi] {
				if _, ok := s.consume(id, now); ok {
					local++
				}
				// Also insert fresh ones concurrently to stress the list/map.
				_, _ = s.insert(logoutChainState{Subject: "v"}, now)
			}
			mu.Lock()
			consumed += int64(local)
			mu.Unlock()
		}()
	}
	wg.Wait()
	if int(consumed) != len(ids) {
		t.Fatalf("consumed %d ids, want exactly %d (each single-use)", consumed, len(ids))
	}
}
