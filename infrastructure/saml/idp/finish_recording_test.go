package idp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
)

// newRecordingHarness wires a Handlers with an in-memory AuditRecorder + an
// in-memory SAMLSessionIndex so a successful finish exercises recordAssertion
// (login_success audit) AND recordSessionIndex (subject->SP row for SLO fan-out).
// The registered SP carries an https SLO URL so the index captures a fan-out
// target. Returns the harness plus the sink + index for assertions.
func newRecordingHarness(t *testing.T, sloURL string) (*harness, *audit.MemorySink, *MemorySessionIndex) {
	t.Helper()
	issuer, pub := newIssuer(t, issuerRSA)
	clients := defaultimpl.NewMemoryClientStore()
	sessions := defaultimpl.NewMemorySessionManager()
	users := defaultimpl.NewMemoryUserProvider()

	if err := clients.Add(context.Background(), &sso.Client{
		ID:     spClientID,
		Active: true,
		Attributes: map[string]string{
			AttrSPEntityID: spEntityID,
			AttrSPACSURLs:  spACSURL,
			AttrSPSLOUrls:  sloURL,
		},
	}); err != nil {
		t.Fatalf("add SP: %v", err)
	}

	sink := audit.NewMemorySink(64)
	idx := NewMemorySessionIndex(0, 0)

	h, err := NewHandlers(Deps{
		ClientStore:     clients,
		SessionManager:  sessions,
		UserProvider:    users,
		IssuerForClient: func(*sso.Client) (string, sso.TokenIssuer, error) { return "test", issuer, nil },
		Issuer:          testIssuer,
		AuditRecorder:   audit.New(sink),
		SessionIndex:    idx,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	h.deps.now = func() time.Time { return fixedNow }
	hh := &harness{h: h, clients: clients, sessions: sessions, users: users, issuer: issuer, signerPub: pub}
	return hh, sink, idx
}

// drainSink reads all events from a MemorySink (newest-first) for assertions.
func drainSink(t *testing.T, sink *audit.MemorySink) []*audit.Event {
	t.Helper()
	events, err := sink.Query(context.Background(), audit.Query{Limit: 64})
	if err != nil {
		t.Fatalf("query sink: %v", err)
	}
	return events
}

// TestFinish_RecordsAuditAndSessionIndex proves a successful SAML assertion
// issuance records a login_success audit event (provider "saml-idp", SP entity id
// on metadata via SetMeta) AND a subject->SP row in the SLO session index (with
// the SP's registered https SLO URL as the fan-out target).
func TestFinish_RecordsAuditAndSessionIndex(t *testing.T) {
	t.Parallel()
	const sloURL = "https://sp.example.com/saml/slo"
	hh, sink, idx := newRecordingHarness(t, sloURL)

	const userID = "alice@example.com"
	sessionID := hh.seedUserSession(t, userID)
	pendingID := hh.insertPending(t, "id-req-rec")

	rec := hh.postFinish(sessionID, pendingID)
	if rec.Code != http.StatusOK {
		t.Fatalf("finish status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	// Audit: exactly one login_success for provider saml-idp, actor = the user,
	// carrying the SP entity id on Metadata (SetMeta, not a clobbered map).
	events := drainSink(t, sink)
	var login *audit.Event
	for _, e := range events {
		if e.Type == audit.EventLogin && e.Outcome == audit.OutcomeSuccess {
			login = e
			break
		}
	}
	if login == nil {
		t.Fatalf("no login_success audit event recorded; got %d events", len(events))
	}
	if login.Provider != "saml-idp" {
		t.Errorf("audit provider = %q, want saml-idp", login.Provider)
	}
	if login.ActorID != userID {
		t.Errorf("audit actor = %q, want %q", login.ActorID, userID)
	}
	if login.Metadata["saml_sp_entity_id"] != spEntityID {
		t.Errorf("audit metadata saml_sp_entity_id = %q, want %q", login.Metadata["saml_sp_entity_id"], spEntityID)
	}

	// Session index: the subject now has one SP row with the registered SLO URL.
	rows, err := idx.ListBySubject(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("session index rows = %d, want 1", len(rows))
	}
	if rows[0].SPEntityID != spEntityID {
		t.Errorf("indexed SP entity = %q, want %q", rows[0].SPEntityID, spEntityID)
	}
	if rows[0].SPSLOUrl != sloURL {
		t.Errorf("indexed SLO URL = %q, want %q", rows[0].SPSLOUrl, sloURL)
	}
}

// TestFinish_NonHTTPSSLOUrl_DroppedFromIndex proves the issuance-time SSRF gate:
// a registered SLO URL that is NOT absolute-https is recorded with an EMPTY
// SPSLOUrl (so it never becomes a fan-out destination), while the row itself is
// still kept (so RemoveAll stays a faithful subject->SP picture).
func TestFinish_NonHTTPSSLOUrl_DroppedFromIndex(t *testing.T) {
	t.Parallel()
	const badSLO = "http://sp.example.com/saml/slo" // plain http — not allowed
	hh, _, idx := newRecordingHarness(t, badSLO)

	const userID = "bob@example.com"
	sessionID := hh.seedUserSession(t, userID)
	pendingID := hh.insertPending(t, "id-req-badslo")

	if rec := hh.postFinish(sessionID, pendingID); rec.Code != http.StatusOK {
		t.Fatalf("finish status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	rows, err := idx.ListBySubject(context.Background(), userID)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("session index rows = %d, want 1 (row kept for RemoveAll)", len(rows))
	}
	if rows[0].SPSLOUrl != "" {
		t.Errorf("non-https SLO URL leaked into the fan-out target: %q, want empty", rows[0].SPSLOUrl)
	}
}

// TestFinish_NoRecorderNoIndex_StillSucceeds proves the recording hooks are
// best-effort no-ops when unwired: the finish flow issues the assertion and
// returns 200 even with a nil AuditRecorder + nil SessionIndex (the default
// harness path), so recording can never fail the issue path.
func TestFinish_NoRecorderNoIndex_StillSucceeds(t *testing.T) {
	t.Parallel()
	hh := newHarness(t, issuerRSA) // no AuditRecorder, no SessionIndex
	sessionID := hh.seedUserSession(t, "carol@example.com")
	pendingID := hh.insertPending(t, "id-req-norec")

	rec := hh.postFinish(sessionID, pendingID)
	if rec.Code != http.StatusOK {
		t.Fatalf("finish (no recorder/index) status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	// Sanity: the auto-POST form carries a SAMLResponse.
	if !strings.Contains(rec.Body.String(), "SAMLResponse") {
		t.Error("finish body missing SAMLResponse form field")
	}
}
