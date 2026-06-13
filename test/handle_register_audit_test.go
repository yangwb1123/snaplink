package ssotest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/oauth"
)

// newDCRAuditHarness wires a DCR server with a real audit Recorder backed by
// an in-memory Sink (no mocks, per §2/§8) so tests can assert exactly which
// credential-lifecycle events the self-service /register paths emit.
func newDCRAuditHarness(t *testing.T, policy oauth.DCRPolicy) (*httptest.Server, *audit.MemorySink, sso.ClientStore) {
	t.Helper()
	sink := audit.NewMemorySink(0)
	clients := defaultimpl.NewMemoryClientStore()
	srv := sso.NewServer(
		sso.WithClientStore(clients),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDynamicClientRegistration(policy),
		sso.WithAuditRecorder(audit.New(sink)),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink, clients
}

// eventsOfType returns every event of type t currently in the sink.
func eventsOfType(t *testing.T, sink *audit.MemorySink, et audit.EventType) []*audit.Event {
	t.Helper()
	evs, err := sink.Query(context.Background(), audit.Query{Type: et, Limit: 100})
	if err != nil {
		t.Fatalf("sink.Query(%s): %v", et, err)
	}
	return evs
}

// registerForAudit mints a client and returns (client_id, regToken, mgmtURI).
func registerForAudit(t *testing.T, srvURL string) (string, string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
		"client_name":   "audit-test",
	})
	resp, err := http.Post(srvURL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	id, _ := out["client_id"].(string)
	tok, _ := out["registration_access_token"].(string)
	uri, _ := out["registration_client_uri"].(string)
	if id == "" || tok == "" || uri == "" {
		t.Fatalf("missing fields in register response: %s", raw)
	}
	return id, tok, uri
}

func TestDCRAudit_Create_EmitsClientRegistered(t *testing.T) {
	srv, sink, _ := newDCRAuditHarness(t, oauth.DCRPolicy{
		InitialAccessToken:   dcrInitialAT,
		DefaultActive:        true,
		DefaultTokenStrategy: "jwt",
	})
	status, body := postDCR(t, srv, dcrInitialAT, map[string]any{
		"client_name":   "my app",
		"redirect_uris": []string{"https://app.example/cb"},
	})
	if status != http.StatusCreated {
		t.Fatalf("status=%d body=%v", status, body)
	}
	id, _ := body["client_id"].(string)

	evs := eventsOfType(t, sink, audit.EventClientRegistered)
	if len(evs) != 1 {
		t.Fatalf("EventClientRegistered count = %d, want 1", len(evs))
	}
	e := evs[0]
	if e.ClientID != id {
		t.Errorf("ClientID = %q want %q", e.ClientID, id)
	}
	if e.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q want success", e.Outcome)
	}
	// Initial-access-token registration records its method.
	if m := e.Metadata["registration_method"]; m != "initial_access_token" {
		t.Errorf("registration_method = %q want initial_access_token", m)
	}
}

func TestDCRAudit_Create_OpenRegistration_RecordsOpenMethod(t *testing.T) {
	srv, sink, _ := newDCRAuditHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	})
	status, body := postDCR(t, srv, "", map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
		"client_name":   "open-app",
	})
	if status != http.StatusCreated {
		t.Fatalf("status=%d body=%v", status, body)
	}
	evs := eventsOfType(t, sink, audit.EventClientRegistered)
	if len(evs) != 1 {
		t.Fatalf("EventClientRegistered count = %d, want 1", len(evs))
	}
	if m := evs[0].Metadata["registration_method"]; m != "open" {
		t.Errorf("registration_method = %q want open", m)
	}
}

func TestDCRAudit_Update_EmitsClientUpdated(t *testing.T) {
	srv, sink, store := newDCRAuditHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	})
	id, tok, uri := registerForAudit(t, srv.URL)

	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://app.example/cb-new"},
		"client_name":   "updated-name",
	})
	req, _ := http.NewRequest(http.MethodPut, uri, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	// Sanity: the store actually changed (the event tracks a real mutation).
	if stored, _ := store.Get(context.Background(), id); stored == nil || stored.Name != "updated-name" {
		t.Fatalf("store not updated")
	}

	evs := eventsOfType(t, sink, audit.EventClientUpdated)
	if len(evs) != 1 {
		t.Fatalf("EventClientUpdated count = %d, want 1", len(evs))
	}
	if evs[0].ClientID != id {
		t.Errorf("ClientID = %q want %q", evs[0].ClientID, id)
	}
	if evs[0].Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q want success", evs[0].Outcome)
	}
}

func TestDCRAudit_Delete_EmitsClientDeleted(t *testing.T) {
	srv, sink, _ := newDCRAuditHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	})
	id, tok, uri := registerForAudit(t, srv.URL)

	req, _ := http.NewRequest(http.MethodDelete, uri, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}

	evs := eventsOfType(t, sink, audit.EventClientDeleted)
	if len(evs) != 1 {
		t.Fatalf("EventClientDeleted count = %d, want 1", len(evs))
	}
	if evs[0].ClientID != id {
		t.Errorf("ClientID = %q want %q", evs[0].ClientID, id)
	}
}

// TestDCRAudit_Update_WrongBearer_EmitsNoEvent locks the §2 anti-enumeration
// property: a 7592 update with a WRONG registration_access_token returns the
// identical 401 invalid_token AND records NOTHING (auditing the rejection
// would leak that the client_id exists — a client-existence oracle).
func TestDCRAudit_Update_WrongBearer_EmitsNoEvent(t *testing.T) {
	srv, sink, _ := newDCRAuditHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true})
	_, _, uri := registerForAudit(t, srv.URL)

	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://attacker.example/steal"},
	})
	req, _ := http.NewRequest(http.MethodPut, uri, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer wrong-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if n := len(eventsOfType(t, sink, audit.EventClientUpdated)); n != 0 {
		t.Errorf("EventClientUpdated count = %d, want 0 (failed bearer must not be audited)", n)
	}
}

// TestDCRAudit_Delete_MissingBearer_EmitsNoEvent is the delete-side companion:
// a missing bearer is the same identical 401 and records nothing.
func TestDCRAudit_Delete_MissingBearer_EmitsNoEvent(t *testing.T) {
	srv, sink, store := newDCRAuditHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true})
	id, _, uri := registerForAudit(t, srv.URL)

	req, _ := http.NewRequest(http.MethodDelete, uri, nil)
	// no Authorization header
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if n := len(eventsOfType(t, sink, audit.EventClientDeleted)); n != 0 {
		t.Errorf("EventClientDeleted count = %d, want 0 (missing bearer must not be audited)", n)
	}
	// The client must still exist — the rejected delete was a no-op.
	if _, err := store.Get(context.Background(), id); err != nil {
		t.Errorf("client removed by an unauthorized delete: %v", err)
	}
}

// TestDCRAudit_UnknownClient_WrongBearer_EmitsNoEvent rounds out the oracle
// proof: probing an unknown client_id with any bearer is the identical 401
// and records nothing (no client-existence signal in the audit log either).
func TestDCRAudit_UnknownClient_WrongBearer_EmitsNoEvent(t *testing.T) {
	srv, sink, _ := newDCRAuditHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/register/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer something")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if n := len(eventsOfType(t, sink, audit.EventClientDeleted)); n != 0 {
		t.Errorf("EventClientDeleted count = %d, want 0", n)
	}
}
