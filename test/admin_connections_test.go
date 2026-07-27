package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func newAdminConnectionsHarness(t *testing.T) (*httptest.Server, connections.Store) {
	t.Helper()
	store := connections.NewMemoryStore()
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithConnectionStore(store),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, store
}

func postJSON(t *testing.T, srv *httptest.Server, path string, body any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	b, _ := io.ReadAll(resp.Body)
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func TestAdminConnections_CRUD(t *testing.T) {
	srv, _ := newAdminConnectionsHarness(t)

	// Create.
	conn := map[string]any{
		"id": "acme", "tenant_id": "t1", "type": "oidc",
		"display_name": "Acme Corp", "domains": []string{"acme.com"},
		"enabled": true, "config": map[string]string{"oidc_issuer": "https://idp.acme.com"},
	}
	code, body := postJSON(t, srv, "/api/v1/admin/connections", conn)
	if code != http.StatusOK {
		t.Fatalf("upsert status=%d body=%v", code, body)
	}
	if body["id"] != "acme" || body["display_name"] != "Acme Corp" {
		t.Errorf("upsert returned %v", body)
	}

	// Get.
	gc, gbody := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/acme", "")
	if gc != http.StatusOK || gbody["tenant_id"] != "t1" {
		t.Fatalf("get status=%d body=%v", gc, gbody)
	}

	// List by tenant.
	lc, lbody := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections?tenant_id=t1", "")
	if lc != http.StatusOK {
		t.Fatalf("list status=%d", lc)
	}
	if list, _ := lbody["connections"].([]any); len(list) != 1 {
		t.Errorf("list = %v, want 1", lbody)
	}

	// Delete.
	dc, _ := doReq(t, srv, http.MethodDelete, "/api/v1/admin/connections/acme", "")
	if dc != http.StatusNoContent {
		t.Fatalf("delete status=%d", dc)
	}
	// Now gone.
	nc, _ := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/acme", "")
	if nc != http.StatusNotFound {
		t.Errorf("get after delete = %d, want 404", nc)
	}
}

func TestAdminConnections_Validation(t *testing.T) {
	srv, _ := newAdminConnectionsHarness(t)

	// Invalid type.
	if code, _ := postJSON(t, srv, "/api/v1/admin/connections", map[string]any{
		"id": "x", "tenant_id": "t1", "type": "ldap",
	}); code != http.StatusBadRequest {
		t.Errorf("invalid type status=%d, want 400", code)
	}
	// Missing id.
	if code, _ := postJSON(t, srv, "/api/v1/admin/connections", map[string]any{
		"tenant_id": "t1", "type": "oidc",
	}); code != http.StatusBadRequest {
		t.Errorf("missing id status=%d, want 400", code)
	}
	// List without tenant_id.
	if code, _ := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections", ""); code != http.StatusBadRequest {
		t.Errorf("list without tenant_id status=%d, want 400", code)
	}
}

func TestAdminConnections_NotMountedWithoutStore(t *testing.T) {
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()
	code, _ := doReq(t, hs, http.MethodGet, "/api/v1/admin/connections?tenant_id=t1", "")
	if code != http.StatusNotFound {
		t.Errorf("unmounted list status=%d, want 404", code)
	}
	if code, _ := doReq(t, hs, http.MethodGet, "/api/v1/admin/connections/acme/health", ""); code != http.StatusNotFound {
		t.Errorf("unmounted health status=%d, want 404", code)
	}
	if code, _ := doReq(t, hs, http.MethodPost, "/api/v1/admin/connections/acme/probe", ""); code != http.StatusNotFound {
		t.Errorf("unmounted probe status=%d, want 404", code)
	}
}

// fakeProber is a deterministic connections.Prober test double — no real
// network — so the admin endpoint tests exercise the store-orchestration +
// HTTP-wiring layer without depending on httpProber's real GET behavior
// (that's covered directly in domains/connections/probe_test.go).
type fakeProber struct {
	mu     sync.Mutex
	result connections.ProbeResult
	calls  int
}

func (f *fakeProber) Probe(_ context.Context, _ *connections.Connection) connections.ProbeResult {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.result
}

func (f *fakeProber) setResult(r connections.ProbeResult) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result = r
}

func newAdminConnectionHealthHarness(t *testing.T) (*httptest.Server, *fakeProber) {
	t.Helper()
	store := connections.NewMemoryStore()
	prober := &fakeProber{result: connections.ProbeResult{Status: connections.HealthHealthy}}
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithConnectionStore(store),
		sso.WithConnectionProber(prober),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, prober
}

func TestAdminConnections_Health_UnprobedReadsUnknown(t *testing.T) {
	srv, _ := newAdminConnectionHealthHarness(t)
	if code, body := postJSON(t, srv, "/api/v1/admin/connections", map[string]any{
		"id": "acme", "tenant_id": "t1", "type": "oidc",
	}); code != http.StatusOK {
		t.Fatalf("upsert = %d body=%v", code, body)
	}

	code, body := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/acme/health", "")
	if code != http.StatusOK {
		t.Fatalf("get health = %d body=%v", code, body)
	}
	if body["status"] != "unknown" || body["last_checked_at"] != nil {
		t.Errorf("unprobed health = %v, want status=unknown with no last_checked_at", body)
	}
}

func TestAdminConnections_Health_UnknownConnectionIs404(t *testing.T) {
	srv, _ := newAdminConnectionHealthHarness(t)
	if code, _ := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/nope/health", ""); code != http.StatusNotFound {
		t.Errorf("get health for missing connection = %d, want 404", code)
	}
	if code, _ := doReq(t, srv, http.MethodPost, "/api/v1/admin/connections/nope/probe", ""); code != http.StatusNotFound {
		t.Errorf("probe missing connection = %d, want 404", code)
	}
}

func TestAdminConnections_Probe_HealthyPersistsAndReadsBack(t *testing.T) {
	srv, prober := newAdminConnectionHealthHarness(t)
	if code, _ := postJSON(t, srv, "/api/v1/admin/connections", map[string]any{
		"id": "acme", "tenant_id": "t1", "type": "oidc",
	}); code != http.StatusOK {
		t.Fatal("upsert failed")
	}
	prober.setResult(connections.ProbeResult{Status: connections.HealthHealthy})

	code, body := doReq(t, srv, http.MethodPost, "/api/v1/admin/connections/acme/probe", "")
	if code != http.StatusOK {
		t.Fatalf("probe = %d body=%v", code, body)
	}
	if body["status"] != "healthy" || body["last_checked_at"] == nil || body["last_success_at"] == nil {
		t.Fatalf("probe response = %v, want healthy with timestamps", body)
	}
	if prober.calls != 1 {
		t.Errorf("prober called %d times, want 1", prober.calls)
	}

	// GET .../health reflects the just-persisted probe outcome.
	code, body = doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/acme/health", "")
	if code != http.StatusOK || body["status"] != "healthy" {
		t.Fatalf("get health after probe = %d body=%v", code, body)
	}
}

func TestAdminConnections_Probe_UnreachableReturns200WithError(t *testing.T) {
	srv, prober := newAdminConnectionHealthHarness(t)
	if code, _ := postJSON(t, srv, "/api/v1/admin/connections", map[string]any{
		"id": "acme", "tenant_id": "t1", "type": "oidc",
	}); code != http.StatusOK {
		t.Fatal("upsert failed")
	}
	prober.setResult(connections.ProbeResult{Status: connections.HealthUnreachable, Err: "dial tcp: connection refused"})

	// A bad outcome is still a 200 — the CHECK succeeded, the result is bad news.
	code, body := doReq(t, srv, http.MethodPost, "/api/v1/admin/connections/acme/probe", "")
	if code != http.StatusOK {
		t.Fatalf("probe = %d body=%v", code, body)
	}
	if body["status"] != "unreachable" || body["last_error"] == "" || body["last_error"] == nil {
		t.Fatalf("probe response = %v, want unreachable with a last_error", body)
	}
	if body["last_success_at"] != nil {
		t.Errorf("last_success_at = %v, want omitted (never succeeded)", body["last_success_at"])
	}
}

// fakeDomainResolver is the hermetic (no real network) DNS double used to drive
// the admin domain-verify endpoint.
type fakeDomainResolver struct {
	mu      sync.Mutex
	records map[string][]string
}

func (f *fakeDomainResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.records[name], nil
}

func (f *fakeDomainResolver) publish(name string, values ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.records == nil {
		f.records = map[string][]string{}
	}
	f.records[name] = values
}

func newVerifiedConnHarness(t *testing.T) (*httptest.Server, *fakeDomainResolver) {
	t.Helper()
	store := connections.NewMemoryStore(connections.WithDomainVerificationRequired(true))
	res := &fakeDomainResolver{}
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
		sso.WithConnectionStore(store),
		sso.WithDomainVerificationResolver(res),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs, res
}

// firstDomainClaim extracts the single claim from a GET .../domains response.
func firstDomainClaim(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	list, _ := body["domains"].([]any)
	if len(list) != 1 {
		t.Fatalf("want exactly one domain claim, got %v", body)
	}
	claim, _ := list[0].(map[string]any)
	return claim
}

func TestAdminConnections_DomainVerification_Endpoints(t *testing.T) {
	srv, res := newVerifiedConnHarness(t)

	// Seed a connection claiming acme.com (pending, not yet routing).
	if code, body := postJSON(t, srv, "/api/v1/admin/connections", map[string]any{
		"id": "acme", "tenant_id": "t1", "type": "oidc",
		"domains": []string{"acme.com"}, "enabled": true,
	}); code != http.StatusOK {
		t.Fatalf("upsert = %d body=%v", code, body)
	}

	// List domains: the claim is pending with a challenge token + record.
	code, body := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/acme/domains", "")
	if code != http.StatusOK {
		t.Fatalf("list domains = %d body=%v", code, body)
	}
	claim := firstDomainClaim(t, body)
	if claim["status"] != "pending" || claim["token"] == "" || claim["record"] == "" {
		t.Fatalf("claim = %v, want pending with token+record", claim)
	}
	record, _ := claim["record"].(string)
	token, _ := claim["token"].(string)

	// Verify before publishing the TXT record: 200, still pending (not an error).
	code, body = doReq(t, srv, http.MethodPost, "/api/v1/admin/connections/acme/domains/acme.com/verify", "")
	if code != http.StatusOK || body["verified"] != false || body["status"] != "pending" {
		t.Fatalf("premature verify = %d body=%v", code, body)
	}

	// Publish the correct TXT value, then verify succeeds.
	res.publish(record, token)
	code, body = doReq(t, srv, http.MethodPost, "/api/v1/admin/connections/acme/domains/acme.com/verify", "")
	if code != http.StatusOK || body["verified"] != true || body["status"] != "verified" {
		t.Fatalf("verify = %d body=%v", code, body)
	}

	// The listing now reflects verified.
	_, body = doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/acme/domains", "")
	if firstDomainClaim(t, body)["status"] != "verified" {
		t.Errorf("listing should show verified, got %v", body)
	}

	// 404s: unknown connection, and a domain this connection never claimed.
	if code, _ := doReq(t, srv, http.MethodGet, "/api/v1/admin/connections/nope/domains", ""); code != http.StatusNotFound {
		t.Errorf("list domains for missing connection = %d, want 404", code)
	}
	if code, _ := doReq(t, srv, http.MethodPost, "/api/v1/admin/connections/acme/domains/other.com/verify", ""); code != http.StatusNotFound {
		t.Errorf("verify unclaimed domain = %d, want 404", code)
	}
}
