package ssotest

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
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
}
