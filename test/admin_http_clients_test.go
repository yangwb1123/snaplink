package ssotest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newAdminClientHarness wires a server with a MemoryClientStore seeded with a
// known client, so admin client-lookup endpoints have data to return.
func newAdminClientHarness(t *testing.T) *httptest.Server {
	t.Helper()
	store := defaultimpl.NewMemoryClientStore()
	store.AddSeed(&sso.Client{
		ID:                    "client-1",
		Secret:                "secret-1",
		Name:                  "Test Client One",
		AllowedScopes:         []string{"openid", "profile"},
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt",
		Active:                true,
	})
	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithClientStore(store),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

// TestAdminClientLookup_GetByID verifies the public GET /api/v1/clients/:id
// endpoint returns the expected client fields for a known client and 404 for an
// unknown one. This is the HTTP equivalent of what the gRPC-only tests in
// admin_grpc_clients_test.go exercise via bufconn.
func TestAdminClientLookup_GetByID(t *testing.T) {
	srv := newAdminClientHarness(t)

	// Known client — 200 + JSON body.
	code, body := doReq(t, srv, http.MethodGet, "/api/v1/clients/client-1", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/v1/clients/client-1 status=%d, want 200", code)
	}
	if id, _ := body["id"].(string); id != "client-1" {
		t.Errorf("id = %q, want client-1", id)
	}
	if name, _ := body["name"].(string); name != "Test Client One" {
		t.Errorf("name = %q, want Test Client One", name)
	}
	if active, _ := body["active"].(bool); !active {
		t.Errorf("active = %v, want true", active)
	}

	// Sensitive fields MUST NOT be exposed on the public endpoint.
	if _, ok := body["secret"]; ok {
		t.Errorf("public client endpoint leaked secret field")
	}
	if _, ok := body["client_secret"]; ok {
		t.Errorf("public client endpoint leaked client_secret field")
	}
}

// TestAdminClientLookup_UnknownID returns 404 with the expected error shape.
func TestAdminClientLookup_UnknownID(t *testing.T) {
	srv := newAdminClientHarness(t)

	code, body := doReq(t, srv, http.MethodGet, "/api/v1/clients/no-such-client", "")
	if code != http.StatusNotFound {
		t.Fatalf("GET /api/v1/clients/no-such-client status=%d, want 404", code)
	}
	if err, _ := body["error"].(string); err == "" {
		t.Errorf("body = %v, want error field", body)
	}
}

// TestAdminClientLookup_MissingID returns 400 when the id param is empty.
func TestAdminClientLookup_MissingID(t *testing.T) {
	srv := newAdminClientHarness(t)

	code, body := doReq(t, srv, http.MethodGet, "/api/v1/clients/", "")
	if code != http.StatusBadRequest {
		t.Fatalf("GET /api/v1/clients/ status=%d, want 400", code)
	}
	if err, _ := body["error"].(string); err == "" {
		t.Errorf("body = %v, want error field for missing id", body)
	}
}

// TestAdminClientLookup_NoStoreMounted returns 500 when no client store is wired.
func TestAdminClientLookup_NoStoreMounted(t *testing.T) {
	// Server without WithClientStore.
	srv := sso.NewServer(sso.WithIssuer("https://sso.example"))
	hs := httptest.NewServer(srv.Handler())
	defer hs.Close()

	code, body := doReq(t, hs, http.MethodGet, "/api/v1/clients/client-1", "")
	if code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500 (no client store)", code)
	}
	if err, _ := body["error"].(string); err == "" {
		t.Errorf("body = %v, want error field", body)
	}
}
