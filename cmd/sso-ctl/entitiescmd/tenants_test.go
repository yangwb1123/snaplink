package entitiescmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangwb1123/snaplink/cmd/sso-ctl/apiclient"
)

// withMockAdmin points apiclient (and therefore RunTenants/RunUsers) at a
// local httptest server for the duration of the test.
func withMockAdmin(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	t.Setenv(apiclient.EnvAddr, srv.URL)
	return srv
}

func TestRunTenants_ListSuccess(t *testing.T) {
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/tenants" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tenants": []Tenant{{ID: "acme", Name: "Acme", Slug: "acme", Status: "active"}},
		})
	})

	if code := RunTenants([]string{"list"}); code != 0 {
		t.Fatalf("RunTenants(list) = %d, want 0", code)
	}
}

func TestRunTenants_GetNotFound(t *testing.T) {
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "tenant_not_found"})
	})

	if code := RunTenants([]string{"get", "missing"}); code != 1 {
		t.Fatalf("RunTenants(get missing) = %d, want 1", code)
	}
}

func TestRunTenants_Create(t *testing.T) {
	var gotBody Tenant
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/tenants" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant": gotBody})
	})

	code := RunTenants([]string{"create", "--id=acme", "--status=active", "--name=Acme Inc", "--slug=acme"})
	if code != 0 {
		t.Fatalf("RunTenants(create) = %d, want 0", code)
	}
	if gotBody.ID != "acme" || gotBody.Status != "active" || gotBody.Name != "Acme Inc" || gotBody.Slug != "acme" {
		t.Errorf("unexpected request body: %+v", gotBody)
	}
}

func TestRunTenants_CreateRejectsInvalidStatus(t *testing.T) {
	// No server needed: validation happens before any request is sent.
	t.Setenv(apiclient.EnvAddr, "http://127.0.0.1:0")

	code := RunTenants([]string{"create", "--id=acme", "--status=bogus"})
	if code != 2 {
		t.Fatalf("RunTenants(create bad status) = %d, want 2", code)
	}
}

func TestRunTenants_Delete(t *testing.T) {
	var called bool
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/admin/tenants/acme" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})

	if code := RunTenants([]string{"delete", "acme", "--yes"}); code != 0 {
		t.Fatalf("RunTenants(delete --yes) = %d, want 0", code)
	}
	if !called {
		t.Error("expected DELETE request to be sent")
	}
}

func TestRunTenants_DeleteRefusesWithoutYes(t *testing.T) {
	var called bool
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	if code := RunTenants([]string{"delete", "acme"}); code != 2 {
		t.Fatalf("RunTenants(delete without --yes) = %d, want 2", code)
	}
	if called {
		t.Error("expected no request to be sent without --yes")
	}
}

// TestRunTenants_UpdateOmitsStatus is a regression test for the documented
// admin-API footgun: the update request body must never carry a "status"
// key, since the server's PUT handler ignores/preserves status and status
// transitions must go through set-status instead.
func TestRunTenants_UpdateOmitsStatus(t *testing.T) {
	var raw map[string]any
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/admin/tenants/acme" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant": raw})
	})

	code := RunTenants([]string{"update", "acme", "--name=Renamed"})
	if code != 0 {
		t.Fatalf("RunTenants(update) = %d, want 0", code)
	}
	if _, present := raw["status"]; present {
		t.Errorf("update request body must not contain \"status\", got: %v", raw)
	}
	if raw["name"] != "Renamed" {
		t.Errorf("update request body name = %v, want Renamed", raw["name"])
	}
}

func TestRunTenants_SetStatus(t *testing.T) {
	var gotBody map[string]string
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/tenants/acme:set-status" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"tenant": map[string]string{"id": "acme", "status": gotBody["status"]}})
	})

	code := RunTenants([]string{"set-status", "acme", "suspended"})
	if code != 0 {
		t.Fatalf("RunTenants(set-status) = %d, want 0", code)
	}
	if gotBody["status"] != "suspended" {
		t.Errorf("set-status request body = %v, want status=suspended", gotBody)
	}
}
