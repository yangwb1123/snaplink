package entitiescmd

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRunUsers_ListSuccess(t *testing.T) {
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/admin/users" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"users": []AdminUser{{ID: "u1", ExternalID: "ext1", Provider: "auth0"}},
		})
	})

	if code := RunUsers([]string{"list"}); code != 0 {
		t.Fatalf("RunUsers(list) = %d, want 0", code)
	}
}

func TestRunUsers_GetNotFound(t *testing.T) {
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "user_not_found"})
	})

	if code := RunUsers([]string{"get", "missing"}); code != 1 {
		t.Fatalf("RunUsers(get missing) = %d, want 1", code)
	}
}

func TestRunUsers_Create(t *testing.T) {
	var gotBody AdminUser
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/admin/users" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": gotBody})
	})

	code := RunUsers([]string{
		"create", "--id=u1", "--external-id=ext1", "--provider=auth0",
		"--attr=email=a@example.com", "--attr=dept=eng",
	})
	if code != 0 {
		t.Fatalf("RunUsers(create) = %d, want 0", code)
	}
	if gotBody.ID != "u1" || gotBody.ExternalID != "ext1" || gotBody.Provider != "auth0" {
		t.Errorf("unexpected request body: %+v", gotBody)
	}
	if gotBody.Attributes["email"] != "a@example.com" || gotBody.Attributes["dept"] != "eng" {
		t.Errorf("unexpected attributes: %+v", gotBody.Attributes)
	}
}

func TestRunUsers_CreateNoAttrsSendsEmptyMap(t *testing.T) {
	var raw map[string]any
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": raw})
	})

	code := RunUsers([]string{"create", "--id=u1"})
	if code != 0 {
		t.Fatalf("RunUsers(create) = %d, want 0", code)
	}
	attrs, ok := raw["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("expected \"attributes\" to be present as an object, got: %v", raw["attributes"])
	}
	if len(attrs) != 0 {
		t.Errorf("expected empty attributes map, got: %v", attrs)
	}
}

func TestRunUsers_CreateRejectsMalformedAttr(t *testing.T) {
	t.Setenv("SSO_ADMIN_ADDR", "http://127.0.0.1:0")

	code := RunUsers([]string{"create", "--id=u1", "--attr=no-equals-sign"})
	if code != 2 {
		t.Fatalf("RunUsers(create malformed attr) = %d, want 2", code)
	}
}

func TestRunUsers_Update(t *testing.T) {
	var gotBody AdminUser
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Path != "/api/v1/admin/users/u1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"user": gotBody})
	})

	code := RunUsers([]string{"update", "u1", "--provider=okta"})
	if code != 0 {
		t.Fatalf("RunUsers(update) = %d, want 0", code)
	}
	if gotBody.ID != "u1" || gotBody.Provider != "okta" {
		t.Errorf("unexpected request body: %+v", gotBody)
	}
}

func TestRunUsers_Delete(t *testing.T) {
	var called bool
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/admin/users/u1" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{})
	})

	if code := RunUsers([]string{"delete", "u1", "--yes"}); code != 0 {
		t.Fatalf("RunUsers(delete --yes) = %d, want 0", code)
	}
	if !called {
		t.Error("expected DELETE request to be sent")
	}
}

func TestRunUsers_DeleteRefusesWithoutYes(t *testing.T) {
	var called bool
	withMockAdmin(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	if code := RunUsers([]string{"delete", "u1"}); code != 2 {
		t.Fatalf("RunUsers(delete without --yes) = %d, want 2", code)
	}
	if called {
		t.Error("expected no request to be sent without --yes")
	}
}
