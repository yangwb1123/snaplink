package ssotest

import "github.com/snaplink/sso/oauth"

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// registerForMgmt creates a new client and returns
// (client_id, registration_access_token, registration_client_uri).
func registerForMgmt(t *testing.T, srvURL string) (string, string, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
		"client_name":   "mgmt-test",
	})
	resp, err := http.Post(srvURL+"/register", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	defer resp.Body.Close()
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

func TestRegistrationMgmt_Get_HappyPath(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	})
	id, tok, uri := registerForMgmt(t, srv.URL)

	req, _ := http.NewRequest(http.MethodGet, uri, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["client_id"] != id {
		t.Errorf("client_id = %v want %q", out["client_id"], id)
	}
	if out["client_name"] != "mgmt-test" {
		t.Errorf("client_name = %v", out["client_name"])
	}
	// RFC 7592 §2.1: GET response SHOULD NOT include the
	// registration_access_token (only the original /register
	// response is the canonical token-distribution point).
	if _, ok := out["registration_access_token"]; ok {
		t.Errorf("GET response must not echo registration_access_token: %v", out)
	}
}

func TestRegistrationMgmt_Get_RejectsBadToken(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	_, _, uri := registerForMgmt(t, srv.URL)

	req, _ := http.NewRequest(http.MethodGet, uri, nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRegistrationMgmt_Get_UnknownClientLooksLikeBadToken(t *testing.T) {
	// Anti-enumeration: an unknown client_id MUST NOT be a 404 (would
	// let an unauthed caller probe for client_id existence). Should
	// look identical to a wrong-token failure.
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/register/nonexistent", nil)
	req.Header.Set("Authorization", "Bearer something")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
}

func TestRegistrationMgmt_Put_UpdatesMetadata(t *testing.T) {
	srv, store := newDCRHarness(t, oauth.DCRPolicy{
		AllowOpenRegistration: true,
		DefaultActive:         true,
	})
	id, tok, uri := registerForMgmt(t, srv.URL)

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
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}

	// Store reflects the new metadata; registration_access_token
	// + client_secret survived unchanged.
	stored, err := store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if stored.Name != "updated-name" {
		t.Errorf("Name = %q want updated-name", stored.Name)
	}
	if len(stored.RedirectURIs) != 1 || stored.RedirectURIs[0] != "https://app.example/cb-new" {
		t.Errorf("RedirectURIs = %v", stored.RedirectURIs)
	}
	if stored.RegistrationAccessToken != tok {
		t.Errorf("RegistrationAccessToken changed: %q want %q", stored.RegistrationAccessToken, tok)
	}
}

func TestRegistrationMgmt_Put_RejectsBadToken(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	_, _, uri := registerForMgmt(t, srv.URL)

	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://attacker.example/steal"},
	})
	req, _ := http.NewRequest(http.MethodPut, uri, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRegistrationMgmt_Put_RejectsInvalidMetadata(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	_, tok, uri := registerForMgmt(t, srv.URL)

	body, _ := json.Marshal(map[string]any{
		// no redirect_uris while default grant_types includes authorization_code
		"client_name": "broken",
	})
	req, _ := http.NewRequest(http.MethodPut, uri, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestRegistrationMgmt_Delete_RemovesClient(t *testing.T) {
	srv, store := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true})
	id, tok, uri := registerForMgmt(t, srv.URL)

	req, _ := http.NewRequest(http.MethodDelete, uri, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	// Store reflects the delete; subsequent Get returns an error.
	if _, err := store.Get(context.Background(), id); err == nil {
		t.Errorf("client still present after DELETE")
	}
}

func TestRegistrationMgmt_Delete_RejectsBadToken(t *testing.T) {
	srv, _ := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true})
	_, _, uri := registerForMgmt(t, srv.URL)

	req, _ := http.NewRequest(http.MethodDelete, uri, nil)
	req.Header.Set("Authorization", "Bearer wrong")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestRegistrationMgmt_PreservesSecretAcrossUpdates(t *testing.T) {
	srv, store := newDCRHarness(t, oauth.DCRPolicy{AllowOpenRegistration: true, DefaultActive: true})
	id, tok, uri := registerForMgmt(t, srv.URL)
	originalSecret, _ := store.Get(context.Background(), id)

	body, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://app.example/cb"},
		"client_name":   "name-change-only",
	})
	req, _ := http.NewRequest(http.MethodPut, uri, strings.NewReader(string(body)))
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()

	after, _ := store.Get(context.Background(), id)
	if after.Secret != originalSecret.Secret {
		t.Errorf("client_secret changed across PUT: %q → %q", originalSecret.Secret, after.Secret)
	}
}
