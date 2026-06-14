package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

// getMe issues GET /me with an optional bearer token.
func getMe(t *testing.T, baseURL, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/me", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestMe_ReturnsProfileAndCounts verifies the self-service overview returns the
// bearer's own sub + profile + an active-session count.
func TestMe_ReturnsProfileAndCounts(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	token := loginAs("alice")

	status, body := getMe(t, srv.URL, token)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["sub"] != "u-alice" {
		t.Errorf("sub = %v, want u-alice", body["sub"])
	}
	user, _ := body["user"].(map[string]any)
	if user == nil || user["id"] != "u-alice" {
		t.Errorf("user = %v, want id u-alice", body["user"])
	}
	// A login mints a session, so the count is at least 1.
	if c, ok := body["active_sessions"].(float64); !ok || c < 1 {
		t.Errorf("active_sessions = %v, want >= 1", body["active_sessions"])
	}
	// iss is present on every response.
	if iss, _ := body["iss"].(string); iss == "" {
		t.Errorf("iss missing from /me response")
	}
}

// TestMe_RequiresBearer verifies an unauthenticated request is rejected with
// the standard 401 challenge (not a silent empty profile).
func TestMe_RequiresBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	status, _ := getMe(t, srv.URL, "")
	if status != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 without a bearer", status)
	}
}

// TestMe_InvalidTokenRejected verifies a malformed bearer is rejected.
func TestMe_InvalidTokenRejected(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	status, _ := getMe(t, srv.URL, "not-a-real-token")
	if status != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 for an invalid token", status)
	}
}

// patchMe issues PATCH /me with a JSON body and optional bearer.
func patchMe(t *testing.T, baseURL, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPatch, baseURL+"/me", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("PATCH /me: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestPatchMe_UpdatesName verifies a user can edit their own display name and
// that the change persists (a follow-up GET /me reflects it).
func TestPatchMe_UpdatesName(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	token := loginAs("alice")

	status, body := patchMe(t, srv.URL, token, map[string]any{"name": "Alice Smith"})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	user, _ := body["user"].(map[string]any)
	if user == nil || user["name"] != "Alice Smith" {
		t.Errorf("user.name = %v, want Alice Smith", body["user"])
	}
	_, got := getMe(t, srv.URL, token)
	gu, _ := got["user"].(map[string]any)
	if gu == nil || gu["name"] != "Alice Smith" {
		t.Errorf("GET /me name = %v, want Alice Smith (not persisted)", got["user"])
	}
}

// TestPatchMe_DropsNonAllowlistedAttributes verifies that with no allowlist
// configured, attributes are ignored entirely — a user cannot self-assign an
// authz-relevant key like "role".
func TestPatchMe_DropsNonAllowlistedAttributes(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	token := loginAs("alice")

	status, _ := patchMe(t, srv.URL, token, map[string]any{
		"name":       "Alice",
		"attributes": map[string]string{"role": "admin"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	_, got := getMe(t, srv.URL, token)
	gu, _ := got["user"].(map[string]any)
	if attrs, _ := gu["attributes"].(map[string]any); attrs != nil {
		if _, leaked := attrs["role"]; leaked {
			t.Errorf("non-allowlisted attribute 'role' was written: %v", attrs)
		}
	}
}

// TestPatchMe_NoBearer verifies an unauthenticated PATCH is rejected.
func TestPatchMe_NoBearer(t *testing.T) {
	srv, _, _ := newMeSessionsHarness(t)
	status, _ := patchMe(t, srv.URL, "", map[string]any{"name": "x"})
	if status != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 without a bearer", status)
	}
}

// TestPatchMe_AllowlistedAttributeApplied verifies that an attribute key in the
// operator allowlist IS applied, while a sibling non-allowlisted key in the
// same request is still dropped.
func TestPatchMe_AllowlistedAttributeApplied(t *testing.T) {
	issuer := defaultimpl.NewEd25519JWTIssuer(
		defaultimpl.WithEd25519Issuer("me-patch-test"),
		defaultimpl.WithEd25519TokenTTL(5*time.Minute),
	)
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "me-app", Secret: "shh", Name: "Me App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	server := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithSelfEditableProfileAttributes("locale"),
	)
	hs := httptest.NewServer(server.Handler())
	defer hs.Close()

	lb, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": "me-app",
		"credential": map[string]string{"username": "alice", "password": "pw"},
	})
	lr, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(lb))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	var lout map[string]any
	_ = json.NewDecoder(lr.Body).Decode(&lout)
	_ = lr.Body.Close()
	token, _ := lout["access_token"].(string)
	if token == "" {
		t.Fatalf("login: no token: %v", lout)
	}

	status, _ := patchMe(t, hs.URL, token, map[string]any{
		"attributes": map[string]string{"locale": "fr-FR", "role": "admin"},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	_, got := getMe(t, hs.URL, token)
	gu, _ := got["user"].(map[string]any)
	attrs, _ := gu["attributes"].(map[string]any)
	if attrs["locale"] != "fr-FR" {
		t.Errorf("allowlisted 'locale' not applied: %v", attrs)
	}
	if _, leaked := attrs["role"]; leaked {
		t.Errorf("non-allowlisted 'role' leaked through allowlist: %v", attrs)
	}
}
