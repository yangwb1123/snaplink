package ssotest

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
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
