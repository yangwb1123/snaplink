package sso_test

// rootcov_session_management_test.go exercises OpenID Connect Session
// Management 1.0 end-to-end over httptest: the /auth/login session_state +
// browser-state cookie, GET /check_session_iframe, /end_session clearing the
// cookie, and the discovery document's check_session_iframe field — plus the
// byte-identical-when-off contract (the default build, no
// WithOIDCSessionManagement, must show none of this). Reuses the rcov*
// harness from rootcov_flow_test.go.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

func TestRcovSessionMgmt_LoginStampsSessionStateAndCookie(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithOIDCSessionManagement())

	req, err := http.NewRequest(http.MethodPost, s.http.URL+"/auth/login", strings.NewReader(
		`{"provider":"password","client_id":"`+rcovClient+`","credential":{"username":"`+rcovUsername+`","password":"`+rcovPassword+`"},"scope":["openid"],"redirect_uri":"`+rcovRedirect+`"}`,
	))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d", resp.StatusCode)
	}

	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	state, _ := out["session_state"].(string)
	if state == "" {
		t.Fatalf("login response missing session_state: %v", out)
	}
	if !strings.Contains(state, ".") {
		t.Fatalf("session_state %q missing salt suffix", state)
	}

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "op_browser_state" {
			cookie = c
			break
		}
	}
	if cookie == nil {
		t.Fatalf("no op_browser_state cookie set; headers=%v", resp.Header)
	}
	if cookie.Value == "" {
		t.Errorf("op_browser_state cookie has empty value")
	}
	if cookie.Path != "/check_session_iframe" {
		t.Errorf("op_browser_state cookie Path = %q, want /check_session_iframe (scoped so it's not sent elsewhere)", cookie.Path)
	}
}

func TestRcovSessionMgmt_CheckSessionIframeServedWhenEnabled(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithOIDCSessionManagement())

	resp, err := http.Get(s.http.URL + "/check_session_iframe")
	if err != nil {
		t.Fatalf("GET check_session_iframe: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	// The whole point is that it must be embeddable by an arbitrary RP.
	if xfo := resp.Header.Get("X-Frame-Options"); xfo != "" {
		t.Errorf("X-Frame-Options = %q, want unset", xfo)
	}

	var doc map[string]any
	rcovGetJSON(t, s.http.URL+"/.well-known/openid-configuration", &doc)
	if doc["check_session_iframe"] != s.http.URL+"/check_session_iframe" {
		t.Errorf("discovery check_session_iframe = %v, want %s/check_session_iframe", doc["check_session_iframe"], s.http.URL)
	}
}

func TestRcovSessionMgmt_EndSessionClearsCookie(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t, sso.WithOIDCSessionManagement())

	resp, err := http.Get(s.http.URL + "/end_session")
	if err != nil {
		t.Fatalf("GET end_session: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var cleared *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "op_browser_state" {
			cleared = c
			break
		}
	}
	if cleared == nil {
		t.Fatalf("end_session did not clear the op_browser_state cookie")
	}
	if cleared.MaxAge >= 0 && cleared.Value != "" {
		t.Errorf("cleared cookie MaxAge=%d value=%q, want expired/empty", cleared.MaxAge, cleared.Value)
	}
}

// TestRcovSessionMgmt_OffByDefault proves the feature is byte-identical when
// WithOIDCSessionManagement is never called: no session_state, no cookie, no
// discovery field, and the iframe route 404s.
func TestRcovSessionMgmt_OffByDefault(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)

	status, out := rcovPostJSON(t, s.http.URL+"/auth/login", "", map[string]any{
		"provider":   "password",
		"client_id":  rcovClient,
		"credential": map[string]string{"username": rcovUsername, "password": rcovPassword},
		"scope":      []string{"openid"},
	})
	if status != http.StatusOK {
		t.Fatalf("login status=%d body=%v", status, out)
	}
	if _, ok := out["session_state"]; ok {
		t.Errorf("session_state present without WithOIDCSessionManagement: %v", out)
	}

	resp, err := http.Get(s.http.URL + "/check_session_iframe")
	if err != nil {
		t.Fatalf("GET check_session_iframe: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("check_session_iframe status=%d, want 404 (route unmounted when the feature is off)", resp.StatusCode)
	}

	var doc map[string]any
	rcovGetJSON(t, s.http.URL+"/.well-known/openid-configuration", &doc)
	if _, ok := doc["check_session_iframe"]; ok {
		t.Errorf("discovery advertises check_session_iframe without WithOIDCSessionManagement: %v", doc["check_session_iframe"])
	}
}
