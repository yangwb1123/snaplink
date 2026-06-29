package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/interfaces/sso"
)

func okNext() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func gateConfig() *Config {
	return &Config{ResourceURI: "https://mcp/", RequiredScope: "mcp:read", Issuer: "https://sso"}
}

func TestRSGate_AllowsValidToken(t *testing.T) {
	iss := edIssuer()
	gate := newRSGate(jwksAuthClient(t, iss), gateConfig(), okNext())
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "agent-1", Resources: []string{"https://mcp/"}}, []string{"mcp:read"})

	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("valid token: code = %d, want 200", w.Code)
	}
}

func TestRSGate_RejectsMissingWrongAudWrongScope(t *testing.T) {
	iss := edIssuer()
	cfg := gateConfig()
	gate := newRSGate(jwksAuthClient(t, iss), cfg, okNext())

	// missing token
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if w.Code != http.StatusUnauthorized || !strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata=") {
		t.Fatalf("missing: code=%d hdr=%q", w.Code, w.Header().Get("WWW-Authenticate"))
	}

	// wrong aud
	bad, _ := iss.Issue(context.Background(), &sso.Subject{ID: "a", Resources: []string{"https://other/"}}, []string{"mcp:read"})
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+bad.AccessToken)
	gate.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong aud: code=%d, want 401", w.Code)
	}

	// insufficient scope
	noscope, _ := iss.Issue(context.Background(), &sso.Subject{ID: "a", Resources: []string{"https://mcp/"}}, []string{"other"})
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer "+noscope.AccessToken)
	gate.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("no scope: code=%d, want 401", w.Code)
	}
}

func TestPRMHandler(t *testing.T) {
	w := httptest.NewRecorder()
	prmHandler(gateConfig())(w, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil))
	body := w.Body.String()
	if !strings.Contains(body, `"https://sso"`) || !strings.Contains(body, `"https://mcp/"`) {
		t.Fatalf("PRM body missing fields: %s", body)
	}
}

func TestLivez(t *testing.T) {
	w := httptest.NewRecorder()
	livezHandler()(w, httptest.NewRequest(http.MethodGet, "/livez", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "alive") {
		t.Fatalf("livez: code=%d body=%s", w.Code, w.Body.String())
	}
}
