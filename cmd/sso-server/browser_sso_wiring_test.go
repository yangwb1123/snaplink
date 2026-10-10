package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

func TestBuildApp_BrowserSSOStockWiring(t *testing.T) {
	for _, alg := range []string{"eddsa", "es256", "rs256", "ps256"} {
		t.Run(alg, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Server.Issuer = "https://sso.example.test"
			cfg.Keys.Signing.Alg = alg
			cfg.OAuth.AuthCode.Enabled = true
			cfg.OIDC.BrowserSSO.Enabled = true
			cfg.Identity.Backend = "sqlite"
			cfg.Identity.SQLite.DSN = "file:" + filepath.Join(t.TempDir(), "identity.db")
			cfg.Authenticators.Password = &config.PasswordConfig{Enabled: true, Users: []config.PasswordUserConfig{{Username: "alice", SubjectID: "alice", BcryptHashFile: writeBcryptHashFile(t, "fixture-password")}}}
			for _, id := range []string{"rp-a", "rp-b"} {
				cfg.Clients = append(cfg.Clients, config.ClientConfig{ID: id, Active: true, SkipConsent: true, TokenStrategy: "jwt", AllowedAuthenticators: []string{"password"}, AllowedScopes: []string{"openid"}, RedirectURIs: []string{"https://" + id + ".example/callback"}})
			}
			a, err := buildApp(cfg, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { shutdownApp(t, a) })
			handler, err := buildHTTPHandler(cfg, a, quietLogger())
			if err != nil {
				t.Fatal(err)
			}
			first := stockBrowserSSORequest(t, handler, map[string]any{"client_id": "rp-a", "response_type": "code", "redirect_uri": "https://rp-a.example/callback", "scope": []string{"openid"}, "provider": "password", "credential": map[string]string{"username": "alice", "password": "fixture-password"}}, nil)
			if first.Code != 200 {
				t.Fatalf("stock first login status=%d", first.Code)
			}
			cookies := first.Result().Cookies()
			if len(cookies) != 1 || !cookies[0].HttpOnly || !cookies[0].Secure || cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].Domain != "" {
				t.Fatal("stock OP cookie not secure and host-only")
			}
			second := stockBrowserSSORequest(t, handler, map[string]any{"client_id": "rp-b", "response_type": "code", "redirect_uri": "https://rp-b.example/callback", "scope": []string{"openid"}, "resume_session": true}, cookies[0])
			var result map[string]any
			json.Unmarshal(second.Body.Bytes(), &result)
			if second.Code != 200 || result["code"] == nil || second.Header().Get("Set-Cookie") != "" {
				t.Fatalf("stock second RP failed: status=%d error=%v", second.Code, result["error"])
			}
			if _, err := a.server.ValidateToken(t.Context(), cookies[0].Value); err == nil {
				t.Fatal("stock OP cookie accepted as bearer")
			}
		})
	}
}

func stockBrowserSSORequest(t *testing.T, handler http.Handler, body map[string]any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestBuildApp_BrowserSSODefaultOff(t *testing.T) {
	cfg := &config.Config{}
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shutdownApp(t, a) })
	rec := stockBrowserSSORequest(t, a.server.Handler(), map[string]any{"client_id": "any"}, nil)
	if strings.Contains(rec.Body.String(), "op_session_supported") || rec.Header().Get("Set-Cookie") != "" {
		t.Fatal("stock default-off changed wire")
	}
}
