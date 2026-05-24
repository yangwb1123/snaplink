package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	fpUserID   = "u-formpost"
	fpClientID = "fp-client"
	fpSecret   = "fp-secret"
	fpPassword = "pw"
	fpRedirect = "https://app.example/cb"
)

func newFormPostHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: fpUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: fpClientID, Secret: fpSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{fpRedirect},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != fpPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: fpUserID, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), 5*time.Minute),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestFormPost_RendersAutoSubmitHTML(t *testing.T) {
	srv := newFormPostHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     fpClientID,
		"credential":    map[string]string{"username": fpUserID, "password": fpPassword},
		"response_type": "code",
		"redirect_uri":  fpRedirect,
		"state":         "xyz-state",
		"response_mode": "form_post",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	if xf := resp.Header.Get("X-Frame-Options"); xf != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", xf)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	raw, _ := io.ReadAll(resp.Body)
	html := string(raw)
	if !strings.Contains(html, `method="POST"`) {
		t.Errorf("HTML missing method=\"POST\": %s", html)
	}
	if !strings.Contains(html, `action="`+fpRedirect+`"`) {
		t.Errorf("HTML missing form action targeting redirect_uri: %s", html)
	}
	if !strings.Contains(html, `name="code"`) {
		t.Errorf("HTML missing code field: %s", html)
	}
	if !strings.Contains(html, `value="xyz-state"`) {
		t.Errorf("HTML missing state field: %s", html)
	}
	if !strings.Contains(html, `name="iss"`) {
		t.Errorf("HTML missing iss field: %s", html)
	}
}

func TestFormPost_HTMLEscapesUntrustedState(t *testing.T) {
	// The state is RP-controlled — an attacker who controls part
	// of the state value MUST NOT be able to break out of the
	// attribute context and inject script. html/template's
	// auto-escaping handles this; the test just verifies the
	// escaping is actually present in the wire response.
	srv := newFormPostHarness(t)
	const evil = `"><script>alert(1)</script>`
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     fpClientID,
		"credential":    map[string]string{"username": fpUserID, "password": fpPassword},
		"response_type": "code",
		"redirect_uri":  fpRedirect,
		"state":         evil,
		"response_mode": "form_post",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if bytes.Contains(raw, []byte("<script>alert(1)</script>")) {
		t.Errorf("untrusted state rendered without escaping: %s", raw)
	}
}

func TestFormPost_RejectsUnknownResponseMode(t *testing.T) {
	srv := newFormPostHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     fpClientID,
		"credential":    map[string]string{"username": fpUserID, "password": fpPassword},
		"response_type": "code",
		"redirect_uri":  fpRedirect,
		"response_mode": "nonsense_mode",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["error"] != sso.ErrInvalidRequest {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidRequest)
	}
}

func TestFormPost_EmptyResponseModeFallsThroughToJSON(t *testing.T) {
	// Backward compat: no response_mode → JSON body with code/iss/state.
	srv := newFormPostHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":      "password",
		"client_id":     fpClientID,
		"credential":    map[string]string{"username": fpUserID, "password": fpPassword},
		"response_type": "code",
		"redirect_uri":  fpRedirect,
		"state":         "legacy",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q want json (legacy fallback)", ct)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["code"] == nil {
		t.Errorf("JSON response missing code: %v", out)
	}
}

func TestFormPost_DiscoveryAdvertisesResponseModes(t *testing.T) {
	srv := newFormPostHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	modes, _ := doc["response_modes_supported"].([]any)
	if len(modes) == 0 {
		t.Fatalf("response_modes_supported missing from discovery: %v", doc)
	}
	found := false
	for _, m := range modes {
		if m == "form_post" {
			found = true
		}
	}
	if !found {
		t.Errorf("response_modes_supported = %v, want to contain form_post", modes)
	}
}
