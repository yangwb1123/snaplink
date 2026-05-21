package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/defaultimpl"
)

func TestBuildWebAuthnHelper_Disabled(t *testing.T) {
	h, err := buildWebAuthnHelper(config.WebAuthnConfig{}, quietLogger())
	if err != nil {
		t.Fatalf("buildWebAuthnHelper disabled: %v", err)
	}
	if h != nil {
		t.Fatal("disabled config must return nil helper")
	}
}

func TestBuildWebAuthnHelper_RequiresRPID(t *testing.T) {
	_, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPOrigins: []string{"https://sso.example.com"},
	}, quietLogger())
	if err == nil {
		t.Fatal("missing rp_id must error")
	}
}

func TestBuildWebAuthnHelper_RequiresAtLeastOneOrigin(t *testing.T) {
	_, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled: true,
		RPID:    "example.com",
	}, quietLogger())
	if err == nil {
		t.Fatal("missing rp_origins must error")
	}
}

func TestBuildWebAuthnHelper_DefaultsMemoryBackends(t *testing.T) {
	h, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
	}, quietLogger())
	if err != nil {
		t.Fatalf("buildWebAuthnHelper: %v", err)
	}
	if h == nil {
		t.Fatal("helper nil when subsystem enabled")
	}
}

func TestBuildWebAuthnUserStore_SQLiteRequiresDSN(t *testing.T) {
	_, _, err := buildWebAuthnUserStore(config.WebAuthnBackendConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("sqlite backend without dsn must error")
	}
}

func TestBuildWebAuthnSessionStore_SQLiteRequiresDSN(t *testing.T) {
	_, _, err := buildWebAuthnSessionStore(config.WebAuthnBackendConfig{Backend: "sqlite"})
	if err == nil {
		t.Fatal("sqlite backend without dsn must error")
	}
}

func TestBuildWebAuthnUserStore_UnknownBackend(t *testing.T) {
	_, _, err := buildWebAuthnUserStore(config.WebAuthnBackendConfig{Backend: "redis"})
	if err == nil {
		t.Fatal("unknown backend must error")
	}
}

func TestBuildWebAuthnHelper_SQLiteBackends(t *testing.T) {
	dir := t.TempDir()
	h, err := buildWebAuthnHelper(config.WebAuthnConfig{
		Enabled:   true,
		RPID:      "example.com",
		RPOrigins: []string{"https://sso.example.com"},
		Storage: config.WebAuthnStorageConfig{
			Users:    config.WebAuthnBackendConfig{Backend: "sqlite", SQLite: config.WebAuthnBackendSQLiteConfig{DSN: "file:" + filepath.Join(dir, "users.db") + "?_journal=WAL"}},
			Sessions: config.WebAuthnBackendConfig{Backend: "sqlite", SQLite: config.WebAuthnBackendSQLiteConfig{DSN: "file:" + filepath.Join(dir, "sessions.db") + "?_journal=WAL"}},
		},
	}, quietLogger())
	if err != nil {
		t.Fatalf("buildWebAuthnHelper sqlite: %v", err)
	}
	if h == nil {
		t.Fatal("helper nil with sqlite backends")
	}
}

// ----- HTTP wrapper tests -----

func newWebAuthnTestServer(t *testing.T) (*httptest.Server, *webauthn.Helper) {
	t.Helper()
	h, err := webauthn.NewHelper(webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "Example AS",
		RPOrigins:     []string{"https://sso.example.com"},
		SessionTTL:    time.Minute,
	}, webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("NewHelper: %v", err)
	}
	srv := sso.NewServer(
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(defaultimpl.NewMemoryClientStore()),
	)
	httpHandler := srv.Handler()
	if err := mountWebAuthnRoutes(srv, h); err != nil {
		t.Fatalf("mountWebAuthnRoutes: %v", err)
	}
	ts := httptest.NewServer(httpHandler)
	t.Cleanup(ts.Close)
	return ts, h
}

func TestWebAuthnHTTP_BeginRegistrationReturnsOptionsAndSession(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: "alice@example.com", DisplayName: "Alice"})
	resp, err := http.Post(ts.URL+pathWebAuthnRegistrationBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d want 200", resp.StatusCode)
	}
	var got webauthnBeginRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.SessionID == "" {
		t.Fatal("empty session_id")
	}
	if len(got.Options) == 0 {
		t.Fatal("empty options")
	}
	if !strings.Contains(string(got.Options), "challenge") {
		t.Fatalf("options missing challenge: %s", got.Options)
	}
}

func TestWebAuthnHTTP_BeginRequiresUsername(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: ""})
	resp, err := http.Post(ts.URL+pathWebAuthnRegistrationBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestWebAuthnHTTP_BeginRejectsEmptyBody(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	resp, err := http.Post(ts.URL+pathWebAuthnRegistrationBegin, "application/json", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestWebAuthnHTTP_FinishRequiresSessionID(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	resp, err := http.Post(ts.URL+pathWebAuthnRegistrationFinish, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status %d want 400", resp.StatusCode)
	}
}

func TestWebAuthnHTTP_FinishUnknownSessionReturns404(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	resp, err := http.Post(ts.URL+pathWebAuthnRegistrationFinish+"?session_id=ghost", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d want 404 (oracle-leak resistance)", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["error"] != "session_invalid" {
		t.Fatalf("error: got %q want session_invalid", got["error"])
	}
}

func TestWebAuthnHTTP_BeginLoginUnknownUserReturns404(t *testing.T) {
	// Unknown username folds into the same 404 session_invalid envelope
	// as bad session_id so a probe can't enumerate registered users.
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: "ghost@example.com"})
	resp, err := http.Post(ts.URL+pathWebAuthnLoginBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status %d want 404", resp.StatusCode)
	}
	var got map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&got)
	if got["error"] != "session_invalid" {
		t.Fatalf("error: got %q want session_invalid", got["error"])
	}
}

func TestWebAuthnHTTP_AllRoutesCacheControlNoStore(t *testing.T) {
	ts, _ := newWebAuthnTestServer(t)
	body, _ := json.Marshal(webauthnBeginRequest{Username: "alice"})
	resp, err := http.Post(ts.URL+pathWebAuthnRegistrationBegin, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control: got %q want no-store (credential endpoint)", got)
	}
}

// Sanity: confirm the error mapping respects the sentinel set.
func TestWebAuthnErrorStatus_Mapping(t *testing.T) {
	cases := []struct {
		in           error
		wantStatus   int
		wantErrorTag string
	}{
		{webauthn.ErrSessionUnknown, http.StatusNotFound, "session_invalid"},
		{webauthn.ErrSessionExpired, http.StatusNotFound, "session_invalid"},
		{webauthn.ErrUserUnknown, http.StatusNotFound, "session_invalid"},
		{errors.New("generic ceremony parse fail"), http.StatusBadRequest, "ceremony_failed"},
	}
	for _, tc := range cases {
		gotStatus, gotErr := webauthnErrorStatus(tc.in)
		if gotStatus != tc.wantStatus || gotErr != tc.wantErrorTag {
			t.Errorf("webauthnErrorStatus(%v) = (%d, %q), want (%d, %q)",
				tc.in, gotStatus, gotErr, tc.wantStatus, tc.wantErrorTag)
		}
	}
}
