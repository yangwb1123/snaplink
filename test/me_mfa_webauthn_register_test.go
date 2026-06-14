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
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/defaultimpl"
)

// newWebAuthnRegisterHarness wires a server with an authenticated self-service
// passkey registrar (a real ceremony Helper over memory stores) + a password
// login to obtain a bearer. withRegistrar=false omits the registrar (routes
// absent). Returns the server + a login helper.
func newWebAuthnRegisterHarness(t *testing.T, withRegistrar bool) (*httptest.Server, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: "u-alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "wa-app", Secret: "s", Name: "WA App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: "u-alice"}, nil
		},
	))
	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5*time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	}
	if withRegistrar {
		helper, err := webauthn.NewHelper(
			webauthn.Config{RPID: "localhost", RPDisplayName: "Test", RPOrigins: []string{"https://localhost"}, SessionTTL: time.Minute},
			webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore(),
		)
		if err != nil {
			t.Fatalf("NewHelper: %v", err)
		}
		opts = append(opts, sso.WithWebAuthnRegistrar(webauthn.NewRegistrar(helper)))
	}
	hs := httptest.NewServer(sso.NewServer(opts...).Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "wa-app",
			"credential": map[string]string{"username": "alice", "password": "pw"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("login: no token: %v", out)
		}
		return tok
	}
	return hs, loginAs
}

func waPost(t *testing.T, url, token string, body io.Reader) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, body)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	out := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestWebAuthnRegister_BeginReturnsOptions: begin returns a session id + the
// CredentialCreation options the browser feeds to navigator.credentials.create.
func TestWebAuthnRegister_BeginReturnsOptions(t *testing.T) {
	srv, loginAs := newWebAuthnRegisterHarness(t, true)
	code, body := waPost(t, srv.URL+"/me/mfa/webauthn/begin", loginAs(), nil)
	if code != http.StatusOK {
		t.Fatalf("begin status=%d body=%v", code, body)
	}
	if sid, _ := body["session_id"].(string); sid == "" {
		t.Errorf("begin returned no session_id: %v", body)
	}
	opts, _ := body["options"].(map[string]any)
	if _, ok := opts["publicKey"]; !ok {
		t.Errorf("begin options missing publicKey: %v", body["options"])
	}
}

func TestWebAuthnRegister_BeginRequiresBearer(t *testing.T) {
	srv, _ := newWebAuthnRegisterHarness(t, true)
	if code, _ := waPost(t, srv.URL+"/me/mfa/webauthn/begin", "", nil); code != http.StatusUnauthorized {
		t.Errorf("begin without bearer = %d, want 401", code)
	}
}

func TestWebAuthnRegister_FinishRequiresSessionID(t *testing.T) {
	srv, loginAs := newWebAuthnRegisterHarness(t, true)
	if code, _ := waPost(t, srv.URL+"/me/mfa/webauthn/finish", loginAs(), nil); code != http.StatusBadRequest {
		t.Errorf("finish without session_id = %d, want 400", code)
	}
}

// TestWebAuthnRegister_FinishBadSessionIsOracleSafe: an unknown session / bad
// attestation collapses to one webauthn_registration_failed (400).
func TestWebAuthnRegister_FinishBadSession(t *testing.T) {
	srv, loginAs := newWebAuthnRegisterHarness(t, true)
	code, body := waPost(t, srv.URL+"/me/mfa/webauthn/finish?session_id=nope", loginAs(), bytes.NewReader([]byte(`{}`)))
	if code != http.StatusBadRequest || body["error"] != "webauthn_registration_failed" {
		t.Fatalf("finish bad session = %d %v, want 400 webauthn_registration_failed", code, body)
	}
}

func TestWebAuthnRegister_NotMountedWithoutRegistrar(t *testing.T) {
	srv, loginAs := newWebAuthnRegisterHarness(t, false)
	if code, _ := waPost(t, srv.URL+"/me/mfa/webauthn/begin", loginAs(), nil); code != http.StatusNotFound {
		t.Errorf("begin without registrar = %d, want 404 (unmounted)", code)
	}
}
