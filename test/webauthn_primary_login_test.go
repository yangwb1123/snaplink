package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

const (
	wapUserID   = "u-wap"
	wapClientID = "wap-client"
	wapSecret   = "wap-secret"
	wapPassword = "pw"
	wapRedirect = "https://app.example/cb"
	wapPWOnlyID = "wap-pwonly-client"
)

// newWebAuthnPrimaryHarness wires a server with BOTH the password
// authenticator AND the WebAuthnPrimaryAuthenticator registered side by side
// — proving the passkey-primary path is purely ADDITIVE (AGENTS.md: "when
// false, this is purely additive... changing nothing for existing flows").
// wapClientID has AllowPasswordlessOnly set; wapPWOnlyID does not (the
// regression / no-op control).
func newWebAuthnPrimaryHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: wapUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: wapClientID, Secret: wapSecret, Active: true,
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{wapRedirect},
		AllowPasswordlessOnly: true, // password refused; webauthn still reachable
	})
	clients.AddSeed(&sso.Client{
		ID: wapPWOnlyID, Secret: wapSecret, Active: true,
		TokenStrategy: "jwt",
		RedirectURIs:  []string{wapRedirect},
		// no AllowPasswordlessOnly — existing password-only flow untouched
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != wapPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: wapUserID, Provider: "password"}, nil
		},
	))
	helper, err := webauthn.NewHelper(webauthn.Config{
		RPID:       "example.com",
		RPOrigins:  []string{"https://sso.example.com"},
		SessionTTL: time.Minute,
	}, webauthn.NewMemoryUserStore(), webauthn.NewMemorySessionStore())
	if err != nil {
		t.Fatalf("webauthn.NewHelper: %v", err)
	}
	primaryAuth, err := webauthn.NewWebAuthnPrimaryAuthenticator(helper)
	if err != nil {
		t.Fatalf("NewWebAuthnPrimaryAuthenticator: %v", err)
	}
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithAuthenticator(primaryAuth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func postLoginJSON(t *testing.T, srv *httptest.Server, body map[string]any) (*http.Response, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	return resp, out
}

// TestAllowPasswordlessOnly_RejectsPasswordProvider proves the new client
// flag refuses password login (400 passwordless_required) BEFORE any
// credential is read — a policy gate, not a credential oracle.
func TestAllowPasswordlessOnly_RejectsPasswordProvider(t *testing.T) {
	srv := newWebAuthnPrimaryHarness(t)
	resp, out := postLoginJSON(t, srv, map[string]any{
		"provider":   "password",
		"client_id":  wapClientID,
		"credential": map[string]string{"username": wapUserID, "password": wapPassword},
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, out)
	}
	if out["error"] != core.ErrPasswordlessRequired {
		t.Errorf("error=%v want %q", out["error"], core.ErrPasswordlessRequired)
	}
}

// TestAllowPasswordlessOnly_DoesNotBlockWebAuthnProvider proves the flag is
// narrowly scoped to "password" — the SAME client reaches the webauthn
// primary authenticator for provider=webauthn (observed here as 404
// session_invalid for a deliberately bogus session, NOT 400
// passwordless_required — proof dispatch reached Authenticate rather than
// being rejected by the passwordless gate).
func TestAllowPasswordlessOnly_DoesNotBlockWebAuthnProvider(t *testing.T) {
	srv := newWebAuthnPrimaryHarness(t)
	resp, out := postLoginJSON(t, srv, map[string]any{
		"provider":   "webauthn",
		"client_id":  wapClientID,
		"credential": map[string]string{"session_id": "ghost-session", "assertion": "{}"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%v", resp.StatusCode, out)
	}
	if out["error"] != core.ErrSessionInvalid {
		t.Errorf("error=%v want %q", out["error"], core.ErrSessionInvalid)
	}
}

// TestAllowPasswordlessOnly_DefaultFalseIsNoOp is the regression control: a
// client WITHOUT the flag keeps the existing password-only flow working
// exactly as before — additive means zero behavior change when unset.
func TestAllowPasswordlessOnly_DefaultFalseIsNoOp(t *testing.T) {
	srv := newWebAuthnPrimaryHarness(t)
	resp, out := postLoginJSON(t, srv, map[string]any{
		"provider":   "password",
		"client_id":  wapPWOnlyID,
		"credential": map[string]string{"username": wapUserID, "password": wapPassword},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, out)
	}
}

// TestWebAuthnPrimary_UnknownSessionOracleSafe404 is the anti-enumeration
// invariant from AGENTS.md §3: a WebAuthn PRIMARY attempt with an
// unknown/expired ceremony session collapses to the SAME 404
// session_invalid the existing second-factor / standalone ceremony
// endpoints use — reached this time through the generic /auth/login
// pipeline instead of a dedicated ceremony endpoint.
func TestWebAuthnPrimary_UnknownSessionOracleSafe404(t *testing.T) {
	srv := newWebAuthnPrimaryHarness(t)
	resp, out := postLoginJSON(t, srv, map[string]any{
		"provider":   "webauthn",
		"client_id":  wapPWOnlyID,
		"credential": map[string]string{"session_id": "totally-unknown", "assertion": "{}"},
	})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status=%d want 404 body=%v", resp.StatusCode, out)
	}
	if out["error"] != "session_invalid" {
		t.Errorf("error=%v want session_invalid", out["error"])
	}
}

// TestWebAuthnPrimary_MissingCredentialFieldsCollapsesToGenericInvalid proves
// a plain malformed request (no session/assertion at all — nothing ceremony-
// stateful to distinguish) does NOT get the 404 session_invalid treatment;
// it falls through to the ordinary invalid_credentials collapse like any
// other authenticator's bad-input case.
func TestWebAuthnPrimary_MissingCredentialFieldsCollapsesToGenericInvalid(t *testing.T) {
	srv := newWebAuthnPrimaryHarness(t)
	resp, out := postLoginJSON(t, srv, map[string]any{
		"provider":   "webauthn",
		"client_id":  wapPWOnlyID,
		"credential": map[string]string{},
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, out)
	}
	if out["error"] != sso.ErrInvalidCredentials {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidCredentials)
	}
}
