package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gw "github.com/go-webauthn/webauthn/webauthn"
	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/authenticators/webauthn"
	"github.com/snaplink/sso/defaultimpl"
)

// newCompositeMFAHarness wires a server whose /me/mfa store composes a TOTP
// store and a WebAuthn-passkey adapter, mirroring the stock binary. It seeds a
// passkey (credID) for u-alice and returns a login helper.
func newCompositeMFAHarness(t *testing.T, credID string) (*httptest.Server, func() string) {
	t.Helper()
	ctx := context.Background()

	totp := defaultimpl.NewMemoryTOTPEnrollmentStore()
	waUsers := webauthn.NewMemoryUserStore()
	if _, err := waUsers.CreateUser(ctx, "u-alice", "Alice"); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := waUsers.AddCredential(ctx, "u-alice", &gw.Credential{ID: []byte(credID)}); err != nil {
		t.Fatalf("AddCredential: %v", err)
	}
	composite := defaultimpl.NewCompositeMFAEnrollmentStore(
		totp,
		defaultimpl.NewWebAuthnMFAEnrollmentAdapter(waUsers),
	)

	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(ctx, &sso.User{ID: "u-alice"})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "mfa-app", Secret: "s", Name: "MFA App",
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
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5*time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithMFAEnrollmentStore(composite),
		sso.WithTOTPEnroller(authenticators.NewTOTPEnroller(authenticators.NewTOTPAuthenticator(totp))),
	)
	hs := httptest.NewServer(server.Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "mfa-app",
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

// TestMyMFA_WebAuthnPasskeyListedAndUnbound proves a registered passkey appears
// in GET /me/mfa as a webauthn factor and unbinds via DELETE /me/mfa/:id.
func TestMyMFA_WebAuthnPasskeyListedAndUnbound(t *testing.T) {
	credID := "passkey-cred-1"
	srv, loginAs := newCompositeMFAHarness(t, credID)
	tok := loginAs()

	code, body := doReq(t, srv, http.MethodGet, "/me/mfa", tok)
	if code != http.StatusOK {
		t.Fatalf("list status=%d body=%v", code, body)
	}
	factors, _ := body["factors"].([]any)
	if len(factors) != 1 {
		t.Fatalf("want 1 passkey factor, got %v", body)
	}
	f0, _ := factors[0].(map[string]any)
	if f0["method"] != "webauthn" {
		t.Errorf("factor method = %v, want webauthn", f0["method"])
	}
	wantID := base64.RawURLEncoding.EncodeToString([]byte(credID))
	if f0["id"] != wantID {
		t.Errorf("factor id = %v, want %s", f0["id"], wantID)
	}

	// Unbind the passkey.
	dc, _ := doReq(t, srv, http.MethodDelete, "/me/mfa/"+wantID, tok)
	if dc != http.StatusNoContent {
		t.Fatalf("delete status=%d", dc)
	}
	_, after := doReq(t, srv, http.MethodGet, "/me/mfa", tok)
	if fs, _ := after["factors"].([]any); len(fs) != 0 {
		t.Errorf("after unbind = %v, want empty", after)
	}
}

// TestMyMFA_CompositeKeepsTOTPEnrollMounted proves the composite forwards
// TOTPEnrollmentWriter so wrapping the TOTP store does NOT unmount the TOTP
// enrollment routes (the regression the composite was designed to avoid).
func TestMyMFA_CompositeKeepsTOTPEnrollMounted(t *testing.T) {
	srv, loginAs := newCompositeMFAHarness(t, "passkey-cred-2")
	tok := loginAs()
	code, body := totpPost(t, srv.URL+"/me/mfa/totp/begin", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("totp begin behind composite status=%d body=%v (route unmounted?)", code, body)
	}
	if s, _ := body["secret"].(string); s == "" {
		t.Errorf("totp begin returned no secret: %v", body)
	}
}
