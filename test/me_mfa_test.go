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

const mfaUserID = "u-mfa-alice"

func newMeMFAHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemoryMFAEnrollmentStore, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: mfaUserID})

	enroll := defaultimpl.NewMemoryMFAEnrollmentStore()
	enroll.AddFactor(mfaUserID, sso.MFAEnrolledFactor{ID: "totp-1", Method: "totp", Label: "Authenticator app", AddedAt: time.Unix(1700000000, 0)})
	enroll.AddFactor(mfaUserID, sso.MFAEnrolledFactor{ID: "wa-1", Method: "webauthn", Label: "YubiKey"})

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "mfa-app", Secret: "s", Name: "MFA App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: mfaUserID}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithMFAEnrollmentStore(enroll),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "mfa-app",
			"credential": map[string]string{"username": "alice", "password": "x"},
		})
		resp, err := http.Post(hs.URL+"/auth/login", "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("login: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		tok, _ := out["access_token"].(string)
		if tok == "" {
			t.Fatalf("no token: %s", raw)
		}
		return tok
	}
	return hs, enroll, loginAs
}

func doMe(t *testing.T, method, url, token string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func TestMyMFA_ListsFactors(t *testing.T) {
	srv, _, loginAs := newMeMFAHarness(t)
	status, body := doMe(t, http.MethodGet, srv.URL+"/me/mfa", loginAs())
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	factors, _ := body["factors"].([]any)
	if len(factors) != 2 {
		t.Errorf("factors len=%d, want 2: %v", len(factors), body)
	}
}

func TestMyMFA_UnbindOwnFactor(t *testing.T) {
	srv, enroll, loginAs := newMeMFAHarness(t)
	token := loginAs()
	if status, _ := doMe(t, http.MethodDelete, srv.URL+"/me/mfa/totp-1", token); status != http.StatusNoContent {
		t.Fatalf("delete status=%d, want 204", status)
	}
	left, _ := enroll.ListFactors(context.Background(), mfaUserID)
	if len(left) != 1 || left[0].ID != "wa-1" {
		t.Errorf("after unbind, factors=%v, want only wa-1", left)
	}
}

func TestMyMFA_UnbindUnknownIs404(t *testing.T) {
	srv, _, loginAs := newMeMFAHarness(t)
	if status, _ := doMe(t, http.MethodDelete, srv.URL+"/me/mfa/does-not-exist", loginAs()); status != http.StatusNotFound {
		t.Errorf("status=%d, want 404 for unknown factor", status)
	}
}

func TestMyMFA_RequiresBearer(t *testing.T) {
	srv, _, _ := newMeMFAHarness(t)
	if status, _ := doMe(t, http.MethodGet, srv.URL+"/me/mfa", ""); status != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401 without bearer", status)
	}
}

func TestMyMFA_NotMountedWithoutStore(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	if status, _ := doMe(t, http.MethodGet, srv.URL+"/me/mfa", loginAs("alice")); status != http.StatusNotFound {
		t.Errorf("status=%d, want 404 without an enrollment store", status)
	}
}
