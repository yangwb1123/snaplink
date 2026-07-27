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
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const pwUserID = "u-pw-alice"

// newMePasswordHarness wires a server with a password credential store
// (pre-seeded with pwUserID's password) and a login helper returning a bearer.
func newMePasswordHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemoryPasswordCredentialStore, func() string) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: pwUserID})

	creds := defaultimpl.NewMemoryPasswordCredentialStore()
	_ = creds.SetPassword(context.Background(), pwUserID, "old-password")

	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "pw-app", Secret: "s", Name: "PW App",
		AllowedAuthenticators: []string{authenticators.MethodPassword},
		TokenStrategy:         "jwt", Active: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: pwUserID}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPasswordCredentialStore(creds),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	loginAs := func() string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"provider": "password", "client_id": "pw-app",
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
			t.Fatalf("no access_token: %s", raw)
		}
		return tok
	}
	return hs, creds, loginAs
}

func postPassword(t *testing.T, baseURL, token, current, next string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"current_password": current, "new_password": next})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/me/password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /me/password: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestMyPassword_ChangeSucceeds verifies the happy path: correct current ->
// 204, and the new password takes effect (old stops working).
func TestMyPassword_ChangeSucceeds(t *testing.T) {
	srv, creds, loginAs := newMePasswordHarness(t)
	token := loginAs()

	if status := postPassword(t, srv.URL, token, "old-password", "new-password"); status != http.StatusNoContent {
		t.Fatalf("change status=%d, want 204", status)
	}
	// New password verifies; old no longer does.
	if err := creds.VerifyPassword(context.Background(), pwUserID, "new-password"); err != nil {
		t.Errorf("new password should verify: %v", err)
	}
	if err := creds.VerifyPassword(context.Background(), pwUserID, "old-password"); !errors.Is(err, sso.ErrPasswordMismatch) {
		t.Errorf("old password should no longer verify, got %v", err)
	}
}

// TestMyPassword_WrongCurrentRejected verifies a wrong current password is
// rejected and the stored password is unchanged.
func TestMyPassword_WrongCurrentRejected(t *testing.T) {
	srv, creds, loginAs := newMePasswordHarness(t)
	token := loginAs()

	if status := postPassword(t, srv.URL, token, "WRONG", "new-password"); status != http.StatusBadRequest {
		t.Fatalf("wrong-current status=%d, want 400", status)
	}
	// Original password still works (change did not apply).
	if err := creds.VerifyPassword(context.Background(), pwUserID, "old-password"); err != nil {
		t.Errorf("original password should still verify after rejected change: %v", err)
	}
}

// TestMyPassword_EmptyNewRejected verifies an empty new password is a 400.
func TestMyPassword_EmptyNewRejected(t *testing.T) {
	srv, _, loginAs := newMePasswordHarness(t)
	token := loginAs()
	if status := postPassword(t, srv.URL, token, "old-password", ""); status != http.StatusBadRequest {
		t.Errorf("empty-new status=%d, want 400", status)
	}
}

// TestMyPassword_RequiresBearer verifies an unauthenticated request is 401.
func TestMyPassword_RequiresBearer(t *testing.T) {
	srv, _, _ := newMePasswordHarness(t)
	if status := postPassword(t, srv.URL, "", "old-password", "new-password"); status != http.StatusUnauthorized {
		t.Errorf("no-bearer status=%d, want 401", status)
	}
}

// TestMyPassword_FormEncodedWorks verifies the endpoint accepts a
// form-urlencoded body (the §2 binder), not just JSON.
func TestMyPassword_FormEncodedWorks(t *testing.T) {
	srv, creds, loginAs := newMePasswordHarness(t)
	token := loginAs()

	form := "current_password=old-password&new_password=form-new"
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/me/password", bytes.NewReader([]byte(form)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("form POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("form-encoded change status=%d, want 204", resp.StatusCode)
	}
	if err := creds.VerifyPassword(context.Background(), pwUserID, "form-new"); err != nil {
		t.Errorf("form-set password should verify: %v", err)
	}
}

// TestMyPassword_EmptyCurrentRejected verifies an omitted/empty current
// password is rejected (never counts as proof of the current credential).
func TestMyPassword_EmptyCurrentRejected(t *testing.T) {
	srv, creds, loginAs := newMePasswordHarness(t)
	token := loginAs()
	if status := postPassword(t, srv.URL, token, "", "new-password"); status != http.StatusBadRequest {
		t.Fatalf("empty-current status=%d, want 400", status)
	}
	// Password unchanged.
	if err := creds.VerifyPassword(context.Background(), pwUserID, "old-password"); err != nil {
		t.Errorf("password should be unchanged after empty-current reject: %v", err)
	}
}

// TestMyPassword_NotMountedWithoutStore verifies the route is absent (404) when
// no password credential store is wired.
func TestMyPassword_NotMountedWithoutStore(t *testing.T) {
	srv, _, loginAs := newMeSessionsHarness(t)
	token := loginAs("alice")
	if status := postPassword(t, srv.URL, token, "a", "b"); status != http.StatusNotFound {
		t.Errorf("status=%d, want 404 without a password store", status)
	}
}
