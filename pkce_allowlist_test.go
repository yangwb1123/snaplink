package sso_test

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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	pkceAllowUserID   = "u-pkce"
	pkceAllowClientID = "pkce-client"
	pkceAllowSecret   = "pkce-secret"
	pkceAllowPassword = "pw"
	pkceAllowRedirect = "https://app.example/cb"
	// 43-byte minimum challenge per RFC 7636.
	pkceAllowChallenge = "0123456789012345678901234567890123456789012"
)

func newPKCEAllowlistHarness(t *testing.T, allowed []string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: pkceAllowUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: pkceAllowClientID, Secret: pkceAllowSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{pkceAllowRedirect},
		AllowedPKCEMethods:    allowed,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != pkceAllowPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: pkceAllowUserID, Provider: "password"}, nil
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

func attemptPKCELogin(t *testing.T, srv *httptest.Server, method string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":              "password",
		"client_id":             pkceAllowClientID,
		"credential":            map[string]string{"username": pkceAllowUserID, "password": pkceAllowPassword},
		"response_type":         "code",
		"redirect_uri":          pkceAllowRedirect,
		"code_challenge":        pkceAllowChallenge,
		"code_challenge_method": method,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

func TestPKCEAllowlist_OnlyS256AcceptsS256(t *testing.T) {
	srv := newPKCEAllowlistHarness(t, []string{sso.PKCEMethodS256})
	status, body := attemptPKCELogin(t, srv, sso.PKCEMethodS256)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["code"] == nil {
		t.Errorf("no code in success response: %v", body)
	}
}

func TestPKCEAllowlist_OnlyS256RejectsPlain(t *testing.T) {
	srv := newPKCEAllowlistHarness(t, []string{sso.PKCEMethodS256})
	status, body := attemptPKCELogin(t, srv, sso.PKCEMethodPlain)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400", status, body)
	}
	if body["error"] != sso.ErrInvalidPKCEMethod {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidPKCEMethod)
	}
}

func TestPKCEAllowlist_EmptyAcceptsBoth(t *testing.T) {
	// Legacy default: no allowlist → both methods accepted (the
	// RFC keeps "plain" valid for older clients).
	srv := newPKCEAllowlistHarness(t, nil)
	for _, m := range []string{sso.PKCEMethodPlain, sso.PKCEMethodS256} {
		status, body := attemptPKCELogin(t, srv, m)
		if status != http.StatusOK {
			t.Errorf("method %q: status=%d body=%v want 200", m, status, body)
		}
	}
}

func TestPKCEAllowlist_DefaultedMethodCheckedAgainstAllowlist(t *testing.T) {
	// Caller omits code_challenge_method → server defaults to
	// "plain" — that default MUST itself pass the allowlist. So
	// a client with AllowedPKCEMethods=["S256"] rejects an
	// empty method (because plain isn't allowed).
	srv := newPKCEAllowlistHarness(t, []string{sso.PKCEMethodS256})
	status, body := attemptPKCELogin(t, srv, "")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v want 400 (empty method defaults to plain, not allowed)", status, body)
	}
	if body["error"] != sso.ErrInvalidPKCEMethod {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidPKCEMethod)
	}
}
