package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	patternClientID = "fapi-static-pattern-client"
	patternUserID   = "fapi-pattern-user"
	patternUsername = "fapi-pattern-user"
	patternPassword = "pattern-password"
)

func TestRedirectURIPatternsAuthorizationGate(t *testing.T) {
	server := newPatternCodeFlowServer(t)
	goodStatus, good := postPatternLogin(t, server, "https://localhost:8443/test/R7bzpU0mqX8Rghe/callback")
	if goodStatus != http.StatusOK || good["code"] == nil {
		t.Fatalf("matching dynamic callback = %d %#v, want 200 with code", goodStatus, good)
	}

	badStatus, bad := postPatternLogin(t, server, "https://localhost:8443/test/a/b/callback")
	if badStatus != http.StatusBadRequest || bad["error"] != sso.ErrInvalidRedirectURI {
		t.Fatalf("cross-segment callback = %d %#v, want 400 invalid_redirect_uri", badStatus, bad)
	}
}

func newPatternCodeFlowServer(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: patternUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: patternClientID, Secret: "pattern-secret", Active: true,
		RedirectURIPatterns:   []string{"https://localhost:8443/test/*/callback"},
		AllowedAuthenticators: []string{"password"}, TokenStrategy: "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, username, password string) (*sso.AuthResult, error) {
			if username == patternUsername && password == patternPassword {
				return &sso.AuthResult{UserID: patternUserID}, nil
			}
			return nil, errors.New("bad credentials")
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users), sso.WithClientStore(clients), sso.WithAuthenticator(pw),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"), sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
	)
	httpServer := httptest.NewServer(srv.Handler())
	t.Cleanup(httpServer.Close)
	return httpServer
}

func postPatternLogin(t *testing.T, server *httptest.Server, redirectURI string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider": "password", "client_id": patternClientID, "response_type": "code",
		"redirect_uri": redirectURI, "credential": map[string]string{
			"username": patternUsername, "password": patternPassword,
		},
	})
	resp, err := http.Post(server.URL+"/auth/login", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("pattern login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode pattern login response: %v (body=%s)", err, raw)
	}
	return resp.StatusCode, out
}
