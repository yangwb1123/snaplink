package sso_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

func newBearerChallengeHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: "bc-c", Secret: "bc-s", Active: true, TokenStrategy: "jwt"})
	srv := sso.NewServer(
		sso.WithIssuer("https://issuer.example"),
		sso.WithUserProvider(users),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestUserInfo_MissingTokenWWWAuthenticateChallenge(t *testing.T) {
	srv := newBearerChallengeHarness(t)
	resp, err := http.Get(srv.URL + "/userinfo")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	ch := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(ch, "Bearer ") {
		t.Errorf("WWW-Authenticate = %q, want Bearer challenge", ch)
	}
	if !strings.Contains(ch, `realm="https://issuer.example"`) {
		t.Errorf("challenge missing realm: %q", ch)
	}
	// RFC 6750 §3.1: no token → no error parameter.
	if strings.Contains(ch, `error=`) {
		t.Errorf("challenge MUST NOT include error= when no token presented: %q", ch)
	}
}

func TestUserInfo_InvalidTokenWWWAuthenticateChallenge(t *testing.T) {
	srv := newBearerChallengeHarness(t)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	ch := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(ch, `error="invalid_token"`) {
		t.Errorf("invalid token challenge missing error=invalid_token: %q", ch)
	}
}
