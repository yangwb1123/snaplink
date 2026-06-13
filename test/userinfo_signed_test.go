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
	usUserID     = "u-us"
	usClientJSON = "us-client-json"
	usClientJWT  = "us-client-jwt"
	usSecret     = "us-secret"
	usPassword   = "pw"
)

func newUserinfoSignedHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID:    usUserID,
		Email: "alice@example.com",
		Name:  "Alice",
	})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: usClientJSON, Secret: usSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		// No UserinfoSignedResponseAlg → plain JSON.
	})
	clients.AddSeed(&sso.Client{
		ID: usClientJWT, Secret: usSecret, Active: true,
		AllowedAuthenticators:     []string{"password"},
		TokenStrategy:             "jwt",
		UserinfoSignedResponseAlg: "EdDSA",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != usPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: usUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithIDTokenIssuer(issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func usLogin(t *testing.T, srv *httptest.Server, clientID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": usUserID, "password": usPassword},
		"scope":      []string{"openid", "email", "profile"},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	access, _ := out["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %s", rb)
	}
	return access
}

func TestUserinfoSigned_JSONByDefault(t *testing.T) {
	srv := newUserinfoSignedHarness(t)
	tok := usLogin(t, srv, usClientJSON)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	ct := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q want application/json (no signed-alg config)", ct)
	}
}

func TestUserinfoSigned_JWTWhenClientOptsIn(t *testing.T) {
	srv := newUserinfoSignedHarness(t)
	tok := usLogin(t, srv, usClientJWT)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	ct := resp.Header.Get("Content-Type")
	if ct != "application/jwt" {
		t.Errorf("Content-Type = %q want application/jwt (client opts into signed userinfo)", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if len(strings.Split(string(body), ".")) != 3 {
		t.Errorf("body is not 3-segment JWT: %s", body)
	}
}

func TestUserinfoSigned_DiscoveryAdvertises(t *testing.T) {
	srv := newUserinfoSignedHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	algs, _ := doc["userinfo_signing_alg_values_supported"].([]any)
	if len(algs) == 0 {
		t.Fatalf("userinfo_signing_alg_values_supported missing: %v", doc)
	}
	found := false
	for _, a := range algs {
		if a == "EdDSA" {
			found = true
		}
	}
	if !found {
		t.Errorf("algs = %v want to contain EdDSA", algs)
	}
}
