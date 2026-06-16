package ssotest

import (
	"bytes"
	"context"
	"encoding/base64"
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

// These prove /userinfo honors a non-EdDSA userinfo_signed_response_alg
// (ES256 here) instead of silently returning plain JSON. Before the fix the
// signed path was gated on a hardcoded == "EdDSA" check, so an ES256-only
// deployment advertised userinfo_signing_alg_values_supported: ["ES256"] in
// discovery yet returned unsigned JSON — a discovery↔handler inconsistency.

const (
	usES256User   = "u-es"
	usES256Client = "es-client-jwt"
	usES256Secret = "es-secret"
)

func newUserinfoES256Harness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID: usES256User, Email: "es@example.com", Name: "Es",
	})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: usES256Client, Secret: usES256Secret, Active: true,
		AllowedAuthenticators:     []string{"password"},
		TokenStrategy:             "jwt",
		UserinfoSignedResponseAlg: "ES256",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != usPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: usES256User, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewECDSAJWTIssuer(defaultimpl.WithECDSATokenTTL(time.Minute))
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

func es256Login(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  usES256Client,
		"credential": map[string]string{"username": usES256User, "password": usPassword},
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

func jwsHeaderAlgField(t *testing.T, jwt string) string {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("not a 3-segment JWT: %q", jwt)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	return h.Alg
}

// TestUserinfoSigned_ES256_HonorsClientAlg: an ES256 deployment with a client
// that registered userinfo_signed_response_alg=ES256 gets an ES256-signed JWT
// userinfo response (not plain JSON). FAILS against the pre-fix EdDSA-only gate.
func TestUserinfoSigned_ES256_HonorsClientAlg(t *testing.T) {
	srv := newUserinfoES256Harness(t)
	tok := es256Login(t, srv)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if ct := resp.Header.Get("Content-Type"); ct != "application/jwt" {
		t.Fatalf("Content-Type = %q want application/jwt (ES256 client opts into signed userinfo)", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if alg := jwsHeaderAlgField(t, string(body)); alg != "ES256" {
		t.Errorf("userinfo JWS alg = %q want ES256", alg)
	}
}

// TestUserinfoSigned_ES256_DiscoveryAdvertises proves discovery advertises
// ES256 — the value the handler now honors (closing the inconsistency).
func TestUserinfoSigned_ES256_DiscoveryAdvertises(t *testing.T) {
	srv := newUserinfoES256Harness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	algs, _ := doc["userinfo_signing_alg_values_supported"].([]any)
	found := false
	for _, a := range algs {
		if a == "ES256" {
			found = true
		}
	}
	if !found {
		t.Errorf("userinfo_signing_alg_values_supported = %v want to contain ES256", algs)
	}
}
