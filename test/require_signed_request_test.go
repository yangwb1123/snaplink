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

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
)

const (
	rsroUser     = "u-rsro"
	rsroClient   = "rsro-client"
	rsroPassword = "pw"
)

func newRSROHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rsroUser})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rsroClient, Active: true,
		AllowedAuthenticators:      []string{"password"},
		TokenStrategy:              "jwt",
		RequireSignedRequestObject: true,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != rsroPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: rsroUser}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestRequireSignedRequestObject_DiscoveryAdvertisesGlobalFlag(t *testing.T) {
	srv := newRSROHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if v, _ := doc["require_signed_request_object"].(bool); !v {
		t.Fatalf("require_signed_request_object missing/false; want true (all clients enforce): %s", raw)
	}
}

func TestRequireSignedRequestObject_RejectsDirectLogin(t *testing.T) {
	srv := newRSROHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  rsroClient,
		"credential": map[string]string{"username": rsroUser, "password": rsroPassword},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	if out["error"] != sso.ErrInvalidRequest {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidRequest)
	}
}
