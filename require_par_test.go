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
	rparUserID    = "u-rpar"
	rparClientID  = "rpar-client"
	rparSecret    = "rpar-secret"
	rparPassword  = "pw"
	rparRedirect  = "https://app.example/cb"
	rparClientLax = "rpar-lax-client"
)

func newRequirePARHarness(t *testing.T) (*httptest.Server, sso.PARStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: rparUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: rparClientID, Secret: rparSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{rparRedirect},
		RequirePAR:            true, // strict — direct /auth/login forbidden
	})
	clients.AddSeed(&sso.Client{
		ID: rparClientLax, Secret: rparSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{rparRedirect},
		// no RequirePAR — direct path still works
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != rparPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: rparUserID, Provider: "password"}, nil
		},
	))
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, parStore
}

func TestRequirePAR_RejectsDirectLoginForStrictClient(t *testing.T) {
	srv, _ := newRequirePARHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  rparClientID,
		"credential": map[string]string{"username": rparUserID, "password": rparPassword},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
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

func TestRequirePAR_AcceptsPARPushForStrictClient(t *testing.T) {
	srv, store := newRequirePARHarness(t)
	uri, err := store.Issue(context.Background(), &sso.PARRequest{
		ClientID:    rparClientID,
		RedirectURI: rparRedirect,
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("seed PAR: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   rparClientID,
		"credential":  map[string]string{"username": rparUserID, "password": rparPassword},
		"request_uri": uri,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
}

func TestRequirePAR_DirectLoginAllowedForLaxClient(t *testing.T) {
	srv, _ := newRequirePARHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  rparClientLax,
		"credential": map[string]string{"username": rparUserID, "password": rparPassword},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		rb, _ := io.ReadAll(resp.Body)
		t.Fatalf("lax client direct login should succeed: status=%d body=%s", resp.StatusCode, rb)
	}
}

func TestRequirePAR_DiscoveryFlagFlipsWhenAnyClientRequires(t *testing.T) {
	srv, _ := newRequirePARHarness(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if v, _ := doc["require_pushed_authorization_requests"].(bool); !v {
		t.Errorf("require_pushed_authorization_requests = %v want true (rpar-client opts in)", doc["require_pushed_authorization_requests"])
	}
}
