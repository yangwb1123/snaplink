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

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	pcatUserID   = "u-pcat"
	pcatClientA  = "pcat-short"
	pcatClientB  = "pcat-long"
	pcatPassword = "pw"
	pcatSecretA  = "secret-a"
	pcatSecretB  = "secret-b"
)

func newPerClientAccessTTLHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: pcatUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: pcatClientA, Secret: pcatSecretA, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AccessTokenTTL:        2 * time.Minute, // override → short
	})
	clients.AddSeed(&sso.Client{
		ID: pcatClientB, Secret: pcatSecretB, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		// No override → inherits the issuer's default (1 hour below).
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != pcatPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: pcatUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Hour))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func loginPCAT(t *testing.T, srv *httptest.Server, clientID string) (token string, expiresIn int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": pcatUserID, "password": pcatPassword},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login %s: %v", clientID, err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s status=%d body=%s", clientID, resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	token, _ = out["access_token"].(string)
	if exp, ok := out["expires_in"].(float64); ok {
		expiresIn = int(exp)
	}
	return token, expiresIn
}

func TestPerClientAccessTTL_OverrideShortensWindow(t *testing.T) {
	srv := newPerClientAccessTTLHarness(t)
	_, expiresIn := loginPCAT(t, srv, pcatClientA)
	// Override is 2m = 120s.
	if expiresIn < 110 || expiresIn > 130 {
		t.Errorf("client A expires_in = %d want ~120 (per-client override)", expiresIn)
	}
}

func TestPerClientAccessTTL_FallsBackToIssuerDefault(t *testing.T) {
	srv := newPerClientAccessTTLHarness(t)
	_, expiresIn := loginPCAT(t, srv, pcatClientB)
	// Issuer default is 1h = 3600s.
	if expiresIn < 3500 || expiresIn > 3700 {
		t.Errorf("client B expires_in = %d want ~3600 (issuer default)", expiresIn)
	}
}

func TestPerClientAccessTTL_HonoredAtJWTExpClaim(t *testing.T) {
	srv := newPerClientAccessTTLHarness(t)
	tok, _ := loginPCAT(t, srv, pcatClientA)
	payload := decodeAccessTokenPayload(t, tok)
	exp, ok := payload["exp"].(float64)
	if !ok {
		t.Fatalf("no exp claim: %v", payload)
	}
	iat, ok := payload["iat"].(float64)
	if !ok {
		t.Fatalf("no iat claim: %v", payload)
	}
	window := int64(exp - iat)
	if window < 110 || window > 130 {
		t.Errorf("JWT exp-iat window = %ds want ~120 (per-client override)", window)
	}
}
