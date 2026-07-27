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

const (
	pcrtUserID   = "u-pcrt"
	pcrtClientA  = "pcrt-short"
	pcrtClientB  = "pcrt-long"
	pcrtPassword = "pw"
	pcrtSecretA  = "secret-a"
	pcrtSecretB  = "secret-b"
)

// newPerClientRefreshTTLHarness wires two clients with different
// RefreshTokenTTL overrides + a server-wide default. Lets tests
// observe each client's effective TTL on the issued refresh token's
// IssuedAt/ExpiresAt window.
func newPerClientRefreshTTLHarness(t *testing.T) (*httptest.Server, *defaultimpl.MemoryRefreshTokenStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: pcrtUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: pcrtClientA, Secret: pcrtSecretA, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RefreshTokenTTL:       5 * time.Minute, // override → short
	})
	clients.AddSeed(&sso.Client{
		ID: pcrtClientB, Secret: pcrtSecretB, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		// No override → inherits the server's WithRefreshTokenStore
		// ttl (1 hour in this harness).
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != pcrtPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: pcrtUserID, Provider: "password"}, nil
		},
	))
	rtStore := defaultimpl.NewMemoryRefreshTokenStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithRefreshTokenStore(rtStore, time.Hour),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, rtStore
}

func loginPCRT(t *testing.T, srv *httptest.Server, clientID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  clientID,
		"credential": map[string]string{"username": pcrtUserID, "password": pcrtPassword},
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login %s: %v", clientID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("login %s status=%d body=%s", clientID, resp.StatusCode, raw)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	rt, _ := out["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("no refresh_token: %v", out)
	}
	return rt
}

func TestPerClientRefreshTTL_OverrideShortensWindow(t *testing.T) {
	srv, store := newPerClientRefreshTTLHarness(t)
	rt := loginPCRT(t, srv, pcrtClientA)

	info, err := store.Inspect(context.Background(), rt)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	window := info.ExpiresAt.Sub(info.IssuedAt)
	// 5 minutes per the override; allow a generous floor.
	if window < 4*time.Minute || window > 6*time.Minute {
		t.Errorf("client A window = %v want ~5m (per-client override)", window)
	}
}

func TestPerClientRefreshTTL_FallsBackToServerDefault(t *testing.T) {
	srv, store := newPerClientRefreshTTLHarness(t)
	rt := loginPCRT(t, srv, pcrtClientB)

	info, err := store.Inspect(context.Background(), rt)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	window := info.ExpiresAt.Sub(info.IssuedAt)
	// 1 hour per the server default; allow leeway.
	if window < 59*time.Minute || window > 61*time.Minute {
		t.Errorf("client B window = %v want ~1h (server default)", window)
	}
}

func TestPerClientRefreshTTL_HonoredOnRotation(t *testing.T) {
	srv, store := newPerClientRefreshTTLHarness(t)
	rt1 := loginPCRT(t, srv, pcrtClientA)

	form := "grant_type=refresh_token&refresh_token=" + rt1 +
		"&client_id=" + pcrtClientA + "&client_secret=" + pcrtSecretA
	resp, err := http.Post(srv.URL+"/token", "application/x-www-form-urlencoded", bytes.NewReader([]byte(form)))
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	rt2, _ := out["refresh_token"].(string)
	if rt2 == "" || rt2 == rt1 {
		t.Fatalf("expected new refresh token; got %q (original %q)", rt2, rt1)
	}
	info, err := store.Inspect(context.Background(), rt2)
	if err != nil {
		t.Fatalf("inspect rotated: %v", err)
	}
	window := info.ExpiresAt.Sub(info.IssuedAt)
	if window < 4*time.Minute || window > 6*time.Minute {
		t.Errorf("rotated token window = %v want ~5m (per-client override preserved across rotation)", window)
	}
}
