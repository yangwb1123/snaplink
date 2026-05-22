package sso_test

import (
	"context"
	"encoding/json"
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
	pcdtUserID     = "u-pcdt"
	pcdtShortCli   = "pcdt-short"
	pcdtDefaultCli = "pcdt-default"
	pcdtSecret     = "pcdt-secret"
	pcdtPassword   = "pw"
)

func newDeviceTTLHarness(t *testing.T) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: pcdtUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: pcdtShortCli, Secret: pcdtSecret, Active: true,
		AllowedAuthenticators:  []string{"password"},
		TokenStrategy:          "jwt",
		DeviceCodeTTL:          90 * time.Second,
		DeviceCodePollInterval: 10 * time.Second,
	})
	clients.AddSeed(&sso.Client{
		ID: pcdtDefaultCli, Secret: pcdtSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: pcdtUserID, Provider: "password"}, nil
		},
	))
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithDeviceCodeStore(defaultimpl.NewMemoryDeviceCodeStore(), 15*time.Minute, 5*time.Second, "https://sso.test/device"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func TestPerClientDeviceTTL_OverrideShortensWindow(t *testing.T) {
	srv := newDeviceTTLHarness(t)
	form := "client_id=" + pcdtShortCli + "&client_secret=" + pcdtSecret
	resp, err := http.Post(srv.URL+"/device/code", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatalf("device/code: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, rb)
	}
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	exp, _ := out["expires_in"].(float64)
	if exp < 80 || exp > 100 {
		t.Errorf("expires_in = %v want ~90 (per-client override)", exp)
	}
	interval, _ := out["interval"].(float64)
	if interval < 9 || interval > 11 {
		t.Errorf("interval = %v want ~10 (per-client override)", interval)
	}
}

func TestPerClientDeviceTTL_FallsBackToServerDefault(t *testing.T) {
	srv := newDeviceTTLHarness(t)
	form := "client_id=" + pcdtDefaultCli + "&client_secret=" + pcdtSecret
	resp, err := http.Post(srv.URL+"/device/code", "application/x-www-form-urlencoded", strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(rb, &out)
	exp, _ := out["expires_in"].(float64)
	if exp < 890 || exp > 910 {
		t.Errorf("expires_in = %v want ~900 (server-wide 15m default)", exp)
	}
	interval, _ := out["interval"].(float64)
	if interval < 4 || interval > 6 {
		t.Errorf("interval = %v want ~5 (server-wide default)", interval)
	}
}
