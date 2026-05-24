package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	uiLocalesUserID   = "u-ui"
	uiLocalesClientID = "ui-client"
	uiLocalesSecret   = "ui-secret"
	uiLocalesPassword = "pw"
	uiLocalesRedirect = "https://app.example/cb"
)

type uiCaptureAuthenticator struct {
	mu      sync.Mutex
	locales []string
}

func (c *uiCaptureAuthenticator) Name() string             { return "password" }
func (c *uiCaptureAuthenticator) LoginURL(_ string) string { return "" }
func (c *uiCaptureAuthenticator) Authenticate(_ context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	if req == nil {
		return nil, errors.New("nil")
	}
	c.mu.Lock()
	c.locales = append([]string(nil), req.UILocales...)
	c.mu.Unlock()
	return &sso.AuthResult{UserID: uiLocalesUserID, Provider: "password"}, nil
}
func (c *uiCaptureAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("no callback")
}
func (c *uiCaptureAuthenticator) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.locales))
	copy(out, c.locales)
	return out
}

func newUIHarness(t *testing.T) (*httptest.Server, *uiCaptureAuthenticator) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: uiLocalesUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: uiLocalesClientID, Secret: uiLocalesSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{uiLocalesRedirect},
	})
	auth := &uiCaptureAuthenticator{}
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(auth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, auth
}

func TestUILocales_PreservedAndThreaded(t *testing.T) {
	srv, auth := newUIHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  uiLocalesClientID,
		"credential": map[string]string{"username": uiLocalesUserID, "password": uiLocalesPassword},
		// OIDC spec: "Space separated list of BCP47 language tag values"
		"ui_locales": "fr-CA fr en-US",
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	got := auth.snapshot()
	want := []string{"fr-CA", "fr", "en-US"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("UILocales = %v want %v (preference order preserved)", got, want)
	}
}

func TestUILocales_AbsentByDefault(t *testing.T) {
	srv, auth := newUIHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  uiLocalesClientID,
		"credential": map[string]string{"username": uiLocalesUserID, "password": uiLocalesPassword},
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if got := auth.snapshot(); len(got) != 0 {
		t.Errorf("UILocales = %v want empty", got)
	}
}
