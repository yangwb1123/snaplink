package sso_test

import "github.com/snaplink/sso/oauth"

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	acrUserID   = "u-acr"
	acrClientID = "acr-client"
	acrSecret   = "acr-secret"
	acrPassword = "pw"
	acrRedirect = "https://app.example/cb"
)

// acrCaptureAuthenticator records every AuthRequest's ACRValues so
// tests can verify they thread through from /auth/login + PAR + JAR.
type acrCaptureAuthenticator struct {
	mu     sync.Mutex
	values []string
}

func (c *acrCaptureAuthenticator) Name() string             { return "password" }
func (c *acrCaptureAuthenticator) LoginURL(_ string) string { return "" }
func (c *acrCaptureAuthenticator) Authenticate(_ context.Context, req *sso.AuthRequest) (*sso.AuthResult, error) {
	if req == nil {
		return nil, errors.New("nil")
	}
	c.mu.Lock()
	c.values = append([]string(nil), req.ACRValues...)
	c.mu.Unlock()
	return &sso.AuthResult{UserID: acrUserID, Provider: "password"}, nil
}
func (c *acrCaptureAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	return nil, errors.New("no callback")
}
func (c *acrCaptureAuthenticator) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]string, len(c.values))
	copy(out, c.values)
	return out
}

func newACRHarness(t *testing.T) (*httptest.Server, *acrCaptureAuthenticator, oauth.PARStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: acrUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: acrClientID, Secret: acrSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{acrRedirect},
	})
	auth := &acrCaptureAuthenticator{}
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(auth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, auth, parStore
}

func TestACRValues_ParsedAndThreaded(t *testing.T) {
	srv, auth, _ := newACRHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  acrClientID,
		"credential": map[string]string{"username": acrUserID, "password": acrPassword},
		"acr_values": "urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze",
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	got := auth.snapshot()
	want := []string{"urn:mace:incommon:iap:silver", "urn:mace:incommon:iap:bronze"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ACRValues = %v want %v (order preserved per OIDC spec)", got, want)
	}
}

func TestACRValues_PARPushSurvives(t *testing.T) {
	srv, auth, store := newACRHarness(t)
	uri, err := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID:    acrClientID,
		RedirectURI: acrRedirect,
		ACRValues:   "level-high level-medium",
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("seed PAR: %v", err)
	}
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   acrClientID,
		"credential":  map[string]string{"username": acrUserID, "password": acrPassword},
		"request_uri": uri,
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	got := auth.snapshot()
	want := []string{"level-high", "level-medium"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PAR-pushed ACRValues = %v want %v", got, want)
	}
}

func TestACRValues_PARPushBeatsLoginParam(t *testing.T) {
	srv, auth, store := newACRHarness(t)
	uri, _ := store.Issue(context.Background(), &oauth.PARRequest{
		ClientID:    acrClientID,
		RedirectURI: acrRedirect,
		ACRValues:   "level-strong",
		ExpiresAt:   time.Now().Add(time.Minute),
	})
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   acrClientID,
		"credential":  map[string]string{"username": acrUserID, "password": acrPassword},
		"request_uri": uri,
		"acr_values":  "level-weak", // tampered redirect-time value
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	got := auth.snapshot()
	sort.Strings(got)
	want := []string{"level-strong"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PAR-pushed ACRValues = %v want %v (push must win)", got, want)
	}
}

func TestACRValues_AbsentByDefault(t *testing.T) {
	srv, auth, _ := newACRHarness(t)
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  acrClientID,
		"credential": map[string]string{"username": acrUserID, "password": acrPassword},
	})
	resp, _ := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	resp.Body.Close()
	if got := auth.snapshot(); len(got) != 0 {
		t.Errorf("ACRValues = %v want empty (no hint supplied)", got)
	}
}
