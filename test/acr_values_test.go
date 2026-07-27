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
	"reflect"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sso "github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/protocols/oauth"
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
	// Echo the first requested ACR value back as AchievedACR so
	// the enforcement gate in handleLogin is satisfied.  Tests
	// that want to exercise the gate use a dedicated verifier
	// that doesn't echo (see TestACREnforcement_* below).
	achieved := ""
	if len(req.ACRValues) > 0 {
		achieved = req.ACRValues[0]
	}
	return &sso.AuthResult{UserID: acrUserID, Provider: "password", AchievedACR: achieved}, nil
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
	defer func() { _ = resp.Body.Close() }()
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
	_ = resp.Body.Close()
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
	_ = resp.Body.Close()
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
	_ = resp.Body.Close()
	if got := auth.snapshot(); len(got) != 0 {
		t.Errorf("ACRValues = %v want empty (no hint supplied)", got)
	}
}

// newACREnforcementServer builds a server whose password authenticator
// always returns the given achievedACR (may be empty).
func newACREnforcementServer(t *testing.T, achievedACR string) *httptest.Server {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: acrUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID:                    acrClientID,
		Secret:                acrSecret,
		Active:                true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, p string) (*sso.AuthResult, error) {
			if p != acrPassword {
				return nil, errors.New("bad")
			}
			return &sso.AuthResult{UserID: acrUserID, Provider: "password", AchievedACR: achievedACR}, nil
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

func acrEnforcementLogin(t *testing.T, srv *httptest.Server, acrValues string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"provider":   "password",
		"client_id":  acrClientID,
		"credential": map[string]string{"username": acrUserID, "password": acrPassword},
		"acr_values": acrValues,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	rb, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(rb, &out)
	return resp.StatusCode, out
}

// TestACREnforcement_MatchingACRIssuesToken: authenticator achieves one
// of the requested ACR values → login succeeds and the token carries
// the right acr claim.
func TestACREnforcement_MatchingACRIssuesToken(t *testing.T) {
	const wantACR = "urn:mace:incommon:iap:silver"
	srv := newACREnforcementServer(t, wantACR)
	status, body := acrEnforcementLogin(t, srv, "urn:mace:incommon:iap:silver urn:mace:incommon:iap:bronze")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("no access_token: %v", body)
	}
	payload, err := jwtPayload(at)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("parse claims: %v", err)
	}
	if got, _ := claims["acr"].(string); got != wantACR {
		t.Errorf("token acr = %q want %q", got, wantACR)
	}
}

// TestACREnforcement_NonMatchingACRRejected: authenticator achieves an
// ACR not in the requested set → 400 unmet_authentication_requirements.
func TestACREnforcement_NonMatchingACRRejected(t *testing.T) {
	srv := newACREnforcementServer(t, "urn:level:low")
	status, body := acrEnforcementLogin(t, srv, "urn:mace:incommon:iap:silver")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != sso.ErrUnmetAuthReqs {
		t.Errorf("error=%v want %q", body["error"], sso.ErrUnmetAuthReqs)
	}
}

// TestACREnforcement_EmptyAchievedACRRejected: authenticator reports no
// ACR but the RP requested one → 400 unmet_authentication_requirements.
func TestACREnforcement_EmptyAchievedACRRejected(t *testing.T) {
	srv := newACREnforcementServer(t, "")
	status, body := acrEnforcementLogin(t, srv, "urn:mace:incommon:iap:bronze")
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != sso.ErrUnmetAuthReqs {
		t.Errorf("error=%v want %q", body["error"], sso.ErrUnmetAuthReqs)
	}
}

// TestACREnforcement_NoACRValuesRequestedAlwaysSucceeds: when the RP
// does not supply acr_values the gate is completely absent regardless of
// what AchievedACR the authenticator reports.
func TestACREnforcement_NoACRValuesRequestedAlwaysSucceeds(t *testing.T) {
	srv := newACREnforcementServer(t, "")
	status, body := acrEnforcementLogin(t, srv, "")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v (no acr_values should always succeed)", status, body)
	}
	if _, ok := body["access_token"].(string); !ok {
		t.Errorf("expected access_token: %v", body)
	}
}

// jwtPayload decodes the payload segment of a compact JWS without
// verifying the signature (test-only).
func jwtPayload(token string) ([]byte, error) {
	// find the two dots that separate header.payload.sig
	first := -1
	second := -1
	for i, c := range token {
		if c == '.' {
			if first == -1 {
				first = i
			} else {
				second = i
				break
			}
		}
	}
	if first == -1 || second == -1 {
		return nil, errors.New("not a compact JWT")
	}
	return base64.RawURLEncoding.DecodeString(token[first+1 : second])
}
