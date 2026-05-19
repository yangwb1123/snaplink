package sso_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
)

const (
	parClientID = "par-client"
	parSecret   = "par-secret"
	parUserID   = "u-par"
	parAPI      = "https://api.example/v1"
	parRedirect = "https://app.example/callback"
)

func newPARHarness(t *testing.T, allowedResources []string) (*httptest.Server, sso.PARStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: parUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: parClientID, Secret: parSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		AllowedResources:      allowedResources,
		RedirectURIs:          []string{parRedirect},
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: parUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	codes := defaultimpl.NewMemoryAuthCodeStore()
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(codes, time.Minute),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, parStore
}

func postPARForm(t *testing.T, srv *httptest.Server, form url.Values) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/par",
		"application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("par: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func TestPAR_HappyPath_FormEncoded(t *testing.T) {
	srv, _ := newPARHarness(t, []string{parAPI})
	status, body := postPARForm(t, srv, url.Values{
		"client_id":     {parClientID},
		"client_secret": {parSecret},
		"response_type": {"code"},
		"redirect_uri":  {parRedirect},
		"scope":         {"read write"},
		"state":         {"xyz"},
		"resource":      {parAPI},
	})
	if status != http.StatusCreated {
		t.Fatalf("status=%d body=%v", status, body)
	}
	uri, _ := body["request_uri"].(string)
	if !strings.HasPrefix(uri, sso.PARURIPrefix) {
		t.Errorf("request_uri = %q want prefix %q", uri, sso.PARURIPrefix)
	}
	if exp, _ := body["expires_in"].(float64); exp <= 0 {
		t.Errorf("expires_in = %v", exp)
	}
}

func TestPAR_HappyPath_JSON(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	bodyReq, _ := json.Marshal(map[string]any{
		"client_id":     parClientID,
		"client_secret": parSecret,
		"response_type": "code",
		"redirect_uri":  parRedirect,
		"scope":         "openid",
		"state":         "abc",
	})
	resp, err := http.Post(srv.URL+"/par", "application/json", strings.NewReader(string(bodyReq)))
	if err != nil {
		t.Fatalf("par json: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestPAR_BasicAuthPrecedence(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	form := url.Values{
		"client_id":     {"wrong-id"},
		"client_secret": {"wrong-secret"},
		"response_type": {"code"},
		"redirect_uri":  {parRedirect},
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/par",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// HTTP Basic with correct creds — must win over body's wrong creds.
	auth := parClientID + ":" + parSecret
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("par basic: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestPAR_RejectsBadSecret(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	status, body := postPARForm(t, srv, url.Values{
		"client_id":     {parClientID},
		"client_secret": {"wrong"},
		"response_type": {"code"},
		"redirect_uri":  {parRedirect},
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%v", status, body)
	}
}

func TestPAR_RejectsBadRedirectURI(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	status, body := postPARForm(t, srv, url.Values{
		"client_id":     {parClientID},
		"client_secret": {parSecret},
		"response_type": {"code"},
		"redirect_uri":  {"https://attacker.example/steal"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidRedirectURI {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidRedirectURI)
	}
}

func TestPAR_RejectsUnregisteredResource(t *testing.T) {
	srv, _ := newPARHarness(t, []string{parAPI})
	status, body := postPARForm(t, srv, url.Values{
		"client_id":     {parClientID},
		"client_secret": {parSecret},
		"response_type": {"code"},
		"redirect_uri":  {parRedirect},
		"resource":      {"https://other.example/v1"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["error"] != sso.ErrInvalidTarget {
		t.Errorf("error=%v want %q", body["error"], sso.ErrInvalidTarget)
	}
}

func TestPAR_LoginConsumesRequestURI(t *testing.T) {
	srv, store := newPARHarness(t, nil)
	uri, err := store.Issue(context.Background(), &sso.PARRequest{
		ClientID:     parClientID,
		ResponseType: "code",
		RedirectURI:  parRedirect,
		Scope:        []string{"read"},
		State:        "abc",
		ExpiresAt:    time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Login with request_uri — merging picks up response_type=code +
	// redirect_uri so an authorization code is returned.
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   parClientID, // still required to gate the store lookup
		"credential":  map[string]string{"username": "x", "password": "y"},
		"request_uri": uri,
	})
	resp, err := http.Post(srv.URL+"/auth/login",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if out["code"] == nil {
		t.Errorf("expected authorization code in response: %s", raw)
	}
	if out["state"] != "abc" {
		t.Errorf("state = %v want abc", out["state"])
	}
	// Single-use: second consume must fail.
	if _, err := store.Consume(context.Background(), uri); err != sso.ErrPARNotFound {
		t.Errorf("second Consume err = %v want ErrPARNotFound", err)
	}
}

func TestPAR_LoginRejectsUnknownRequestURI(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   parClientID,
		"credential":  map[string]string{"username": "x", "password": "y"},
		"request_uri": sso.PARURIPrefix + "bogus",
	})
	resp, err := http.Post(srv.URL+"/auth/login",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	if out["error"] != sso.ErrInvalidRequestURI {
		t.Errorf("error=%v want %q", out["error"], sso.ErrInvalidRequestURI)
	}
}

func TestPAR_StoreNotConfigured_Returns501(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{ID: parClientID, Secret: parSecret, Active: true})
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)

	resp, err := http.Post(httpSrv.URL+"/par",
		"application/x-www-form-urlencoded",
		strings.NewReader("client_id="+parClientID+"&client_secret="+parSecret))
	if err != nil {
		t.Fatalf("par: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	if out["error"] != sso.ErrPARNotConfigured {
		t.Errorf("error=%v want %q", out["error"], sso.ErrPARNotConfigured)
	}
}

func TestPAR_AdvertisedInDiscovery(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	endpoint, _ := doc["pushed_authorization_request_endpoint"].(string)
	if !strings.HasSuffix(endpoint, "/par") {
		t.Errorf("pushed_authorization_request_endpoint = %q", endpoint)
	}
}
