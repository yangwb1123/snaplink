package ssotest

import "github.com/yangwb1123/snaplink/protocols/oauth"

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

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	parClientID = "par-client"
	parSecret   = "par-secret"
	parUserID   = "u-par"
	parAPI      = "https://api.example/v1"
	parRedirect = "https://app.example/callback"
)

func newPARHarness(t *testing.T, allowedResources []string) (*httptest.Server, oauth.PARStore) {
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
	defer func() { _ = resp.Body.Close() }()
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
	if !strings.HasPrefix(uri, oauth.PARURIPrefix) {
		t.Errorf("request_uri = %q want prefix %q", uri, oauth.PARURIPrefix)
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
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
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
	uri, err := store.Issue(context.Background(), &oauth.PARRequest{
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
	defer func() { _ = resp.Body.Close() }()
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
	if _, err := store.Consume(context.Background(), uri); err != oauth.ErrPARNotFound {
		t.Errorf("second Consume err = %v want oauth.ErrPARNotFound", err)
	}
}

func TestPAR_LoginRejectsUnknownRequestURI(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	body, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   parClientID,
		"credential":  map[string]string{"username": "x", "password": "y"},
		"request_uri": oauth.PARURIPrefix + "bogus",
	})
	resp, err := http.Post(srv.URL+"/auth/login",
		"application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
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
	defer func() { _ = resp.Body.Close() }()
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

// newPARHarnessWithAuthzDetailsAllowlist wires the same components
// as newPARHarness but also seeds the client with an
// authorization_details type allowlist so RFC 9396 PAR tests can
// drive both the accept + reject branches.
func newPARHarnessWithAuthzDetailsAllowlist(t *testing.T, allowedTypes []string) (*httptest.Server, oauth.PARStore) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: parUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: parClientID, Secret: parSecret, Active: true,
		AllowedAuthenticators:            []string{"password"},
		TokenStrategy:                    "jwt",
		RedirectURIs:                     []string{parRedirect},
		AllowedAuthorizationDetailsTypes: allowedTypes,
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, _, _ string) (*sso.AuthResult, error) {
			return &sso.AuthResult{UserID: parUserID, Provider: "password"}, nil
		},
	))
	issuer := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(pw),
		sso.WithTokenIssuer("jwt", issuer),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, parStore
}

// parThenLogin pushes the given RAR payload via /par then drives
// /auth/login with the resulting request_uri. Returns the access
// token's decoded JWT payload (or the failure response body when
// /par or /auth/login return non-2xx).
func parThenLogin(t *testing.T, srv *httptest.Server, details string, extraAuthzDetailsOnLogin string) (parStatus int, loginStatus int, loginBody map[string]any) {
	t.Helper()
	// No response_type=code: we want the subsequent /auth/login to
	// direct-mint an access token we can inspect for the
	// authorization_details claim (the code-flow variant lives in
	// rar_test.go).
	parReq := map[string]any{
		"client_id":     parClientID,
		"client_secret": parSecret,
		"redirect_uri":  parRedirect,
	}
	if details != "" {
		parReq["authorization_details"] = json.RawMessage(details)
	}
	parBody, _ := json.Marshal(parReq)
	parResp, err := http.Post(srv.URL+"/par", "application/json", strings.NewReader(string(parBody)))
	if err != nil {
		t.Fatalf("par: %v", err)
	}
	defer func() { _ = parResp.Body.Close() }()
	rawPAR, _ := io.ReadAll(parResp.Body)
	var parOut map[string]any
	_ = json.Unmarshal(rawPAR, &parOut)
	parStatus = parResp.StatusCode
	if parStatus != http.StatusCreated {
		return parStatus, 0, parOut
	}
	uri, _ := parOut["request_uri"].(string)
	if uri == "" {
		t.Fatalf("par returned no request_uri: %s", rawPAR)
	}

	loginReq := map[string]any{
		"provider":    "password",
		"client_id":   parClientID,
		"credential":  map[string]string{"username": "x", "password": "y"},
		"request_uri": uri,
	}
	if extraAuthzDetailsOnLogin != "" {
		loginReq["authorization_details"] = json.RawMessage(extraAuthzDetailsOnLogin)
	}
	loginRaw, _ := json.Marshal(loginReq)
	loginResp, err := http.Post(srv.URL+"/auth/login", "application/json", strings.NewReader(string(loginRaw)))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = loginResp.Body.Close() }()
	rawLogin, _ := io.ReadAll(loginResp.Body)
	loginBody = map[string]any{}
	_ = json.Unmarshal(rawLogin, &loginBody)
	loginStatus = loginResp.StatusCode
	return parStatus, loginStatus, loginBody
}

func TestPAR_AuthorizationDetailsSurvivesIntoAccessToken(t *testing.T) {
	srv, _ := newPARHarnessWithAuthzDetailsAllowlist(t, nil)
	const details = `[{"type":"payment_initiation","amount":"42","currency":"EUR","payee":"acme"}]`
	parStatus, loginStatus, body := parThenLogin(t, srv, details, "")
	if parStatus != http.StatusCreated || loginStatus != http.StatusOK {
		t.Fatalf("par=%d login=%d body=%v", parStatus, loginStatus, body)
	}
	tok, _ := body["access_token"].(string)
	if tok == "" {
		t.Fatalf("no access_token in login response: %v", body)
	}
	payload := decodeAccessTokenPayload(t, tok)
	ad, ok := payload["authorization_details"].([]any)
	if !ok {
		t.Fatalf("authorization_details missing on access token: %v", payload)
	}
	if len(ad) != 1 {
		t.Fatalf("expected 1 element, got %d: %v", len(ad), ad)
	}
	elem, _ := ad[0].(map[string]any)
	if elem["type"] != "payment_initiation" || elem["amount"] != "42" ||
		elem["currency"] != "EUR" || elem["payee"] != "acme" {
		t.Errorf("element fields not preserved end-to-end: %v", elem)
	}
}

func TestPAR_RejectsDisallowedAuthorizationDetailsTypeAtPushTime(t *testing.T) {
	srv, _ := newPARHarnessWithAuthzDetailsAllowlist(t, []string{"payment_initiation"})
	const details = `[{"type":"forbidden_type"}]`
	parStatus, _, body := parThenLogin(t, srv, details, "")
	if parStatus != http.StatusBadRequest {
		t.Fatalf("par status=%d body=%v want 400", parStatus, body)
	}
	if body["error"] != oauth.ErrInvalidAuthorizationDetails {
		t.Errorf("error=%v want %q", body["error"], oauth.ErrInvalidAuthorizationDetails)
	}
}

func TestPAR_RejectsMalformedAuthorizationDetailsAtPushTime(t *testing.T) {
	srv, _ := newPARHarnessWithAuthzDetailsAllowlist(t, nil)
	// RFC 9396 §2: authorization_details MUST be a JSON array.
	// A bare object MUST be rejected at PAR time (the whole point
	// of PAR is to validate upstream of the redirect).
	const details = `{"type":"payment_initiation"}`
	parStatus, _, body := parThenLogin(t, srv, details, "")
	if parStatus != http.StatusBadRequest {
		t.Fatalf("par status=%d body=%v want 400", parStatus, body)
	}
	if body["error"] != oauth.ErrInvalidAuthorizationDetails {
		t.Errorf("error=%v want %q", body["error"], oauth.ErrInvalidAuthorizationDetails)
	}
}

func TestPAR_AuthorizationDetailsOverridesLoginParam(t *testing.T) {
	// PAR's value is committing the authorization request up-front;
	// when both PAR's payload AND a caller-supplied parameter at
	// /auth/login are present, PAR wins (same precedence as
	// scope / resource / redirect_uri).
	srv, _ := newPARHarnessWithAuthzDetailsAllowlist(t, nil)
	const pushed = `[{"type":"payment_initiation","amount":"100"}]`
	const swapped = `[{"type":"payment_initiation","amount":"999999"}]`
	parStatus, loginStatus, body := parThenLogin(t, srv, pushed, swapped)
	if parStatus != http.StatusCreated || loginStatus != http.StatusOK {
		t.Fatalf("par=%d login=%d body=%v", parStatus, loginStatus, body)
	}
	tok, _ := body["access_token"].(string)
	payload := decodeAccessTokenPayload(t, tok)
	ad, _ := payload["authorization_details"].([]any)
	if len(ad) != 1 {
		t.Fatalf("expected 1 element, got %d", len(ad))
	}
	elem, _ := ad[0].(map[string]any)
	if elem["amount"] != "100" {
		t.Errorf("amount = %v want \"100\" (PAR payload, not the swap attempt)", elem["amount"])
	}
}

func TestPAR_LegacyCallerWithoutAuthorizationDetails(t *testing.T) {
	// PAR without authorization_details → token without the claim.
	// Confirms the merge path is opt-in and doesn't stamp empty
	// arrays or otherwise pollute the legacy code path.
	srv, _ := newPARHarnessWithAuthzDetailsAllowlist(t, nil)
	parStatus, loginStatus, body := parThenLogin(t, srv, "", "")
	if parStatus != http.StatusCreated || loginStatus != http.StatusOK {
		t.Fatalf("par=%d login=%d body=%v", parStatus, loginStatus, body)
	}
	tok, _ := body["access_token"].(string)
	payload := decodeAccessTokenPayload(t, tok)
	if _, ok := payload["authorization_details"]; ok {
		t.Errorf("authorization_details unexpectedly present on legacy token: %v", payload["authorization_details"])
	}
}

func TestPAR_AdvertisedInDiscovery(t *testing.T) {
	srv, _ := newPARHarness(t, nil)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	endpoint, _ := doc["pushed_authorization_request_endpoint"].(string)
	if !strings.HasSuffix(endpoint, "/par") {
		t.Errorf("pushed_authorization_request_endpoint = %q", endpoint)
	}
}
