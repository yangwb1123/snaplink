package ssotest

// AC3 contract tests for the B4-4 SDK form-emission change
// (cmd/gensdk, reconciliation D6): the generated TS/Python clients now
// send application/x-www-form-urlencoded bodies on the seven
// credential-family operations. These tests pin the form wire against
// the server's DUAL-MODE binder, which accepts form bodies today
// (oauthwire.BindParams); the JSON-rejection control arm (415
// invalid_request) lands with the sibling strict-binder change, which
// owns the server-side tests.
//
// TestSdkForm_PARClaimsThreaded is the F1 merge-interlock arm (D6): it
// is deliberately RED until the sibling's json.RawMessage form branch
// lands in oauthwire/bind.go (RFC 9396 §3 JSON-string decoding for
// PAR claims/authorization_details) and must never be skipped — CI
// cannot go green before the sibling change merges.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// newSDKFormClaimsHarness is newClaimsParamHarness plus an auth-code
// store: the PAR claims arm logs in with response_type=code (the
// code-flow shape a real PAR client uses), which needs the store.
func newSDKFormClaimsHarness(t *testing.T) (*httptest.Server, *claimsCaptureAuthenticator) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: cpUserID})
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: cpClientID, Secret: cpSecret, Active: true,
		AllowedAuthenticators: []string{"password"},
		TokenStrategy:         "jwt",
		RedirectURIs:          []string{cpRedirect},
	})
	auth := &claimsCaptureAuthenticator{}
	parStore := defaultimpl.NewMemoryPARStore()
	srv := sso.NewServer(
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuthenticator(auth),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(time.Minute))),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
		sso.WithPARStore(parStore, 0),
	)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, auth
}

// TestSdkForm_TokenClientCredentialsFormWire drives POST /token exactly
// as the generated clients emit it: HTTP Basic for the confidential
// client plus a form-urlencoded body (grant_type, scope). This is the
// wire shape the strict binder (B4-4) will require.
func TestSdkForm_TokenClientCredentialsFormWire(t *testing.T) {
	srv, _ := newTokenHarness(t, true)

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read write"},
	}
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(tokenClientID, tokenSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token (form): %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok, _ := out["access_token"].(string); tok == "" {
		t.Errorf("access_token empty: %v", out)
	}
	if out["token_type"] != "Bearer" {
		t.Errorf("token_type = %v", out["token_type"])
	}
	if out["scope"] != "read write" {
		t.Errorf("scope = %v", out["scope"])
	}
}

// TestSdkForm_PARRepeatedResourceKeys pins the repeated-key contract
// (openapi.yaml: "Repeated form keys form the resource lists"): the
// form serializer emits one resource= per element and the binder's
// formStringSlice collects them verbatim.
func TestSdkForm_PARRepeatedResourceKeys(t *testing.T) {
	srv, _ := newPARHarness(t, nil)

	form := url.Values{
		"client_id":     {parClientID},
		"client_secret": {parSecret},
		"response_type": {"code"},
		"redirect_uri":  {parRedirect},
		"scope":         {"openid"},
		"resource":      {"https://api.example/v1", "https://rs2.example"},
	}
	resp, err := http.Post(srv.URL+"/par", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("par: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if uri, _ := out["request_uri"].(string); !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri = %q", uri)
	}
}

// TestSdkForm_PARClaimsThreaded drives a form-encoded PAR carrying the
// claims JSON-string (RFC 9396 §3 / OIDC Core §5.5), then logs in with
// the request_uri and asserts the requested claims reached the
// authorization request.
//
// F1 interlock (reconciliation D6): the shared decoder's
// json.RawMessage form branch is the sibling B4-4 change. Until it
// lands, the claims key binds successfully with the value silently
// dropped, this test FAILS (claims absent at login), and the gensdk
// change cannot merge. Never skip this test.
func TestSdkForm_PARClaimsThreaded(t *testing.T) {
	srv, auth := newSDKFormClaimsHarness(t)

	const claims = `{"userinfo":{"email":null,"name":{"essential":true}},"id_token":{"email":null}}`
	form := url.Values{
		"client_id":     {cpClientID},
		"client_secret": {cpSecret},
		"response_type": {"code"},
		"redirect_uri":  {cpRedirect},
		"claims":        {claims},
	}
	resp, err := http.Post(srv.URL+"/par", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("par: %v", err)
	}
	rawPAR, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("par status=%d body=%s", resp.StatusCode, rawPAR)
	}
	var parOut map[string]any
	if err := json.Unmarshal(rawPAR, &parOut); err != nil {
		t.Fatalf("decode par: %v", err)
	}
	uri, _ := parOut["request_uri"].(string)
	if uri == "" {
		t.Fatalf("par returned no request_uri: %s", rawPAR)
	}

	loginBody, _ := json.Marshal(map[string]any{
		"provider":    "password",
		"client_id":   cpClientID,
		"credential":  map[string]string{"username": cpUserID, "password": cpPassword},
		"request_uri": uri,
	})
	loginResp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(loginBody))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	rawLogin, _ := io.ReadAll(loginResp.Body)
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusOK {
		t.Fatalf("login status=%d body=%s", loginResp.StatusCode, rawLogin)
	}

	got := auth.snapshot()
	if len(got) == 0 {
		// Deliberately red until the sibling F1 decoder lands: the
		// form PAR's claims key is silently dropped by setFormField
		// today (no json.RawMessage branch). Do not skip.
		t.Fatal("form-PAR claims did not thread into the authorization request (sibling F1 decoder not landed)")
	}
	var parsed map[string]any
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("requested claims not parseable: %v", err)
	}
	if _, ok := parsed["userinfo"].(map[string]any); !ok {
		t.Errorf("userinfo branch missing: %v", parsed)
	}
	if _, ok := parsed["id_token"].(map[string]any); !ok {
		t.Errorf("id_token branch missing: %v", parsed)
	}
}
