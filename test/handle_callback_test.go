package ssotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// callbackAuth is a stub Authenticator whose Callback returns a
// configurable result so handleCallback can be driven end-to-end
// without a real OIDC provider.
type callbackAuth struct {
	name string
	want string // expected callback code; mismatch triggers err
	out  *sso.AuthResult
	err  error
}

func (c *callbackAuth) Name() string { return c.name }
func (c *callbackAuth) Authenticate(context.Context, *sso.AuthRequest) (*sso.AuthResult, error) {
	return nil, errors.New("authenticate not used in callback tests")
}
func (c *callbackAuth) Callback(_ context.Context, s *sso.CallbackState) (*sso.AuthResult, error) {
	if c.err != nil {
		return nil, c.err
	}
	if c.want != "" && s.Code != c.want {
		return nil, errors.New("callback: code mismatch")
	}
	return c.out, nil
}
func (c *callbackAuth) LoginURL(state string) string {
	return "https://upstream.example/authorize?" + url.Values{"state": {state}}.Encode()
}

const (
	callbackClient    = "callback-client"
	callbackRedirect  = "https://rp.example/callback"
	callbackLoginPage = "https://login.example/authorize"
)

func newCallbackHarness(t *testing.T, auths ...sso.Authenticator) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	users := defaultimpl.NewMemoryUserProvider()
	for _, auth := range auths {
		stub, ok := auth.(*callbackAuth)
		if ok && stub.out != nil && stub.out.UserID != "" {
			_ = users.CreateOrUpdate(context.Background(), &sso.User{ID: stub.out.UserID})
		}
	}
	return newCallbackHarnessWithUsers(t, users, auths...)
}

func newCallbackHarnessWithUsers(
	t *testing.T, users *defaultimpl.MemoryUserProvider, auths ...sso.Authenticator,
) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	clients := defaultimpl.NewMemoryClientStore()
	allowed := make([]string, 0, len(auths))
	for _, auth := range auths {
		allowed = append(allowed, auth.Name())
	}
	clients.AddSeed(&sso.Client{
		ID: callbackClient, RedirectURIs: []string{callbackRedirect},
		AllowedAuthenticators: allowed, LoginPageURI: callbackLoginPage,
		TokenStrategy: "jwt", Active: true, SkipConsent: true,
	})

	opts := []sso.Option{
		sso.WithUserProvider(users),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithClientStore(clients),
		sso.WithAuditRecorder(rec),
		sso.WithTokenIssuer("jwt", defaultimpl.NewEd25519JWTIssuer()),
		sso.WithDefaultTokenStrategy("jwt"),
		sso.WithAuthCodeStore(defaultimpl.NewMemoryAuthCodeStore(), time.Minute),
	}
	for _, a := range auths {
		opts = append(opts, sso.WithAuthenticator(a))
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

func callbackGetNoFollow(t *testing.T, target string) *http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	return resp
}

func startCallbackFlow(t *testing.T, srv *httptest.Server, provider string) string {
	t.Helper()
	q := url.Values{
		"provider": {provider}, "client_id": {callbackClient},
		"response_type": {"code"}, "redirect_uri": {callbackRedirect},
		"state": {"rp-state"}, "scope": {"openid"},
	}
	resp := callbackGetNoFollow(t, srv.URL+"/auth/login?"+q.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("start callback flow = %d body=%s", resp.StatusCode, body)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || location.Query().Get("state") == "" {
		t.Fatalf("invalid upstream redirect: %q err=%v", resp.Header.Get("Location"), err)
	}
	return location.Query().Get("state")
}

func finishCallbackFlow(
	t *testing.T, srv *httptest.Server, state string, values url.Values,
) string {
	t.Helper()
	values.Set("state", state)
	resp := callbackGetNoFollow(t, srv.URL+"/auth/callback?"+values.Encode())
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("finish callback flow = %d body=%s", resp.StatusCode, body)
	}
	location, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || location.Scheme != "https" || location.Host != "login.example" {
		t.Fatalf("invalid hosted-login continuation: %q err=%v", resp.Header.Get("Location"), err)
	}
	fragment, err := url.ParseQuery(location.Fragment)
	if err != nil || fragment.Get("login_transaction_id") == "" {
		t.Fatalf("invalid continuation fragment: %q err=%v", location.Fragment, err)
	}
	return fragment.Get("login_transaction_id")
}

func resumeCallbackFlow(t *testing.T, srv *httptest.Server, transaction string) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(map[string]string{
		"client_id": callbackClient, "login_transaction_id": transaction,
	})
	resp, err := http.Post(srv.URL+"/auth/login", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("resume callback flow: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := map[string]any{}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func TestCallback_HappyPath_WithProviderQuery(t *testing.T) {
	auth := &callbackAuth{
		name: "oidc",
		want: "good-code",
		out:  &sso.AuthResult{UserID: "u-oidc-alice", ExternalID: "alice", Provider: "oidc"},
	}
	srv, _ := newCallbackHarness(t, auth)

	state := startCallbackFlow(t, srv, "oidc")
	transaction := finishCallbackFlow(t, srv, state, url.Values{
		"provider": {"oidc"}, "code": {"good-code"},
	})
	status, body := resumeCallbackFlow(t, srv, transaction)
	if status != http.StatusOK || body["code"] == nil || body["state"] != "rp-state" {
		t.Fatalf("resume = %d body=%v, want authorization code", status, body)
	}
}

func TestCallback_UnboundOrMissingState_400(t *testing.T) {
	auth := &callbackAuth{name: "oidc", out: &sso.AuthResult{UserID: "u"}}
	srv, _ := newCallbackHarness(t, auth)

	for _, q := range []string{
		"/auth/callback?state=xyz", // missing code
		"/auth/callback?code=x",    // missing state
		"/auth/callback",           // missing both
	} {
		resp, err := http.Get(srv.URL + q)
		if err != nil {
			t.Fatalf("GET %s: %v", q, err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("q=%q: status = %d, want 400", q, resp.StatusCode)
		}
		if body["error"] != "invalid_callback" {
			t.Errorf("q=%q: error = %v", q, body["error"])
		}
	}
}

func TestCallback_ProviderQueryTamperFailsClosed(t *testing.T) {
	auth := &callbackAuth{name: "oidc", out: &sso.AuthResult{UserID: "u"}}
	srv, _ := newCallbackHarness(t, auth)

	state := startCallbackFlow(t, srv, "oidc")
	transaction := finishCallbackFlow(t, srv, state, url.Values{
		"provider": {"saml"}, "code": {"x"},
	})
	status, body := resumeCallbackFlow(t, srv, transaction)
	if status != http.StatusUnauthorized || body["error"] != "callback_failed" {
		t.Fatalf("resume = %d body=%v, want callback_failed", status, body)
	}
}

func TestCallback_AuthenticatorReturnsError(t *testing.T) {
	auth := &callbackAuth{
		name: "oidc",
		err:  errors.New("token exchange failed at IdP"),
	}
	srv, sink := newCallbackHarness(t, auth)

	state := startCallbackFlow(t, srv, "oidc")
	transaction := finishCallbackFlow(t, srv, state, url.Values{
		"provider": {"oidc"}, "code": {"x"},
	})
	status, body := resumeCallbackFlow(t, srv, transaction)
	if status != http.StatusUnauthorized || body["error"] != "callback_failed" {
		t.Fatalf("resume = %d body=%v, want callback_failed", status, body)
	}
	// Failure should emit a callback_failure audit event.
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventCallbackFailure})
	if len(events) == 0 {
		t.Error("no callback_failure audit event recorded")
	}
}

func TestCallback_UsesStateBoundProviderWithoutQuery(t *testing.T) {
	// The provider query is optional because the server-issued state already
	// binds the callback to exactly one authenticator.
	good := &callbackAuth{name: "oidc", out: &sso.AuthResult{UserID: "u-discover"}}
	srv, _ := newCallbackHarness(t, good)

	state := startCallbackFlow(t, srv, "oidc")
	transaction := finishCallbackFlow(t, srv, state, url.Values{"code": {"x"}})
	status, body := resumeCallbackFlow(t, srv, transaction)
	if status != http.StatusOK || body["code"] == nil {
		t.Fatalf("resume = %d body=%v, want authorization code", status, body)
	}
}

// TestCallback_DeprovisionedUserBlocked proves that a federated callback for a
// user who has been SCIM-deprovisioned (active=false) returns 403 account_locked
// and does NOT create a session, even though the authenticator succeeded.
func TestCallback_DeprovisionedUserBlocked(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	_ = users.CreateOrUpdate(context.Background(), &sso.User{
		ID: "deprovisioned-alice",
		Attributes: map[string]string{
			"scim:active": "false",
		},
	})

	auth := &callbackAuth{
		name: "oidc",
		out:  &sso.AuthResult{UserID: "deprovisioned-alice", Provider: "oidc"},
	}
	hs, _ := newCallbackHarnessWithUsers(t, users, auth)

	state := startCallbackFlow(t, hs, "oidc")
	transaction := finishCallbackFlow(t, hs, state, url.Values{
		"provider": {"oidc"}, "code": {"x"},
	})
	status, body := resumeCallbackFlow(t, hs, transaction)
	if status != http.StatusForbidden || body["error"] != "account_locked" {
		t.Fatalf("resume = %d body=%v, want account_locked", status, body)
	}
}

func TestCallback_UnissuedStateDoesNotProbeAuthenticators(t *testing.T) {
	bad := &callbackAuth{name: "oidc", err: errors.New("nope")}
	srv, _ := newCallbackHarness(t, bad)

	resp, err := http.Get(srv.URL + "/auth/callback?code=x&state=oidc:slf.not-issued")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "invalid_callback" {
		t.Errorf("error = %v", body["error"])
	}
}
