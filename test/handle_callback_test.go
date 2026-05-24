package ssotest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/defaultimpl"
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
func (c *callbackAuth) LoginURL(string) string { return "" }

func newCallbackHarness(t *testing.T, auths ...sso.Authenticator) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	opts := []sso.Option{
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager()),
		sso.WithAuditRecorder(rec),
	}
	for _, a := range auths {
		opts = append(opts, sso.WithAuthenticator(a))
	}

	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv, sink
}

func TestCallback_HappyPath_WithProviderQuery(t *testing.T) {
	auth := &callbackAuth{
		name: "oidc",
		want: "good-code",
		out:  &sso.AuthResult{UserID: "u-oidc-alice", ExternalID: "alice", Provider: "oidc"},
	}
	srv, _ := newCallbackHarness(t, auth)

	resp, err := http.Get(srv.URL + "/auth/callback?provider=oidc&code=good-code&state=xyz")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d body=%s", resp.StatusCode, body)
	}

	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["status"] != "authenticated" {
		t.Errorf("status = %v", body["status"])
	}
	if sid, _ := body["session_id"].(string); sid == "" {
		t.Errorf("missing session_id in %v", body)
	}
}

func TestCallback_MissingCodeOrState_400(t *testing.T) {
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
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("q=%q: status = %d, want 400", q, resp.StatusCode)
		}
		if body["error"] != "invalid_callback" {
			t.Errorf("q=%q: error = %v", q, body["error"])
		}
	}
}

func TestCallback_UnknownProviderQuery(t *testing.T) {
	auth := &callbackAuth{name: "oidc", out: &sso.AuthResult{UserID: "u"}}
	srv, _ := newCallbackHarness(t, auth)

	resp, err := http.Get(srv.URL + "/auth/callback?provider=saml&code=x&state=y")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "unknown_provider" {
		t.Errorf("error = %v", body["error"])
	}
}

func TestCallback_AuthenticatorReturnsError(t *testing.T) {
	auth := &callbackAuth{
		name: "oidc",
		err:  errors.New("token exchange failed at IdP"),
	}
	srv, sink := newCallbackHarness(t, auth)

	resp, err := http.Get(srv.URL + "/auth/callback?provider=oidc&code=x&state=y")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "callback_failed" {
		t.Errorf("error = %v", body["error"])
	}
	// Failure should emit a callback_failure audit event.
	events, _ := sink.Query(context.Background(), audit.Query{Type: audit.EventCallbackFailure})
	if len(events) == 0 {
		t.Error("no callback_failure audit event recorded")
	}
}

func TestCallback_AutoDiscoverProvider(t *testing.T) {
	// No ?provider query — handler iterates authenticators and picks the
	// first one whose Callback succeeds.
	good := &callbackAuth{name: "oidc", out: &sso.AuthResult{UserID: "u-discover"}}
	srv, _ := newCallbackHarness(t, good)

	resp, err := http.Get(srv.URL + "/auth/callback?code=x&state=y")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("status = %d body=%s", resp.StatusCode, body)
	}
}

func TestCallback_AutoDiscover_NoCandidateMatches(t *testing.T) {
	// All authenticators reject — handler reports unknown_provider.
	bad := &callbackAuth{name: "oidc", err: errors.New("nope")}
	srv, _ := newCallbackHarness(t, bad)

	resp, err := http.Get(srv.URL + "/auth/callback?code=x&state=y")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", resp.StatusCode)
	}
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if body["error"] != "unknown_provider" {
		t.Errorf("error = %v", body["error"])
	}
}
