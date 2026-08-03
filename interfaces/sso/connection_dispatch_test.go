package sso_test

// connection_dispatch_test.go exercises the enterprise-connections RUNTIME
// dispatch on /auth/login (WithConnectionStore + WithConnectionAuthenticator-
// Factory): provider=<connection id> routes through the factory-built upstream
// authenticator, a statically-registered provider name always shadows a
// same-named connection, and every connection miss (unknown / disabled /
// cross-tenant / build failure) collapses to the byte-identical
// unsupported_provider response an unknown provider gets (anti-enumeration).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

const (
	cdClientID = "cd-client"
	cdHostA    = "acme.test"
	cdHostB    = "bigco.test"
	cdTenantA  = "t-acme"
	cdTenantB  = "t-bigco"

	cdConnOkta     = "conn-okta"     // tenant A, enabled, valid config
	cdConnDisabled = "conn-disabled" // tenant A, disabled
	cdConnOther    = "conn-other"    // tenant B, enabled, valid config
	cdConnBroken   = "conn-broken"   // tenant A, enabled, config missing a required key

	cdAuthzA = "https://idp.acme.test/authorize"
	cdAuthzB = "https://idp.bigco.test/authorize"
)

// cdFactory is a minimal in-test connections.AuthenticatorFactory. The
// production implementation lives in cmd/sso-server/serverbuildauthn, which
// nothing outside cmd/ may import (layer direction), so this mirrors its OIDC
// Config mapping onto the REAL authenticators.NewOIDCFederationAuthenticator
// — only the cmd-owned caching/audit wrapper is substituted. Call counts let
// tests prove which paths never reach the factory (shadowing, tenant guard).
type cdFactory struct {
	mu    sync.Mutex
	calls map[string]int
}

var _ connections.AuthenticatorFactory = (*cdFactory)(nil)

func (f *cdFactory) AuthenticatorFor(_ context.Context, c *connections.Connection) (sso.Authenticator, error) {
	f.mu.Lock()
	f.calls[c.ID]++
	f.mu.Unlock()
	if c.Type != connections.TypeOIDC {
		return nil, connections.ErrConnectionTypeUnsupported
	}
	return authenticators.NewOIDCFederationAuthenticator(authenticators.OIDCFederationConfig{
		Name:                  c.ID,
		AuthorizationEndpoint: c.Config[connections.ConfigKeyOIDCAuthorizationEndpoint],
		TokenEndpoint:         c.Config[connections.ConfigKeyOIDCTokenEndpoint],
		ClientID:              c.Config[connections.ConfigKeyOIDCClientID],
		ClientSecret:          c.Config[connections.ConfigKeyOIDCClientSecret],
		RedirectURI:           c.Config[connections.ConfigKeyOIDCRedirectURI],
	})
}

func (f *cdFactory) count(id string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[id]
}

func cdConnection(id, tenantID, authzEndpoint string) *connections.Connection {
	return &connections.Connection{
		ID:       id,
		TenantID: tenantID,
		Type:     connections.TypeOIDC,
		Enabled:  true,
		Config: map[string]string{
			connections.ConfigKeyOIDCAuthorizationEndpoint: authzEndpoint,
			connections.ConfigKeyOIDCTokenEndpoint:         "https://idp.example.test/token",
			connections.ConfigKeyOIDCClientID:              "upstream-client",
			connections.ConfigKeyOIDCClientSecret:          "upstream-secret",
			connections.ConfigKeyOIDCRedirectURI:           "https://sso.example.test/auth/callback",
		},
	}
}

func cdSeedConnections(t *testing.T) *connections.MemoryStore {
	t.Helper()
	conns := connections.NewMemoryStore()
	disabled := cdConnection(cdConnDisabled, cdTenantA, cdAuthzA)
	disabled.Enabled = false
	broken := cdConnection(cdConnBroken, cdTenantA, cdAuthzA)
	delete(broken.Config, connections.ConfigKeyOIDCClientSecret)
	seed := []*connections.Connection{
		cdConnection(cdConnOkta, cdTenantA, cdAuthzA),
		cdConnection(cdConnOther, cdTenantB, cdAuthzB),
		// Same id as the static password provider: MUST be shadowed by it.
		cdConnection(authenticators.MethodPassword, cdTenantA, cdAuthzA),
		disabled,
		broken,
	}
	for _, c := range seed {
		if err := conns.Upsert(context.Background(), c); err != nil {
			t.Fatalf("Upsert(%s): %v", c.ID, err)
		}
	}
	return conns
}

func cdSeedTenants(t *testing.T) *tenantmemory.Store {
	t.Helper()
	tenants := tenantmemory.New()
	for host, id := range map[string]string{cdHostA: cdTenantA, cdHostB: cdTenantB} {
		if err := tenants.PutTenant(context.Background(), &tenant.Tenant{ID: id, Slug: id, Name: id}); err != nil {
			t.Fatalf("PutTenant(%s): %v", id, err)
		}
		if err := tenants.PutDomain(context.Background(), &tenant.Domain{Hostname: host, TenantID: id}); err != nil {
			t.Fatalf("PutDomain(%s): %v", host, err)
		}
	}
	return tenants
}

// newCDServer wires a server with a static password authenticator PLUS the
// connection store + factory, multi-tenant host routing, and just enough
// identity plumbing for a static login to mint (session strategy).
func newCDServer(t *testing.T) (*httptest.Server, *cdFactory) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	// TenantID left empty: a platform client is servable under both tenant
	// hosts, so the tenant middleware's client gate never interferes with the
	// connection-level guard under test.
	clients.AddSeed(&sso.Client{
		ID:            cdClientID,
		Name:          "Connection Dispatch",
		Active:        true,
		TokenStrategy: sso.TokenStrategySession,
		RedirectURIs:  []string{"https://rp.example.test/callback"},
		LoginPageURI:  "https://login.example.test/authorize",
	})
	pw := authenticators.NewPasswordAuthenticator(authenticators.PasswordVerifierFunc(
		func(_ context.Context, u, p string) (*sso.AuthResult, error) {
			if u == "alice" && p == "pw" {
				return &sso.AuthResult{UserID: "user-alice", AuthMethods: []string{"pwd"}}, nil
			}
			return nil, errors.New("bad credentials")
		},
	))
	factory := &cdFactory{calls: map[string]int{}}
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(pw),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithTenantStore(cdSeedTenants(t)),
		sso.WithConnectionStore(cdSeedConnections(t)),
		sso.WithConnectionAuthenticatorFactory(factory),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, factory
}

// cdLogin POSTs /auth/login under the given tenant host WITHOUT following the
// upstream redirect, returning the raw status/headers/body for byte-level
// comparison.
func cdLogin(t *testing.T, ts *httptest.Server, host, provider, state string) (int, http.Header, []byte) {
	t.Helper()
	payload := map[string]any{
		"provider":   provider,
		"client_id":  cdClientID,
		"credential": map[string]string{"username": "alice", "password": "pw"},
		"state":      state,
	}
	if provider != authenticators.MethodPassword {
		payload["response_type"] = "code"
		payload["redirect_uri"] = "https://rp.example.test/callback"
	}
	raw, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/auth/login", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /auth/login provider=%s: %v", provider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, resp.Header, body
}

func TestConnectionDispatch_EnabledConnectionRedirectsUpstream(t *testing.T) {
	t.Parallel()
	ts, factory := newCDServer(t)

	status, hdr, body := cdLogin(t, ts, cdHostA, cdConnOkta, "st-conn")
	if status != http.StatusFound {
		t.Fatalf("status = %d body=%s, want 302 upstream redirect", status, body)
	}
	loc := hdr.Get("Location")
	if !strings.HasPrefix(loc, cdAuthzA+"?") {
		t.Errorf("Location = %q, want the connection's authorization endpoint", loc)
	}
	for _, want := range []string{"client_id=upstream-client"} {
		if !strings.Contains(loc, want) {
			t.Errorf("Location %q missing %q", loc, want)
		}
	}
	parsed, err := url.Parse(loc)
	if err != nil || !strings.HasPrefix(parsed.Query().Get("state"), cdConnOkta+":slf.") {
		t.Errorf("Location %q did not carry server-issued state", loc)
	}
	// /auth/login is a credential endpoint even on the federated redirect leg.
	if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if got := factory.count(cdConnOkta); got != 1 {
		t.Errorf("factory calls for %s = %d, want 1", cdConnOkta, got)
	}
}

func TestConnectionDispatch_StaticProviderShadowsSameNamedConnection(t *testing.T) {
	t.Parallel()
	ts, factory := newCDServer(t)

	status, hdr, body := cdLogin(t, ts, cdHostA, authenticators.MethodPassword, "")
	if status != http.StatusOK {
		t.Fatalf("status = %d body=%s, want 200 from the static authenticator", status, body)
	}
	if loc := hdr.Get("Location"); loc != "" {
		t.Errorf("Location = %q, want no upstream redirect for a shadowed connection id", loc)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal body %s: %v", body, err)
	}
	if out["error"] != nil || out["access_token"] == nil {
		t.Errorf("static login body = %s, want minted tokens", body)
	}
	// The registered name wins BEFORE the connection path runs at all.
	if got := factory.count(authenticators.MethodPassword); got != 0 {
		t.Errorf("factory calls for shadowed id = %d, want 0", got)
	}
}

// TestConnectionDispatch_AntiEnumerationByteIdentical proves a probe cannot
// distinguish "no such provider", "no such connection", "disabled",
// "belongs to another tenant", and "misconfigured" — the full wire response
// (status + body bytes + content type) is identical for all five.
func TestConnectionDispatch_AntiEnumerationByteIdentical(t *testing.T) {
	t.Parallel()
	ts, factory := newCDServer(t)

	cases := []string{"no-such-provider", "conn-ghost", cdConnDisabled, cdConnOther, cdConnBroken}
	var wantStatus int
	var wantCT string
	var wantBody []byte
	for i, provider := range cases {
		status, hdr, body := cdLogin(t, ts, cdHostA, provider, "st-anti")
		if i == 0 {
			wantStatus, wantCT, wantBody = status, hdr.Get("Content-Type"), body
			if status != http.StatusBadRequest {
				t.Fatalf("baseline status = %d body=%s, want 400", status, body)
			}
			if !bytes.Contains(body, []byte(`"unsupported_provider"`)) {
				t.Fatalf("baseline body = %s, want unsupported_provider", body)
			}
			continue
		}
		if status != wantStatus {
			t.Errorf("provider=%s status = %d, want %d", provider, status, wantStatus)
		}
		if ct := hdr.Get("Content-Type"); ct != wantCT {
			t.Errorf("provider=%s Content-Type = %q, want %q", provider, ct, wantCT)
		}
		if !bytes.Equal(body, wantBody) {
			t.Errorf("provider=%s body = %s, want byte-identical to unknown provider %s", provider, body, wantBody)
		}
	}
	// The disabled and cross-tenant refusals happen BEFORE the factory runs:
	// existence of those connections must not even be probed via a build.
	if got := factory.count(cdConnDisabled); got != 0 {
		t.Errorf("factory calls for disabled connection = %d, want 0", got)
	}
	if got := factory.count(cdConnOther); got != 0 {
		t.Errorf("factory calls for cross-tenant connection = %d, want 0", got)
	}
	// The broken connection DID reach the factory (server-side signal only).
	if got := factory.count(cdConnBroken); got != 1 {
		t.Errorf("factory calls for broken connection = %d, want 1", got)
	}
}

// TestConnectionDispatch_CrossTenantGuardIsHostScoped is the positive control
// for the guard: the SAME connection that collapses to unsupported_provider
// under tenant A's host dispatches normally under its own tenant's host.
func TestConnectionDispatch_CrossTenantGuardIsHostScoped(t *testing.T) {
	t.Parallel()
	ts, _ := newCDServer(t)

	status, hdr, body := cdLogin(t, ts, cdHostB, cdConnOther, "st-b")
	if status != http.StatusFound {
		t.Fatalf("own-tenant host status = %d body=%s, want 302", status, body)
	}
	if loc := hdr.Get("Location"); !strings.HasPrefix(loc, cdAuthzB+"?") {
		t.Errorf("Location = %q, want tenant B's authorization endpoint", loc)
	}

	status, _, body = cdLogin(t, ts, cdHostA, cdConnOther, "st-b")
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte(`"unsupported_provider"`)) {
		t.Errorf("cross-tenant host status = %d body=%s, want 400 unsupported_provider", status, body)
	}
}

// cdCallback GETs /auth/callback under the given tenant host, returning the raw
// status + body for byte-level comparison. The callback is the SECOND leg of
// the federated flow (the upstream IdP redirects the browser back here with
// provider=<connection id>), so the cross-tenant guard and anti-enumeration
// collapse must hold here exactly as on the /auth/login leg.
func cdCallback(t *testing.T, ts *httptest.Server, host, provider string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet,
		ts.URL+"/auth/callback?provider="+provider+"&code=upstream-code&state=st-cb", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = host
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /auth/callback provider=%s: %v", provider, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp.StatusCode, body
}

// TestConnectionDispatch_CallbackCrossTenantGuard proves legacy provider-only
// callbacks cannot probe either nonexistent or cross-tenant connections.
func TestConnectionDispatch_CallbackCrossTenantGuard(t *testing.T) {
	t.Parallel()
	ts, factory := newCDServer(t)

	// Baseline: a nonexistent provider on the callback leg.
	baseStatus, baseBody := cdCallback(t, ts, cdHostA, "no-such-provider")
	if baseStatus != http.StatusBadRequest {
		t.Fatalf("baseline callback status = %d body=%s, want 400", baseStatus, baseBody)
	}
	if !bytes.Contains(baseBody, []byte(`"invalid_callback"`)) {
		t.Fatalf("baseline callback body = %s, want invalid_callback", baseBody)
	}

	// cdConnOther belongs to tenant B; a callback for it under tenant A's host
	// must be byte-identical to the nonexistent-provider baseline.
	xtStatus, xtBody := cdCallback(t, ts, cdHostA, cdConnOther)
	if xtStatus != baseStatus || !bytes.Equal(xtBody, baseBody) {
		t.Errorf("cross-tenant callback = %d %s, want byte-identical to unknown provider %d %s",
			xtStatus, xtBody, baseStatus, baseBody)
	}
	// The guard fires BEFORE the factory: a cross-tenant connection's existence
	// is never probed via a build on the callback leg either.
	if got := factory.count(cdConnOther); got != 0 {
		t.Errorf("factory calls for cross-tenant connection on callback = %d, want 0", got)
	}
}
