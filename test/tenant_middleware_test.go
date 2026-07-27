package ssotest

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// stubTenantStore lets specific tests drive errors / latency
// without standing up a real backing store.
type stubTenantStore struct {
	getDomainErr error
	getTenantErr error
	delay        time.Duration
	domain       *tenant.Domain
	tenant       *tenant.Tenant
	hostSeen     string
}

func (s *stubTenantStore) GetTenant(ctx context.Context, _ string) (*tenant.Tenant, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.getTenantErr != nil {
		return nil, s.getTenantErr
	}
	return s.tenant, nil
}
func (s *stubTenantStore) GetDomain(ctx context.Context, host string) (*tenant.Domain, error) {
	s.hostSeen = host
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.getDomainErr != nil {
		return nil, s.getDomainErr
	}
	return s.domain, nil
}
func (s *stubTenantStore) ListTenants(context.Context) ([]*tenant.Tenant, error) { return nil, nil }
func (s *stubTenantStore) PutTenant(context.Context, *tenant.Tenant) error       { return nil }
func (s *stubTenantStore) DeleteTenant(context.Context, string) error            { return nil }
func (s *stubTenantStore) ListDomains(context.Context) ([]*tenant.Domain, error) { return nil, nil }
func (s *stubTenantStore) ListDomainsByTenant(context.Context, string) ([]*tenant.Domain, error) {
	return nil, nil
}
func (s *stubTenantStore) PutDomain(context.Context, *tenant.Domain) error { return nil }
func (s *stubTenantStore) DeleteDomain(context.Context, string) error      { return nil }
func (s *stubTenantStore) Close() error                                    { return nil }

func newTenantCtx(t *testing.T, host string) sso.HandlerContext {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = host
	rec := httptest.NewRecorder()
	return sso.NewContext(rec, r)
}

func makeTenantStore(t *testing.T, hostname, tenantID string) *tenantmemory.Store {
	t.Helper()
	store := tenantmemory.New()
	ctx := context.Background()
	if err := store.PutTenant(ctx, &tenant.Tenant{ID: tenantID, Slug: tenantID, Name: tenantID}); err != nil {
		t.Fatalf("PutTenant: %v", err)
	}
	if err := store.PutDomain(ctx, &tenant.Domain{Hostname: hostname, TenantID: tenantID}); err != nil {
		t.Fatalf("PutDomain: %v", err)
	}
	return store
}

func TestTenantMiddleware_PopulatesContext(t *testing.T) {
	store := makeTenantStore(t, "acme.com", "t-acme")
	mw := sso.TenantMiddleware(store, sso.TenantMiddlewareOptions{})
	hctx := newTenantCtx(t, "acme.com")
	mw(hctx)
	r, ok := sso.TenantFromHandlerContext(hctx)
	if !ok {
		t.Fatal("FromHandlerContext returned !ok")
	}
	if r.Tenant.ID != "t-acme" {
		t.Errorf("tenant id=%q", r.Tenant.ID)
	}
	if r.Domain.Hostname != "acme.com" {
		t.Errorf("domain host=%q", r.Domain.Hostname)
	}
}

func TestTenantMiddleware_StripsPort(t *testing.T) {
	store := makeTenantStore(t, "acme.com", "t-acme")
	mw := sso.TenantMiddleware(store, sso.TenantMiddlewareOptions{})
	hctx := newTenantCtx(t, "acme.com:8443")
	mw(hctx)
	if _, ok := sso.TenantFromHandlerContext(hctx); !ok {
		t.Fatal("port-stripped lookup failed")
	}
}

func TestTenantMiddleware_HonorsXForwardedHost(t *testing.T) {
	store := makeTenantStore(t, "portal.acme.com", "t-acme")
	mw := sso.TenantMiddleware(store, sso.TenantMiddlewareOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "internal-load-balancer:8080"
	r.Header.Set("X-Forwarded-Host", "portal.acme.com, edge-2")
	rec := httptest.NewRecorder()
	hctx := sso.NewContext(rec, r)
	mw(hctx)
	if _, ok := sso.TenantFromHandlerContext(hctx); !ok {
		t.Fatal("XFH first-hop did not resolve")
	}
}

func TestTenantMiddleware_UnknownHostLeavesContextEmpty(t *testing.T) {
	store := makeTenantStore(t, "acme.com", "t-acme")
	mw := sso.TenantMiddleware(store, sso.TenantMiddlewareOptions{})
	hctx := newTenantCtx(t, "ghost.example")
	mw(hctx)
	if _, ok := sso.TenantFromHandlerContext(hctx); ok {
		t.Error("unknown host should leave context empty")
	}
}

func TestTenantMiddleware_NilStoreIsNoop(t *testing.T) {
	mw := sso.TenantMiddleware(nil, sso.TenantMiddlewareOptions{})
	hctx := newTenantCtx(t, "acme.com")
	mw(hctx) // should not panic
	if _, ok := sso.TenantFromHandlerContext(hctx); ok {
		t.Error("nil store populated context")
	}
}

func TestTenantMiddleware_EmptyHostSkipsLookup(t *testing.T) {
	stub := &stubTenantStore{
		domain: &tenant.Domain{Hostname: "x", TenantID: "t1"},
		tenant: &tenant.Tenant{ID: "t1", Slug: "t1", Status: tenant.StatusActive},
	}
	mw := sso.TenantMiddleware(stub, sso.TenantMiddlewareOptions{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = ""
	rec := httptest.NewRecorder()
	mw(sso.NewContext(rec, r))
	if stub.hostSeen != "" {
		t.Errorf("GetDomain called with host=%q despite empty Host", stub.hostSeen)
	}
}

func TestTenantMiddleware_SuspendedTenantHidden(t *testing.T) {
	stub := &stubTenantStore{
		domain: &tenant.Domain{Hostname: "acme.com", TenantID: "t1"},
		tenant: &tenant.Tenant{ID: "t1", Slug: "acme", Status: tenant.StatusSuspended},
	}
	mw := sso.TenantMiddleware(stub, sso.TenantMiddlewareOptions{})
	hctx := newTenantCtx(t, "acme.com")
	mw(hctx)
	if _, ok := sso.TenantFromHandlerContext(hctx); ok {
		t.Error("suspended tenant exposed without IncludeSuspended")
	}
}

func TestTenantMiddleware_SuspendedTenantVisibleWhenOptedIn(t *testing.T) {
	stub := &stubTenantStore{
		domain: &tenant.Domain{Hostname: "acme.com", TenantID: "t1"},
		tenant: &tenant.Tenant{ID: "t1", Slug: "acme", Status: tenant.StatusSuspended},
	}
	mw := sso.TenantMiddleware(stub, sso.TenantMiddlewareOptions{IncludeSuspended: true})
	hctx := newTenantCtx(t, "acme.com")
	mw(hctx)
	r, ok := sso.TenantFromHandlerContext(hctx)
	if !ok {
		t.Fatal("opt-in failed")
	}
	if r.Tenant.Status != tenant.StatusSuspended {
		t.Errorf("status=%q", r.Tenant.Status)
	}
}

func TestTenantMiddleware_BackendErrorFiresOnError(t *testing.T) {
	wantErr := errors.New("db down")
	stub := &stubTenantStore{getDomainErr: wantErr}
	var captured error
	mw := sso.TenantMiddleware(stub, sso.TenantMiddlewareOptions{
		OnError: func(err error) { captured = err },
	})
	mw(newTenantCtx(t, "acme.com"))
	if !errors.Is(captured, wantErr) {
		t.Errorf("OnError captured %v", captured)
	}
}

func TestTenantMiddleware_NotFoundDoesNotFireOnError(t *testing.T) {
	stub := &stubTenantStore{getDomainErr: tenant.ErrDomainNotFound}
	var captured error
	mw := sso.TenantMiddleware(stub, sso.TenantMiddlewareOptions{
		OnError: func(err error) { captured = err },
	})
	mw(newTenantCtx(t, "ghost.example"))
	if captured != nil {
		t.Errorf("ErrDomainNotFound should not fire OnError; got %v", captured)
	}
}

func TestTenantMiddleware_DanglingDomainFiresOnError(t *testing.T) {
	// Domain row exists but tenant is gone — the cascade-on-delete
	// should prevent this in memory backend, but stricter backends
	// (e.g., eventual-consistency SQL replicas) might surface it.
	stub := &stubTenantStore{
		domain:       &tenant.Domain{Hostname: "acme.com", TenantID: "t-gone"},
		getTenantErr: errors.New("connection reset"),
	}
	var captured error
	mw := sso.TenantMiddleware(stub, sso.TenantMiddlewareOptions{
		OnError: func(err error) { captured = err },
	})
	mw(newTenantCtx(t, "acme.com"))
	if captured == nil {
		t.Error("OnError should fire for tenant lookup failure")
	}
}

func TestTenantMiddleware_TimeoutBoundsLookup(t *testing.T) {
	// Stub honors ctx (like a real SQL backend would), so the
	// timeout actually preempts. Lookup is bounded to 10ms even
	// though the stub would otherwise block 500ms.
	stub := &stubTenantStore{
		delay:  500 * time.Millisecond,
		domain: &tenant.Domain{Hostname: "acme.com", TenantID: "t1"},
		tenant: &tenant.Tenant{ID: "t1", Slug: "acme", Status: tenant.StatusActive},
	}
	mw := sso.TenantMiddleware(stub, sso.TenantMiddlewareOptions{Timeout: 10 * time.Millisecond})
	start := time.Now()
	mw(newTenantCtx(t, "acme.com"))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("middleware blocked %v despite 10ms timeout", elapsed)
	}
}

func TestDefaultHostExtractor_HostHeader(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "acme.com:8443"
	if got := sso.DefaultHostExtractor(r); got != "acme.com" {
		t.Errorf("got %q", got)
	}
}

func TestDefaultHostExtractor_XForwardedHostFirstHop(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "internal:8080"
	r.Header.Set("X-Forwarded-Host", "portal.acme.com, edge2")
	if got := sso.DefaultHostExtractor(r); got != "portal.acme.com" {
		t.Errorf("got %q", got)
	}
}

func TestDefaultHostExtractor_IPv6(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "[2001:db8::1]:8443"
	if got := sso.DefaultHostExtractor(r); got != "2001:db8::1" {
		t.Errorf("got %q", got)
	}
}

func TestDefaultHostExtractor_NoPort(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "acme.com"
	if got := sso.DefaultHostExtractor(r); got != "acme.com" {
		t.Errorf("got %q", got)
	}
}

// --- Audit enrichment integration tests ---

// stubTenantAuthenticator is local to this file so we don't collide
// with stubAuthenticator from geo_login_test.go. Same shape.
type stubTenantAuthenticator struct {
	name   string
	result *sso.AuthResult
}

func (s *stubTenantAuthenticator) Name() string             { return s.name }
func (s *stubTenantAuthenticator) LoginURL(_ string) string { return "" }
func (s *stubTenantAuthenticator) Authenticate(_ context.Context, _ *sso.AuthRequest) (*sso.AuthResult, error) {
	cp := *s.result
	return &cp, nil
}
func (s *stubTenantAuthenticator) Callback(_ context.Context, _ *sso.CallbackState) (*sso.AuthResult, error) {
	cp := *s.result
	return &cp, nil
}

func tenantAuditFixture(t *testing.T, store tenant.Store) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		AllowedAuthenticators: []string{"stub"},
		TokenStrategy:         sso.TokenStrategySession,
	})
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(&stubTenantAuthenticator{
			name:   "stub",
			result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
		}),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithAuditRecorder(rec),
		sso.WithTenantStore(store),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sink
}

func TestAudit_TenantEnrichment_LoginCarriesTenant(t *testing.T) {
	store := makeTenantStore(t, "acme.com", "t-acme")
	ts, sink := tenantAuditFixture(t, store)

	// httptest's URL is 127.0.0.1; we need Host=acme.com to drive
	// the tenant resolution. Build the request manually.
	tsURL := ts.URL
	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", tsURL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "acme.com"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()

	events, _ := sink.Query(context.Background(), audit.Query{Limit: 10})
	var login *audit.Event
	for _, e := range events {
		if e.Type == audit.EventLogin {
			login = e
			break
		}
	}
	if login == nil {
		t.Fatalf("no login event recorded; got %d events", len(events))
	}
	want := map[string]string{
		"tenant.id":     "t-acme",
		"tenant.slug":   "t-acme",
		"tenant.domain": "acme.com",
	}
	for k, v := range want {
		if got := login.Metadata[k]; got != v {
			t.Errorf("Metadata[%q]=%q want %q (full meta=%v)", k, got, v, login.Metadata)
		}
	}
}

func TestAudit_TenantEnrichment_NilStoreOmitsKeys(t *testing.T) {
	ts, sink := tenantAuditFixture(t, nil) // no store
	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "acme.com"
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	events, _ := sink.Query(context.Background(), audit.Query{Limit: 10})
	for _, e := range events {
		for k := range e.Metadata {
			if strings.HasPrefix(k, "tenant.") {
				t.Errorf("event %q carries tenant.* metadata despite nil store: %v", e.Type, e.Metadata)
			}
		}
	}
}

func TestAudit_TenantEnrichment_UnknownHostOmitsKeys(t *testing.T) {
	store := makeTenantStore(t, "acme.com", "t-acme")
	ts, sink := tenantAuditFixture(t, store)
	body := `{"provider":"stub","client_id":"web-app","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "ghost.example"
	resp, _ := http.DefaultClient.Do(req)
	_ = resp.Body.Close()

	events, _ := sink.Query(context.Background(), audit.Query{Limit: 10})
	for _, e := range events {
		for k := range e.Metadata {
			if strings.HasPrefix(k, "tenant.") {
				t.Errorf("unknown host enriched: %v", e.Metadata)
			}
		}
	}
}

// --- Tenant ↔ Client mismatch enforcement ---

// tenantClientFixture is like tenantAuditFixture but lets the
// caller customize the seeded Client (specifically Client.TenantID).
func tenantClientFixture(t *testing.T, store tenant.Store, client *sso.Client) (*httptest.Server, *audit.MemorySink) {
	t.Helper()
	clients := defaultimpl.NewMemoryClientStore()
	clients.AddSeed(client)
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	srv := sso.NewServer(
		sso.WithRouter(sso.NewStdRouter()),
		sso.WithAuthenticator(&stubTenantAuthenticator{
			name:   "stub",
			result: &sso.AuthResult{UserID: "user-alice", Provider: "stub"},
		}),
		sso.WithClientStore(clients),
		sso.WithUserProvider(defaultimpl.NewMemoryUserProvider()),
		sso.WithSessionManager(defaultimpl.NewMemorySessionManager(0)),
		sso.WithTokenIssuer(sso.TokenStrategySession, defaultimpl.NewSessionTokenIssuer()),
		sso.WithAuditRecorder(rec),
		sso.WithTenantStore(store),
	)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, sink
}

func loginWithHost(t *testing.T, ts *httptest.Server, host, clientID string) *http.Response {
	t.Helper()
	body := `{"provider":"stub","client_id":"` + clientID + `","credential":{"u":"alice"}}`
	req, _ := http.NewRequest("POST", ts.URL+"/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = host
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	return resp
}

func TestLogin_TenantMatchSucceeds(t *testing.T) {
	store := makeTenantStore(t, "acme.com", "t-acme")
	client := &sso.Client{
		ID: "acme-portal", TenantID: "t-acme", Active: true,
		AllowedAuthenticators: []string{"stub"},
		TokenStrategy:         sso.TokenStrategySession,
	}
	ts, _ := tenantClientFixture(t, store, client)

	resp := loginWithHost(t, ts, "acme.com", "acme-portal")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("status=%d, want 200", resp.StatusCode)
	}
}

func TestLogin_TenantMismatchRejected(t *testing.T) {
	// Two tenants registered; client belongs to t-acme; request
	// arrives via beta.io (resolves to t-beta). Should 403.
	store := tenantmemory.New()
	ctx := context.Background()
	for _, id := range []string{"t-acme", "t-beta"} {
		_ = store.PutTenant(ctx, &tenant.Tenant{ID: id, Slug: id, Name: id})
	}
	_ = store.PutDomain(ctx, &tenant.Domain{Hostname: "acme.com", TenantID: "t-acme"})
	_ = store.PutDomain(ctx, &tenant.Domain{Hostname: "beta.io", TenantID: "t-beta"})

	client := &sso.Client{
		ID: "acme-portal", TenantID: "t-acme", Active: true,
		AllowedAuthenticators: []string{"stub"},
		TokenStrategy:         sso.TokenStrategySession,
	}
	ts, sink := tenantClientFixture(t, store, client)

	resp := loginWithHost(t, ts, "beta.io", "acme-portal")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 403 {
		t.Errorf("status=%d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), sso.ErrTenantMismatch) {
		t.Errorf("body missing %q: %s", sso.ErrTenantMismatch, body)
	}
	// Should produce a login_failure audit event with reason
	// = ErrTenantMismatch.
	events, _ := sink.Query(ctx, audit.Query{Limit: 10})
	var found bool
	for _, e := range events {
		if e.Type == audit.EventLoginFailure && e.Reason == sso.ErrTenantMismatch {
			found = true
		}
	}
	if !found {
		t.Errorf("no tenant_mismatch login_failure event recorded; events=%+v", events)
	}
}

func TestLogin_EmptyClientTenantIDAllowsAnyHost(t *testing.T) {
	// "Platform admin" client with no TenantID — backward-compat
	// shape for single-tenant deployments. Should serve from any
	// resolved tenant context.
	store := makeTenantStore(t, "acme.com", "t-acme")
	client := &sso.Client{
		ID: "platform", TenantID: "", Active: true,
		AllowedAuthenticators: []string{"stub"},
		TokenStrategy:         sso.TokenStrategySession,
	}
	ts, _ := tenantClientFixture(t, store, client)

	resp := loginWithHost(t, ts, "acme.com", "platform")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("empty-TenantID client rejected from acme.com: status=%d", resp.StatusCode)
	}
}

func TestLogin_NoTenantContextAllowsClientWithTenantID(t *testing.T) {
	// Tenant store wired but request comes via ghost.example
	// (no resolved tenant). Don't 403 — pre-multi-tenant
	// deployments enabling a tenant store shouldn't suddenly
	// break every existing client.
	store := makeTenantStore(t, "acme.com", "t-acme")
	client := &sso.Client{
		ID: "acme-portal", TenantID: "t-acme", Active: true,
		AllowedAuthenticators: []string{"stub"},
		TokenStrategy:         sso.TokenStrategySession,
	}
	ts, _ := tenantClientFixture(t, store, client)

	resp := loginWithHost(t, ts, "ghost.example", "acme-portal")
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Errorf("no-resolved-tenant rejected: status=%d", resp.StatusCode)
	}
}

// --- compile-time sanity that stubTenantStore satisfies the interface ---

var _ tenant.Store = (*stubTenantStore)(nil)
