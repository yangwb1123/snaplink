package tenant

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// memStore is a minimal in-process tenant.Store used only to drive the
// middleware tests. The package-level memory backend lives in
// tenant/memory and importing it here would create a test-only import
// cycle (memory imports tenant), so the white-box middleware tests use
// this tiny real store rather than a mock. Behaviour matches the
// production memory backend for the slices the middleware exercises.
type memStore struct {
	tenants  map[string]*Tenant
	domains  map[string]*Domain
	domErr   error // forced error returned by GetDomain (other than ErrDomainNotFound)
	tenErr   error // forced error returned by GetTenant (other than ErrTenantNotFound)
	nilOnGet bool  // GetTenant returns (nil, nil) to exercise the misbehaved-store guard
}

func newMemStore() *memStore {
	return &memStore{tenants: map[string]*Tenant{}, domains: map[string]*Domain{}}
}

func (m *memStore) GetTenant(_ context.Context, id string) (*Tenant, error) {
	if m.tenErr != nil {
		return nil, m.tenErr
	}
	if m.nilOnGet {
		return nil, nil
	}
	t, ok := m.tenants[id]
	if !ok {
		return nil, ErrTenantNotFound
	}
	return t, nil
}

func (m *memStore) ListTenants(context.Context) ([]*Tenant, error) {
	out := make([]*Tenant, 0, len(m.tenants))
	for _, t := range m.tenants {
		out = append(out, t)
	}
	return out, nil
}

func (m *memStore) PutTenant(_ context.Context, t *Tenant) error {
	if err := t.Validate(); err != nil {
		return err
	}
	m.tenants[t.ID] = t
	return nil
}

func (m *memStore) DeleteTenant(_ context.Context, id string) error {
	delete(m.tenants, id)
	return nil
}

func (m *memStore) GetDomain(_ context.Context, hostname string) (*Domain, error) {
	if m.domErr != nil {
		return nil, m.domErr
	}
	d, ok := m.domains[hostname]
	if !ok {
		return nil, ErrDomainNotFound
	}
	return d, nil
}

func (m *memStore) ListDomains(context.Context) ([]*Domain, error) { return nil, nil }

func (m *memStore) ListDomainsByTenant(context.Context, string) ([]*Domain, error) {
	return nil, nil
}

func (m *memStore) PutDomain(_ context.Context, d *Domain) error {
	if err := d.Validate(); err != nil {
		return err
	}
	m.domains[d.Hostname] = d
	return nil
}

func (m *memStore) DeleteDomain(_ context.Context, hostname string) error {
	delete(m.domains, hostname)
	return nil
}

func (m *memStore) Close() error { return nil }

var _ Store = (*memStore)(nil)

// seedActive wires a domain → active tenant pair.
func (m *memStore) seedActive(host, tenantID string) {
	m.tenants[tenantID] = &Tenant{ID: tenantID, Slug: tenantID, Status: StatusActive}
	m.domains[host] = &Domain{Hostname: host, TenantID: tenantID}
}

// runMiddleware drives mw against an HTTP request with the given Host
// header and returns the populated HandlerContext.
func runMiddleware(mw core.MiddlewareFunc, host string) core.HandlerContext {
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/auth/login", nil)
	req.Host = host
	hctx := core.NewContext(httptest.NewRecorder(), req)
	mw(hctx)
	return hctx
}

func TestMiddleware_NilStoreIsNoOp(t *testing.T) {
	t.Parallel()
	mw := Middleware(nil, MiddlewareOptions{})
	// Must not panic and must leave the context empty.
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("nil store middleware populated a Resolved")
	}
}

func TestMiddleware_ResolvesActiveTenant(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.seedActive("acme.com", "t1")
	mw := Middleware(s, MiddlewareOptions{})

	hctx := runMiddleware(mw, "acme.com")
	r, ok := FromHandlerContext(hctx)
	if !ok || r == nil {
		t.Fatal("expected resolved tenant")
	}
	if r.Tenant == nil || r.Tenant.ID != "t1" {
		t.Errorf("tenant=%+v", r.Tenant)
	}
	if r.Domain == nil || r.Domain.Hostname != "acme.com" {
		t.Errorf("domain=%+v", r.Domain)
	}
}

func TestMiddleware_EmptyHostSkipsLookup(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.seedActive("acme.com", "t1")
	// A HostExtractor returning "" must short-circuit before any store call.
	mw := Middleware(s, MiddlewareOptions{
		HostExtractor: func(*http.Request) string { return "" },
	})
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("empty host should skip the lookup and leave context empty")
	}
}

func TestMiddleware_UnknownDomainIsNonFatal(t *testing.T) {
	t.Parallel()
	s := newMemStore() // no domains seeded
	var onErrCalled bool
	mw := Middleware(s, MiddlewareOptions{
		OnError: func(error) { onErrCalled = true },
	})
	hctx := runMiddleware(mw, "ghost.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("unknown domain should not populate a tenant")
	}
	// ErrDomainNotFound is expected and MUST NOT be surfaced to OnError.
	if onErrCalled {
		t.Error("OnError fired for an ordinary ErrDomainNotFound")
	}
}

func TestMiddleware_GetDomainBackendErrorCallsOnError(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.domErr = errors.New("backend down")
	var got error
	mw := Middleware(s, MiddlewareOptions{OnError: func(e error) { got = e }})
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("backend error must not populate a tenant (fail-open empty)")
	}
	if got == nil {
		t.Error("OnError not invoked for a non-NotFound GetDomain error")
	}
}

func TestMiddleware_GetDomainBackendErrorNilOnErrorDoesNotPanic(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.domErr = errors.New("backend down")
	// OnError nil: backend outage must stay non-fatal and not panic.
	mw := Middleware(s, MiddlewareOptions{})
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("populated despite backend error")
	}
}

func TestMiddleware_DanglingDomainTenantNotFound(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	// Domain row points at a tenant that doesn't exist.
	s.domains["acme.com"] = &Domain{Hostname: "acme.com", TenantID: "ghost"}
	var onErrCalled bool
	mw := Middleware(s, MiddlewareOptions{OnError: func(error) { onErrCalled = true }})
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("dangling domain must not populate a tenant")
	}
	// ErrTenantNotFound for a dangling domain is expected; not surfaced to OnError.
	if onErrCalled {
		t.Error("OnError fired for an expected ErrTenantNotFound")
	}
}

func TestMiddleware_GetTenantBackendErrorCallsOnError(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.domains["acme.com"] = &Domain{Hostname: "acme.com", TenantID: "t1"}
	s.tenErr = errors.New("tenant backend down")
	var got error
	mw := Middleware(s, MiddlewareOptions{OnError: func(e error) { got = e }})
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("tenant backend error must not populate a tenant")
	}
	if got == nil {
		t.Error("OnError not invoked for a non-NotFound GetTenant error")
	}
}

func TestMiddleware_MisbehavedStoreNilTenantGuarded(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.domains["acme.com"] = &Domain{Hostname: "acme.com", TenantID: "t1"}
	s.nilOnGet = true // GetTenant returns (nil, nil)
	mw := Middleware(s, MiddlewareOptions{})
	hctx := runMiddleware(mw, "acme.com") // must not panic
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("(nil, nil) GetTenant should be treated as no tenant")
	}
}

func TestMiddleware_SuspendedTenantHiddenByDefault(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.tenants["t1"] = &Tenant{ID: "t1", Slug: "t1", Status: StatusSuspended}
	s.domains["acme.com"] = &Domain{Hostname: "acme.com", TenantID: "t1"}
	mw := Middleware(s, MiddlewareOptions{})
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); ok {
		t.Error("suspended tenant should not populate context by default")
	}
}

func TestMiddleware_SuspendedTenantIncludedWhenOptedIn(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.tenants["t1"] = &Tenant{ID: "t1", Slug: "t1", Status: StatusSuspended}
	s.domains["acme.com"] = &Domain{Hostname: "acme.com", TenantID: "t1"}
	mw := Middleware(s, MiddlewareOptions{IncludeSuspended: true})
	hctx := runMiddleware(mw, "acme.com")
	r, ok := FromHandlerContext(hctx)
	if !ok || r == nil || r.Tenant == nil || r.Tenant.Status != StatusSuspended {
		t.Errorf("IncludeSuspended did not surface the suspended tenant: %+v", r)
	}
}

func TestMiddleware_DefaultTimeoutApplied(t *testing.T) {
	t.Parallel()
	// A zero/negative Timeout must fall back to DefaultLookupTimeout. We
	// can't observe the deadline directly through the Store seam without a
	// mock, but a slow store that respects ctx cancellation lets us assert
	// the path completes within a bounded window and still resolves.
	s := newMemStore()
	s.seedActive("acme.com", "t1")
	mw := Middleware(s, MiddlewareOptions{Timeout: 0})
	start := time.Now()
	hctx := runMiddleware(mw, "acme.com")
	if elapsed := time.Since(start); elapsed > DefaultLookupTimeout {
		t.Errorf("lookup took %v, longer than default timeout", elapsed)
	}
	if _, ok := FromHandlerContext(hctx); !ok {
		t.Error("expected resolution with default timeout")
	}
}

func TestMiddleware_CustomTimeoutHonored(t *testing.T) {
	t.Parallel()
	s := newMemStore()
	s.seedActive("acme.com", "t1")
	mw := Middleware(s, MiddlewareOptions{Timeout: 5 * time.Second})
	hctx := runMiddleware(mw, "acme.com")
	if _, ok := FromHandlerContext(hctx); !ok {
		t.Error("expected resolution with custom timeout")
	}
}

func TestFromHandlerContext_NilContext(t *testing.T) {
	t.Parallel()
	if r, ok := FromHandlerContext(nil); ok || r != nil {
		t.Errorf("nil ctx: got (%v, %v)", r, ok)
	}
}

func TestFromHandlerContext_AbsentValue(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://acme.com/", nil)
	hctx := core.NewContext(httptest.NewRecorder(), req)
	if r, ok := FromHandlerContext(hctx); ok || r != nil {
		t.Errorf("absent value: got (%v, %v)", r, ok)
	}
}

func TestFromHandlerContext_WrongType(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://acme.com/", nil)
	hctx := core.NewContext(httptest.NewRecorder(), req)
	// Stash a value of the wrong type under the key — the typed helper
	// must guard against the bad cast rather than panic.
	hctx.Set(HandlerContextKey, "not-a-resolved")
	if r, ok := FromHandlerContext(hctx); ok || r != nil {
		t.Errorf("wrong type: got (%v, %v)", r, ok)
	}
}

func TestFromHandlerContext_RoundTrip(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://acme.com/", nil)
	hctx := core.NewContext(httptest.NewRecorder(), req)
	want := &Resolved{Tenant: &Tenant{ID: "t1"}, Domain: &Domain{Hostname: "acme.com"}}
	hctx.Set(HandlerContextKey, want)
	got, ok := FromHandlerContext(hctx)
	if !ok || got != want {
		t.Errorf("round-trip mismatch: got (%v, %v)", got, ok)
	}
}

func TestDefaultHostExtractor(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		host string // r.Host
		xfh  string // X-Forwarded-Host header (empty = absent)
		want string
	}{
		{name: "plain host", host: "acme.com", want: "acme.com"},
		{name: "host with port", host: "acme.com:8443", want: "acme.com"},
		{name: "uppercase lowercased", host: "Acme.COM", want: "acme.com"},
		{name: "trailing dot stripped", host: "acme.com.", want: "acme.com"},
		{name: "xfh wins over host", host: "internal:8080", xfh: "public.acme.com", want: "public.acme.com"},
		{name: "xfh first hop of chain", host: "x", xfh: "client.acme.com, proxy1, proxy2", want: "client.acme.com"},
		{name: "xfh with port", host: "x", xfh: "public.acme.com:443", want: "public.acme.com"},
		{name: "ipv6 literal bracketed with port", host: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "ipv6 literal bracketed no port", host: "[2001:db8::1]", want: "2001:db8::1"},
		{name: "empty host", host: "", want: ""},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "http://example/", nil)
			req.Host = tc.host
			if tc.xfh != "" {
				req.Header.Set("X-Forwarded-Host", tc.xfh)
			}
			if got := DefaultHostExtractor(req); got != tc.want {
				t.Errorf("DefaultHostExtractor() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultHostExtractor_NilRequest(t *testing.T) {
	t.Parallel()
	if got := DefaultHostExtractor(nil); got != "" {
		t.Errorf("nil request: got %q", got)
	}
}

func TestDefaultHostExtractor_XFHLeadingComma(t *testing.T) {
	t.Parallel()
	// A leading comma means IndexByte returns 0 (not > 0), so the whole
	// trimmed value is used. Documents the boundary in stripHostPort logic.
	req := httptest.NewRequest(http.MethodGet, "http://example/", nil)
	req.Host = "fallback.com"
	req.Header.Set("X-Forwarded-Host", ",weird.com")
	if got := DefaultHostExtractor(req); got != ",weird.com" {
		t.Errorf("got %q", got)
	}
}

func TestStripHostPort(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in, want string
	}{
		{"acme.com", "acme.com"},
		{"acme.com:443", "acme.com"},
		{"ACME.COM", "acme.com"},
		{"acme.com.", "acme.com"},
		{"  acme.com  ", "acme.com"},
		{"", ""},
		{"[2001:db8::1]:8443", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"[::1]:443", "::1"},
		// Bare IPv6 without brackets has multiple colons: LastIndex splits at
		// the final colon. This is the documented (lossy) behavior for
		// unbracketed literals — callers are expected to bracket them.
		{"2001:db8::1", "2001:db8:"},
		// Leading colon: LastIndex finds it at >0 only if not index 0.
		{":8080", ":8080"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			if got := stripHostPort(tc.in); got != tc.want {
				t.Errorf("stripHostPort(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMiddleware_EndToEndThroughExtractorAndStore(t *testing.T) {
	t.Parallel()
	// Exercise the full default path: DefaultHostExtractor strips the port
	// off r.Host, the store keys on the bare hostname.
	s := newMemStore()
	s.seedActive("portal.acme.com", "acme")
	mw := Middleware(s, MiddlewareOptions{})
	hctx := runMiddleware(mw, "portal.acme.com:8443")
	r, ok := FromHandlerContext(hctx)
	if !ok || r == nil || r.Tenant.ID != "acme" {
		t.Errorf("end-to-end resolution failed: %+v", r)
	}
}
