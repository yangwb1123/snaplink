package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/memorystorecredential"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/admingovernance"
	"github.com/yangwb1123/snaplink/shared/core"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// TestIsGatedGRPCMethod_DiscoveryMutations verifies that the discovery write
// mutations (Register, Deregister) require admin auth, while the discovery
// read operations (Discover, Watch) remain open for service-discovery clients
// that do not hold admin tokens. The existing admin/audit/netpolicy prefix
// gates must not regress.
func TestIsGatedGRPCMethod_DiscoveryMutations(t *testing.T) {
	t.Parallel()
	gated := []string{
		// Discovery write mutations — the security fix.
		"/snaplink.discovery.v1.Discovery/Register",
		"/snaplink.discovery.v1.Discovery/Deregister",
		// Admin CRUD services — must remain gated.
		"/snaplink.admin.v1.UserAdminService/Delete",
		"/snaplink.admin.v1.ClientAdminService/Create",
		// Audit service — must remain gated.
		"/snaplink.audit.v1.AuditWriter/StreamEvents",
		// Netpolicy management — must remain gated.
		"/snaplink.netpolicy.v1.PolicyService/Apply",
	}
	for _, m := range gated {
		if !isGatedGRPCMethod(m) {
			t.Errorf("isGatedGRPCMethod(%q) = false, want true", m)
		}
	}

	open := []string{
		// Discovery read operations must remain open for service-mesh clients.
		"/snaplink.discovery.v1.Discovery/Discover",
		"/snaplink.discovery.v1.Discovery/Watch",
	}
	for _, m := range open {
		if isGatedGRPCMethod(m) {
			t.Errorf("isGatedGRPCMethod(%q) = true, want false", m)
		}
	}
}

// --- Admin governance framework: HTTPMiddleware transport-level checks ---
//
// These exercise the real end-to-end HTTP path (httptest.Server + a real
// Middleware), not just the pure domains/admingovernance helpers, so a wiring
// mistake in HTTPMiddleware itself (wrong order, wrong field) would be caught
// here.

// fakeValidator is a minimal TokenValidator test double: every token
// validates to the same fixed claims. Not a mock (no call-count assertions,
// no behavior verification) — a hand-written stub, the same shape as
// bgTestDeps in break_glass_test.go.
type fakeValidator struct {
	claims *core.TokenClaims
	err    error
}

func (f fakeValidator) ValidateToken(context.Context, string) (*core.TokenClaims, error) {
	return f.claims, f.err
}

// allowAllAuthorizer grants every admin-scope check — the tests below are
// about the governance checks that run BEFORE/AFTER authorization, not about
// authorization itself.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) HasAdminScope(context.Context, string, string, string) (bool, error) {
	return true, nil
}

// newTestMiddleware builds a Middleware with a fixed-subject validator and an
// allow-all authorizer, constructed directly (this test file is `package
// admin`) rather than through NewMiddleware, so no permissions.Provider fake
// is needed.
func newTestMiddleware(subject string) *Middleware {
	return &Middleware{
		validator:    fakeValidator{claims: &core.TokenClaims{Subject: subject}},
		authorizer:   allowAllAuthorizer{},
		methodScopes: defaultMethodScopes(),
	}
}

func TestHTTPMiddleware_WriteQuotaBlocksAfterLimit(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	mw.SetWriteQuota(admingovernance.NewMemoryWriteQuotaStore(), 1, time.Hour, "")
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	post := func() int {
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	if code := post(); code != http.StatusOK {
		t.Fatalf("first write = %d; want 200 (within quota)", code)
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Fatalf("second write = %d; want 429 (quota exhausted)", code)
	}

	// A GET (read) never consumes the write-only quota, so it must still
	// succeed even though the write budget is exhausted.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET after write-quota exhaustion = %d; want 200", resp.StatusCode)
	}
}

func TestHTTPMiddleware_DestructiveActionRequiresConfirm(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	mw.SetDestructiveActions(admingovernance.NewDestructiveSet([]admingovernance.DestructiveRule{
		{Method: http.MethodDelete, PathPrefix: "/api/v1/admin/tenants/", Action: "tenant_delete"},
	}))
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/tenants/acme", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE without confirm: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("DELETE without X-Confirm = %d; want 409", resp.StatusCode)
	}

	req2, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/tenants/acme", nil)
	req2.Header.Set("Authorization", "Bearer t")
	req2.Header.Set(HeaderConfirm, "true")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("DELETE with confirm: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("DELETE with X-Confirm=true = %d; want 200", resp2.StatusCode)
	}

	// An unrelated (non-destructive) path must be unaffected.
	req3, _ := http.NewRequest(http.MethodDelete, ts.URL+"/api/v1/admin/connections/abc", nil)
	req3.Header.Set("Authorization", "Bearer t")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("DELETE unrelated path: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("DELETE on a non-classified path = %d; want 200 (unaffected)", resp3.StatusCode)
	}
}

// clientIDAuthorizer grants one client scope and retains the ID it observed,
// exercising the claim selection performed by both admin transports.
type clientIDAuthorizer struct{ clientID string }

func (a *clientIDAuthorizer) HasAdminScope(_ context.Context, _, clientID, _ string) (bool, error) {
	a.clientID = clientID
	return clientID == "sso-admin-console", nil
}

func TestAdminAuthorizationUsesClientIDWithoutAudience(t *testing.T) {
	claims := &core.TokenClaims{Subject: "admin", ClientID: "sso-admin-console"}
	authorizer := &clientIDAuthorizer{}
	mw := &Middleware{
		validator:    fakeValidator{claims: claims},
		authorizer:   authorizer,
		methodScopes: defaultMethodScopes(),
	}

	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/endpoints", nil)
	req.Header.Set("Authorization", "Bearer token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("HTTP request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || authorizer.clientID != claims.ClientID {
		t.Fatalf("HTTP admin scope used client %q with status %d", authorizer.clientID, resp.StatusCode)
	}

	grpcCtx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer token"))
	actorCtx, err := mw.authorizeGRPC(grpcCtx, "/snaplink.admin.v1.UserAdminService/List")
	if err != nil {
		t.Fatalf("gRPC authorization: %v", err)
	}
	_, clientID, ok := ActorFromContext(actorCtx)
	if !ok || clientID != claims.ClientID || authorizer.clientID != claims.ClientID {
		t.Fatalf("gRPC admin scope used actor client %q and authorizer client %q", clientID, authorizer.clientID)
	}
}

func TestHTTPMiddleware_IPAllowlistDenies(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	// httptest's client always connects from 127.0.0.1; a CIDR that excludes
	// it must deny every request regardless of a valid bearer token.
	cfg, err := admingovernance.ParseIPAllowlistConfig([]string{"10.0.0.0/8"}, nil)
	if err != nil {
		t.Fatalf("ParseIPAllowlistConfig: %v", err)
	}
	mw.SetIPAllowlist(cfg, nil)
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET from a non-allowlisted IP = %d; want 403", resp.StatusCode)
	}
}

func TestHTTPMiddleware_IPAllowlistAllowsMatchingCIDR(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	cfg, err := admingovernance.ParseIPAllowlistConfig([]string{"127.0.0.1/32"}, nil)
	if err != nil {
		t.Fatalf("ParseIPAllowlistConfig: %v", err)
	}
	mw.SetIPAllowlist(cfg, nil)
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
	req.Header.Set("Authorization", "Bearer t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET from an allowlisted IP = %d; want 200", resp.StatusCode)
	}
}

// --- Admin-wide rate limit (SetRateLimit / SetRateLimitPolicyStore) ---

func TestHTTPMiddleware_RateLimitBlocksAfterBurst(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	mw.SetRateLimit(1, 1) // burst 1: first request OK, second immediately blocked
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	get := func() (int, string) {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode, resp.Header.Get("Retry-After")
	}
	if code, _ := get(); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200 (within burst)", code)
	}
	code, retryAfter := get()
	if code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429 (burst exhausted)", code)
	}
	if retryAfter == "" {
		t.Error("expected a non-empty Retry-After header on 429")
	}
}

// TestHTTPMiddleware_RateLimitPolicyStoreHotSwap proves SetRateLimitPolicyStore
// wires a SHARED store: swapping its Policy (as a SIGHUP config reload would)
// takes effect on the admin gate immediately, without reconstructing the
// Middleware.
func TestHTTPMiddleware_RateLimitPolicyStoreHotSwap(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	store := ratelimit.NewPolicyStore(ratelimit.Policy{Default: ratelimit.NewMemoryLimiter(1, 1)})
	mw.SetRateLimitPolicyStore(store)
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	get := func() int {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}
	if code := get(); code != http.StatusOK {
		t.Fatalf("first request = %d, want 200 (within burst=1)", code)
	}
	if code := get(); code != http.StatusTooManyRequests {
		t.Fatalf("second request = %d, want 429 (burst=1 exhausted)", code)
	}

	// Hot-swap to a much larger burst — simulating a SIGHUP config reload —
	// without touching mw at all.
	store.Set(ratelimit.Policy{Default: ratelimit.NewMemoryLimiter(1000, 1000)})
	if code := get(); code != http.StatusOK {
		t.Fatalf("request after hot-swap = %d, want 200 (new policy has ample burst)", code)
	}
}

// TestHTTPMiddleware_RateLimitUnwiredIsUnlimited proves neither SetRateLimit
// nor SetRateLimitPolicyStore ever being called is byte-identical to a build
// without the feature.
func TestHTTPMiddleware_RateLimitUnwiredIsUnlimited(t *testing.T) {
	mw := newTestMiddleware("admin-1")
	ts := httptest.NewServer(mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	defer ts.Close()

	for i := 0; i < 20; i++ {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/admin/connections", nil)
		req.Header.Set("Authorization", "Bearer t")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %d = %d, want 200 (unlimited when unwired)", i, resp.StatusCode)
		}
	}
}

type failingAuditSink struct{ *audit.MemorySink }

func (failingAuditSink) Record(context.Context, *audit.Event) error { return errors.New("sink failed") }

type errorAuthorizer struct{}

func (errorAuthorizer) HasAdminScope(context.Context, string, string, string) (bool, error) {
	return false, errors.New("authorizer failed")
}
func adminAuthResponse(mw *Middleware, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/admin/connections", nil)
	r.RemoteAddr = "198.51.100.7:1234"
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	mw.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })).ServeHTTP(w, r)
	return w
}
func adminEvents(t *testing.T, sink *audit.MemorySink, typ audit.EventType) []*audit.Event {
	got, _ := sink.Query(context.Background(), audit.Query{Type: typ})
	return got
}
func sameAdminResponse(a, b *httptest.ResponseRecorder) bool {
	return a.Code == b.Code && a.Body.String() == b.Body.String() && reflect.DeepEqual(a.Header(), b.Header())
}
func TestHTTPMiddleware_AuthDenialsAudited(t *testing.T) {
	cases := []struct {
		name, auth, reason, actor, client string
		claims                            *core.TokenClaims
		validationErr                     error
		authorizer                        Authorizer
		expired                           bool
		status                            int
	}{
		{name: "missing", reason: "missing_token", status: http.StatusUnauthorized, authorizer: allowAllAuthorizer{}},
		{name: "invalid", auth: "Bearer bad", reason: "invalid_token", status: http.StatusUnauthorized, validationErr: errors.New("bad"), claims: &core.TokenClaims{Subject: "untrusted", ClientID: "untrusted"}, authorizer: allowAllAuthorizer{}},
		{name: "forbidden", auth: "Bearer good", reason: "forbidden", actor: "user-1", client: "client-audience", status: http.StatusForbidden, claims: &core.TokenClaims{Subject: "user-1", ClientID: "client-fallback", Audience: []string{"client-audience"}}, authorizer: &clientIDAuthorizer{clientID: "other"}},
		{name: "expired", auth: "Bearer good", reason: "session_expired", actor: "user-1", client: "client-audience", status: http.StatusUnauthorized, claims: &core.TokenClaims{Subject: "user-1", ClientID: "client-fallback", Audience: []string{"client-audience"}, JTI: "jti-expired"}, authorizer: allowAllAuthorizer{}, expired: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			makeMW := func(rec *audit.Recorder) *Middleware {
				mw := &Middleware{validator: fakeValidator{claims: tc.claims, err: tc.validationErr}, authorizer: tc.authorizer, methodScopes: defaultMethodScopes()}
				if tc.expired {
					store := memorystorecredential.NewMemoryAdminTokenStore()
					_ = store.Record(context.Background(), core.AdminToken{ID: "jti-expired", LastUsedAt: time.Now().Add(-time.Hour)})
					mw.SetAdminTokenStore(store)
					mw.SetAdminSessionTTL(time.Minute)
				}
				mw.SetAuditRecorder(rec)
				return mw
			}
			plain := adminAuthResponse(makeMW(nil), tc.auth)
			sink := audit.NewMemorySink(8)
			got := adminAuthResponse(makeMW(audit.New(sink)), tc.auth)
			if !sameAdminResponse(got, plain) || got.Code != tc.status {
				t.Fatalf("response drift: got %#v/%q, plain %#v/%q", got.Header(), got.Body.String(), plain.Header(), plain.Body.String())
			}
			events := adminEvents(t, sink, audit.EventAdminAuthDenied)
			if len(events) != 1 {
				t.Fatalf("auth denial events = %d, want exactly 1", len(events))
			}
			e := events[0]
			if e.Type != audit.EventAdminAuthDenied || e.Outcome != audit.OutcomeFailure || e.ActorIP != "198.51.100.7" || e.ActorID != tc.actor || e.ClientID != tc.client || e.Reason != tc.reason {
				t.Fatalf("event = %+v", e)
			}
			if len(e.Metadata) != 3 || e.Metadata["method"] != http.MethodGet || e.Metadata["path"] != "/api/v1/admin/connections" || e.Metadata["reason"] != tc.reason {
				t.Fatalf("metadata = %#v", e.Metadata)
			}
		})
	}
}
func TestHTTPMiddleware_AuthDenialAuditFailOpenAndExcluded(t *testing.T) {
	base := adminAuthResponse(newTestMiddleware("admin"), "")
	for _, rec := range []*audit.Recorder{nil, audit.New(&failingAuditSink{})} {
		mw := newTestMiddleware("admin")
		mw.SetAuditRecorder(rec)
		if !sameAdminResponse(adminAuthResponse(mw, ""), base) {
			t.Fatal("audit recorder changed missing-token response")
		}
	}
	sink := audit.NewMemorySink(8)
	checks := []struct {
		mw     *Middleware
		status int
	}{{&Middleware{authorizer: allowAllAuthorizer{}, methodScopes: defaultMethodScopes()}, http.StatusServiceUnavailable}, {&Middleware{validator: fakeValidator{claims: &core.TokenClaims{Subject: "user"}}, authorizer: errorAuthorizer{}, methodScopes: defaultMethodScopes()}, http.StatusInternalServerError}}
	for _, check := range checks {
		check.mw.SetAuditRecorder(audit.New(sink))
		if got := adminAuthResponse(check.mw, "Bearer token"); got.Code != check.status {
			t.Fatalf("status = %d, want %d", got.Code, check.status)
		}
	}
	if got := adminEvents(t, sink, audit.EventAdminAuthDenied); len(got) != 0 {
		t.Fatalf("excluded branches recorded %d auth denials", len(got))
	}
}

func TestAdminAuthDenialAuditTransportParity(t *testing.T) {
	cases := []struct {
		name, auth    string
		claims        *core.TokenClaims
		validationErr error
		authorizer    Authorizer
	}{{name: "no token", authorizer: allowAllAuthorizer{}}, {name: "invalid token", auth: "Bearer bad", claims: &core.TokenClaims{Subject: "bad"}, validationErr: errors.New("bad"), authorizer: allowAllAuthorizer{}}, {name: "no scope", auth: "Bearer good", claims: &core.TokenClaims{Subject: "user", ClientID: "client"}, authorizer: &clientIDAuthorizer{clientID: "other"}}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			makeMW := func(rec *audit.Recorder) *Middleware {
				mw := &Middleware{validator: fakeValidator{claims: tc.claims, err: tc.validationErr}, authorizer: tc.authorizer, methodScopes: defaultMethodScopes()}
				mw.SetAuditRecorder(rec)
				return mw
			}
			hs := audit.NewMemorySink(8)
			if got := adminAuthResponse(makeMW(audit.New(hs)), tc.auth); got.Code < 400 {
				t.Fatalf("HTTP status = %d", got.Code)
			}
			gs := audit.NewMemorySink(8)
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", tc.auth))
			_, err := makeMW(audit.New(gs)).UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/snaplink.admin.v1.UserAdminService/Get"}, func(context.Context, any) (any, error) { return nil, nil })
			if err == nil {
				t.Fatal("gRPC denial returned nil error")
			}
			if got := adminEvents(t, hs, audit.EventAdminAuthDenied); len(got) != 1 {
				t.Fatalf("HTTP auth events = %d", len(got))
			}
			if got := adminEvents(t, gs, audit.EventAdminGRPCCalled); len(got) != 1 || got[0].Outcome != audit.OutcomeFailure {
				t.Fatalf("gRPC denial events = %+v", got)
			}
		})
	}
}
