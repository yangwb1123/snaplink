package core

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContextParamAndQuery(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/users/42?filter=active&empty=", nil)
	rec := httptest.NewRecorder()
	ctx := NewContext(rec, req)
	ctx.params["id"] = "42"

	if got := ctx.Param("id"); got != "42" {
		t.Errorf("Param(id) = %q, want 42", got)
	}
	// Unknown param returns the zero value, never panics.
	if got := ctx.Param("missing"); got != "" {
		t.Errorf("Param(missing) = %q, want empty", got)
	}
	if got := ctx.Query("filter"); got != "active" {
		t.Errorf("Query(filter) = %q, want active", got)
	}
	if got := ctx.Query("empty"); got != "" {
		t.Errorf("Query(empty) = %q, want empty", got)
	}
	if got := ctx.Query("absent"); got != "" {
		t.Errorf("Query(absent) = %q, want empty", got)
	}
}

func TestContextRequestAndResponseWriter(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	ctx := NewContext(rec, req)

	if ctx.Request() != req {
		t.Error("Request() did not return the wrapped *http.Request")
	}
	if ctx.ResponseWriter() != rec {
		t.Error("ResponseWriter() did not return the wrapped http.ResponseWriter")
	}
}

func TestContextBind(t *testing.T) {
	t.Parallel()

	body := `{"name":"acme","count":3}`
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	ctx := NewContext(httptest.NewRecorder(), req)

	var out struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	if err := ctx.Bind(&out); err != nil {
		t.Fatalf("Bind() error = %v", err)
	}
	if out.Name != "acme" || out.Count != 3 {
		t.Errorf("Bind() = %+v, want {acme 3}", out)
	}
}

func TestContextBindInvalidJSON(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("{not json"))
	ctx := NewContext(httptest.NewRecorder(), req)

	var out map[string]any
	if err := ctx.Bind(&out); err == nil {
		t.Error("Bind() on malformed JSON should return an error")
	}
}

func TestContextJSON(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	ctx := NewContext(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	ctx.JSON(http.StatusTeapot, map[string]string{"hello": "world"})

	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if ct := rec.Header().Get(HeaderContentType); ct != ContentTypeJSON {
		t.Errorf("Content-Type = %q, want %q", ct, ContentTypeJSON)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != `{"hello":"world"}` {
		t.Errorf("body = %q, want %q", body, `{"hello":"world"}`)
	}
}

func TestContextRedirect(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	ctx := NewContext(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	ctx.Redirect(http.StatusFound, "https://example.com/next")

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if loc := rec.Header().Get("Location"); loc != "https://example.com/next" {
		t.Errorf("Location = %q, want https://example.com/next", loc)
	}
}

func TestContextSetGet(t *testing.T) {
	t.Parallel()

	ctx := NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	if v := ctx.Get("absent"); v != nil {
		t.Errorf("Get(absent) = %v, want nil", v)
	}

	ctx.Set("user", "alice")
	if v := ctx.Get("user"); v != "alice" {
		t.Errorf("Get(user) = %v, want alice", v)
	}

	// Overwrite replaces the prior value.
	ctx.Set("user", "bob")
	if v := ctx.Get("user"); v != "bob" {
		t.Errorf("Get(user) after overwrite = %v, want bob", v)
	}
}

func TestStdRouterMethodsDispatch(t *testing.T) {
	t.Parallel()

	methods := []struct {
		name     string
		register func(r *StdRouter, path string, h HandlerFunc)
		method   string
	}{
		{"GET", (*StdRouter).GET, http.MethodGet},
		{"POST", (*StdRouter).POST, http.MethodPost},
		{"PUT", (*StdRouter).PUT, http.MethodPut},
		{"PATCH", (*StdRouter).PATCH, http.MethodPatch},
		{"DELETE", (*StdRouter).DELETE, http.MethodDelete},
	}

	for _, m := range methods {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			r := NewStdRouter()
			called := false
			m.register(r, "/resource", func(ctx HandlerContext) {
				called = true
				ctx.JSON(http.StatusOK, map[string]string{"ok": "1"})
			})

			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(m.method, "/resource", nil))

			if !called {
				t.Fatalf("%s handler not invoked", m.name)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("%s status = %d, want 200", m.name, rec.Code)
			}
		})
	}
}

func TestStdRouterMethodMismatchFallsThrough(t *testing.T) {
	t.Parallel()

	r := NewStdRouter()
	r.GET("/only-get", func(ctx HandlerContext) {
		ctx.JSON(http.StatusOK, nil)
	})

	// A POST to a GET-only route matches no route → 404.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/only-get", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("method mismatch status = %d, want 404", rec.Code)
	}
}

func TestStdRouterNotFound(t *testing.T) {
	t.Parallel()

	r := NewStdRouter()
	r.GET("/known", func(ctx HandlerContext) {})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/unknown", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown path status = %d, want 404", rec.Code)
	}
}

func TestStdRouterPathParam(t *testing.T) {
	t.Parallel()

	r := NewStdRouter()
	var gotID string
	r.GET("/clients/:id", func(ctx HandlerContext) {
		gotID = ctx.Param("id")
		ctx.JSON(http.StatusOK, nil)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/clients/abc123", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotID != "abc123" {
		t.Errorf("extracted param = %q, want abc123", gotID)
	}
}

func TestStdRouterMultipleParams(t *testing.T) {
	t.Parallel()

	r := NewStdRouter()
	var tenant, user string
	r.GET("/tenants/:tid/users/:uid", func(ctx HandlerContext) {
		tenant = ctx.Param("tid")
		user = ctx.Param("uid")
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tenants/acme/users/u-7", nil))

	if tenant != "acme" || user != "u-7" {
		t.Errorf("params = (%q, %q), want (acme, u-7)", tenant, user)
	}
}

func TestStdRouterSegmentCountMismatch(t *testing.T) {
	t.Parallel()

	r := NewStdRouter()
	r.GET("/clients/:id", func(ctx HandlerContext) {
		ctx.JSON(http.StatusOK, nil)
	})

	// Extra trailing segment must NOT match the single-param pattern.
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/clients/abc/extra", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("extra segment status = %d, want 404", rec.Code)
	}
}

func TestStdRouterMiddlewareRunsInOrder(t *testing.T) {
	t.Parallel()

	r := NewStdRouter()
	var order []string
	r.Use(func(ctx HandlerContext) { order = append(order, "global") })
	r.GET("/x", func(ctx HandlerContext) {
		order = append(order, "handler")
		ctx.JSON(http.StatusOK, nil)
	})

	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))

	if len(order) != 2 || order[0] != "global" || order[1] != "handler" {
		t.Errorf("execution order = %v, want [global handler]", order)
	}
}

func TestStdRouterGroupPrefixAndMiddleware(t *testing.T) {
	t.Parallel()

	root := NewStdRouter()
	var seen []string
	root.Use(func(ctx HandlerContext) { seen = append(seen, "root-mw") })

	api := root.Group("/api/v1", func(ctx HandlerContext) { seen = append(seen, "group-mw") })
	var hit string
	api.GET("/clients/:id", func(ctx HandlerContext) {
		hit = ctx.Param("id")
		seen = append(seen, "handler")
	})

	// Group registrations are visible from the root's shared route table.
	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/clients/c9", nil))

	if hit != "c9" {
		t.Errorf("group param = %q, want c9", hit)
	}
	// Both the root and group middleware run, in order, before the handler.
	if len(seen) != 3 || seen[0] != "root-mw" || seen[1] != "group-mw" || seen[2] != "handler" {
		t.Errorf("group execution order = %v, want [root-mw group-mw handler]", seen)
	}
}

func TestStdRouterNestedGroups(t *testing.T) {
	t.Parallel()

	root := NewStdRouter()
	outer := root.Group("/api")
	inner := outer.Group("/v1")
	hit := false
	inner.GET("/ping", func(ctx HandlerContext) {
		hit = true
		ctx.JSON(http.StatusOK, nil)
	})

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil))
	if !hit {
		t.Error("nested group route /api/v1/ping not dispatched")
	}
}

func TestStdRouterBuildPathNormalization(t *testing.T) {
	t.Parallel()

	r := NewStdRouter()

	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"/", ""},
		{"health", "/health"},
		{"/health", "/health"},
		{"/api/v1", "/api/v1"},
	}
	for _, tc := range tests {
		if got := r.buildPath(tc.in); got != tc.want {
			t.Errorf("buildPath(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestStdRouterRootGroupNoPrefix(t *testing.T) {
	t.Parallel()

	root := NewStdRouter()
	// Group("/") contributes no prefix (buildPath collapses "/" to "").
	grp := root.Group("/")
	hit := false
	grp.GET("/bare", func(ctx HandlerContext) {
		hit = true
		ctx.JSON(http.StatusOK, nil)
	})

	rec := httptest.NewRecorder()
	root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/bare", nil))
	if !hit {
		t.Error("route under Group(\"/\") not reachable at /bare")
	}
}

func TestMatchPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pattern string
		actual  string
		want    bool
	}{
		{"exact", "/health", "/health", true},
		{"exact mismatch", "/health", "/livez", false},
		{"param matches", "/users/:id", "/users/7", true},
		{"length mismatch short", "/users/:id", "/users", false},
		{"length mismatch long", "/users/:id", "/users/7/roles", false},
		{"literal middle mismatch", "/a/b/c", "/a/x/c", false},
		{"param in middle", "/a/:b/c", "/a/anything/c", true},
		{"root", "/", "/", true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := matchPath(tc.pattern, tc.actual); got != tc.want {
				t.Errorf("matchPath(%q, %q) = %v, want %v", tc.pattern, tc.actual, got, tc.want)
			}
		})
	}
}

func TestExtractParams(t *testing.T) {
	t.Parallel()

	ctx := NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	extractParams(ctx, "/tenants/:tid/users/:uid", "/tenants/acme/users/u9")

	if ctx.params["tid"] != "acme" {
		t.Errorf("params[tid] = %q, want acme", ctx.params["tid"])
	}
	if ctx.params["uid"] != "u9" {
		t.Errorf("params[uid] = %q, want u9", ctx.params["uid"])
	}

	// A pattern with no params leaves the map empty.
	ctx2 := NewContext(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	extractParams(ctx2, "/health", "/health")
	if len(ctx2.params) != 0 {
		t.Errorf("params = %v, want empty for param-less pattern", ctx2.params)
	}
}

// Interface guards: the concrete std types satisfy the framework-agnostic seams
// the SSO server programs against. A signature drift breaks the build here
// rather than at every consumer call site.
var (
	_ HandlerContext = (*Context)(nil)
	_ Router         = (*StdRouter)(nil)
	_ Router         = (*GatedRouter)(nil)
)

// TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404 is the
// package-local proof of GatedRouter's core claim (interfaces/sso's
// mountAdminSurface is the motivating caller): the SAME registered route
// answers normally while live() is true and answers BYTE-IDENTICALLY to a
// path that was never registered at all while live() is false — no
// re-registration, just a boolean flip.
func TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404(t *testing.T) {
	t.Parallel()

	live := true
	root := NewStdRouter()
	gated := NewGatedRouter(root.Group("/api"), func() bool { return live })
	gated.GET("/widgets", func(ctx HandlerContext) { ctx.JSON(http.StatusOK, map[string]bool{"ok": true}) })

	doGet := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	if rec := doGet("/api/widgets"); rec.Code != http.StatusOK {
		t.Fatalf("GET /api/widgets while live = %d, want 200", rec.Code)
	}

	// The baseline: a path NEVER registered on this router at all.
	baseline := doGet("/api/never-registered")
	if baseline.Code != http.StatusNotFound {
		t.Fatalf("baseline status = %d, want 404 (sanity check on the test itself)", baseline.Code)
	}

	live = false
	got := doGet("/api/widgets")
	if got.Code != baseline.Code {
		t.Errorf("status while gated off = %d, want %d (byte-identical to never-registered)", got.Code, baseline.Code)
	}
	if got.Body.String() != baseline.Body.String() {
		t.Errorf("body while gated off = %q, want %q", got.Body.String(), baseline.Body.String())
	}
	if ct := got.Header().Get("Content-Type"); ct != baseline.Header().Get("Content-Type") {
		t.Errorf("Content-Type while gated off = %q, want %q", ct, baseline.Header().Get("Content-Type"))
	}

	// Flip back on: the route was only ever suppressed, never removed.
	live = true
	if rec := doGet("/api/widgets"); rec.Code != http.StatusOK {
		t.Errorf("GET /api/widgets after re-enabling live = %d, want 200", rec.Code)
	}
}

// TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak reproduces the
// exact scenario a global Use()-registered middleware (Tracing in
// production) creates for a naive handler-only gate: the middleware is
// added to the router BEFORE the gated route is registered (mirroring
// mountMiddleware() running before mountAdminSurface() in
// interfaces/sso), so it would be baked into that route's own
// StdRoute.middlewares. If the gate only wrapped the HANDLER (the
// pre-fix design), this middleware would still run and stamp
// X-Probe-Header on a gated-off response — a response byte-for-byte
// different from a genuinely-never-registered path's 404, and thus an
// oracle revealing "this route exists but is currently gated off"
// distinct from "this route never existed". The fix (StdRoute.live,
// checked in ServeHTTP before running middlewares at all) must make
// these two 404s identical, including headers.
func TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak(t *testing.T) {
	t.Parallel()

	root := NewStdRouter()
	root.Use(func(ctx HandlerContext) {
		ctx.ResponseWriter().Header().Set("X-Probe-Header", "traced")
	})

	live := false
	gated := NewGatedRouter(root.Group("/api"), func() bool { return live })
	gated.GET("/widgets", func(ctx HandlerContext) { ctx.JSON(http.StatusOK, map[string]bool{"ok": true}) })

	doGet := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		root.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		return rec
	}

	baseline := doGet("/api/never-registered")
	if baseline.Code != http.StatusNotFound {
		t.Fatalf("baseline status = %d, want 404 (sanity check)", baseline.Code)
	}
	if baseline.Header().Get("X-Probe-Header") != "" {
		t.Fatalf("sanity check failed: baseline itself carries the probe header — test setup is wrong")
	}

	gateOff := doGet("/api/widgets")
	if gateOff.Code != baseline.Code {
		t.Errorf("gated-off status = %d, want %d", gateOff.Code, baseline.Code)
	}
	if gateOff.Body.String() != baseline.Body.String() {
		t.Errorf("gated-off body = %q, want %q", gateOff.Body.String(), baseline.Body.String())
	}
	if got := gateOff.Header().Get("X-Probe-Header"); got != "" {
		t.Errorf("gated-off response leaked the global middleware's header: %q — the middleware ran even though the gate was off", got)
	}
	if !headersEqual(gateOff.Header(), baseline.Header()) {
		t.Errorf("gated-off headers = %v, want byte-identical to never-registered %v", gateOff.Header(), baseline.Header())
	}

	live = true
	if rec := doGet("/api/widgets"); rec.Code != http.StatusOK {
		t.Errorf("GET /api/widgets after enabling live = %d, want 200", rec.Code)
	}
}

func headersEqual(a, b http.Header) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || len(va) != len(vb) {
			return false
		}
		for i := range va {
			if va[i] != vb[i] {
				return false
			}
		}
	}
	return true
}

// TestGateHTTPHandler_LiveToggle exercises GateHTTPHandler directly (the
// plain net/http analog GateHandler/GatedRouter use for routes registered
// straight on an http.ServeMux, e.g. interfaces/sso's static SPA mounts).
func TestGateHTTPHandler_LiveToggle(t *testing.T) {
	t.Parallel()

	live := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	h := GateHTTPHandler(func() bool { return live }, inner)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status while off = %d, want 404", rec.Code)
	}

	live = true
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
	if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("while on: status=%d body=%q, want 200 \"ok\"", rec.Code, rec.Body.String())
	}
}
