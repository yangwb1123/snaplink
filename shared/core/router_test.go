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
)
