// Package routertest hosts the shared behavioral conformance suite for
// core.Router implementations (StdRouter, the gin/echo adapters, future
// peers). Backend authors hook their factory into ConformanceSuite to lock
// the wire bytes sso.WithRouter embeddings depend on: unmatched responses
// byte-identical to http.NotFound, middleware order and Abort semantics,
// registration-time middleware snapshots, and gated-off routes
// byte-identical to never-registered ones. The suite lives outside
// shared/core (the kernel imports no Snaplink package) and outside the
// adapter packages (they provide the Factory); a backend that cannot run
// this suite green cannot claim sso.WithRouter support.
package routertest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangwb1123/snaplink/shared/core"
)

// ConformanceSuite is the behavioral contract every Router backend must
// satisfy. Mirror of permissionstest.ConformanceSuite: a factory plus a
// scenario matrix, run as one subtest per scenario against a fresh router.
type ConformanceSuite struct {
	// Factory returns a FRESH router per subtest; instances MUST NOT be
	// shared across subtests (state leakage would mask backend bugs).
	// Factory must build via the backend's public constructor with default
	// wiring (no options), so the suite exercises the exact configuration
	// sso.WithRouter embeddings get — never a test-only configuration.
	Factory func(*testing.T) core.Router
}

// Run executes the full scenario matrix. Each scenario is a subtest against
// a fresh Factory(t) instance; a panic or assertion failure in one scenario
// does not hide the others.
func (s ConformanceSuite) Run(t *testing.T) {
	t.Helper()
	if s.Factory == nil {
		t.Fatal("ConformanceSuite.Factory is nil — wire the backend's public constructor")
	}
	newRouter := func(t *testing.T) core.Router {
		t.Helper()
		r := s.Factory(t)
		if r == nil {
			t.Fatal("Factory returned a nil Router")
		}
		return r
	}
	for _, sc := range []struct {
		name string
		fn   func(*testing.T, func(*testing.T) core.Router)
	}{
		{"FiveMethodDispatch", fiveMethodDispatch},
		{"PathParamsAndQuery", pathParamsAndQuery},
		{"UnknownPath_ByteIdenticalToHTTPNotFound", unknownPathByteIdenticalToHTTPNotFound},
		{"MethodMismatch_ByteIdenticalToHTTPNotFound", methodMismatchByteIdenticalToHTTPNotFound},
		{"HeadOnGetRoute_ByteIdenticalToHTTPNotFound", headOnGetRouteByteIdenticalToHTTPNotFound},
		{"OptionsOnKnownPath_ByteIdenticalToHTTPNotFound", optionsOnKnownPathByteIdenticalToHTTPNotFound},
		{"TrailingSlash_ByteIdenticalToHTTPNotFound", trailingSlashByteIdenticalToHTTPNotFound},
		{"MiddlewareOrderAndAbort_HandlerNotRun", middlewareOrderAndAbortHandlerNotRun},
		{"GroupPrefix_InheritsMiddleware", groupPrefixInheritsMiddleware},
		{"UseAfterRegister_DoesNotAffectRegisteredRoutes", useAfterRegisterDoesNotAffectRegisteredRoutes},
		{"GateOff_ByteIdenticalToNeverMounted", gateOffByteIdenticalToNeverMounted},
		{"GateOff_SkipsGlobalMiddleware_NoHeaderLeak", gateOffSkipsGlobalMiddlewareNoHeaderLeak},
		{"GatedGroup_PreservesGate", gatedGroupPreservesGate},
		{"GateOn_ServesRoute", gateOnServesRoute},
	} {
		sc := sc
		t.Run(sc.name, func(t *testing.T) {
			sc.fn(t, newRouter)
		})
	}
}

// --- helpers ---

// referenceNotFound computes the canonical unmatched response the stdlib
// produces, derived at runtime — never hardcoded. The contract is
// "identical to the stdlib's canonical 404", which is exactly the contract
// StdRouter.ServeHTTP already has; if stdlib bytes drift, every backend
// tracks the drift together and the suite still passes (correct: the
// reference moved, and backends track it). Recorder-level comparison
// deliberately excludes wire framing (HEAD body suppression,
// Content-Length), which Go's http.Server applies uniformly across
// backends.
func referenceNotFound(t *testing.T, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	http.NotFound(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// assertByteIdenticalToNotFound asserts that the router's response for the
// given method+path is byte-identical (status, body, full header map) to
// http.NotFound's canonical response. Full equality — never strings.Contains.
func assertByteIdenticalToNotFound(t *testing.T, r core.Router, method, path string) {
	t.Helper()
	ref := referenceNotFound(t, method, path)
	rec := do(r, method, path)
	if rec.Code != ref.Code {
		t.Errorf("%s %s: status = %d, want %d", method, path, rec.Code, ref.Code)
	}
	if rec.Body.String() != ref.Body.String() {
		t.Errorf("%s %s: body = %q, want %q", method, path, rec.Body.String(), ref.Body.String())
	}
	if !headersEqual(rec.Header(), ref.Header()) {
		t.Errorf("%s %s: headers = %v, want %v", method, path, rec.Header(), ref.Header())
	}
}

func do(r core.Router, method, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

// headersEqual compares two header maps order-insensitively, mirroring the
// helper in shared/core/router_test.go.
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

func okHandler(c core.HandlerContext) { c.JSON(http.StatusOK, map[string]bool{"ok": true}) }

// register dispatches to the matching Router method; the interface has no
// generic register, so the switch is the suite's only place that names all
// five.
func register(r core.Router, method, path string, h core.HandlerFunc) {
	switch method {
	case http.MethodGet:
		r.GET(path, h)
	case http.MethodPost:
		r.POST(path, h)
	case http.MethodPut:
		r.PUT(path, h)
	case http.MethodPatch:
		r.PATCH(path, h)
	case http.MethodDelete:
		r.DELETE(path, h)
	default:
		panic("routertest: unsupported method " + method)
	}
}

// --- scenarios ---

// fiveMethodDispatch pins that all five verbs dispatch and produce valid
// JSON. Cross-backend byte equality of the JSON body is NOT asserted (gin
// omits the trailing newline and appends "; charset=utf-8"; StdRouter/echo
// differ too) — the contract is status + JSON value + Content-Type, which
// is what handlers and clients rely on.
func fiveMethodDispatch(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		m := m
		register(r, m, "/m", func(c core.HandlerContext) {
			c.JSON(http.StatusOK, map[string]string{"method": m})
		})
	}
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rec := do(r, m, "/m")
		if rec.Code != http.StatusOK {
			t.Errorf("%s /m: status = %d, want 200", m, rec.Code)
			continue
		}
		var got map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
			t.Errorf("%s /m: body %q is not JSON: %v", m, rec.Body.String(), err)
			continue
		}
		if got["method"] != m {
			t.Errorf("%s /m: body = %q, want method %q", m, rec.Body.String(), m)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s /m: Content-Type = %q, want application/json", m, ct)
		}
	}
}

func pathParamsAndQuery(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	r.GET("/tenants/:tid/users/:uid", func(c core.HandlerContext) {
		c.JSON(http.StatusOK, map[string]string{
			"tid":    c.Param("tid"),
			"uid":    c.Param("uid"),
			"active": c.Query("active"),
		})
	})
	rec := do(r, http.MethodGet, "/tenants/acme/users/u9?active=1")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	if got["tid"] != "acme" || got["uid"] != "u9" || got["active"] != "1" {
		t.Errorf("params = %v, want tid=acme uid=u9 active=1", got)
	}
}

func unknownPathByteIdenticalToHTTPNotFound(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	r.GET("/known", okHandler)
	assertByteIdenticalToNotFound(t, r, http.MethodGet, "/never-registered")
}

// methodMismatchByteIdenticalToHTTPNotFound locks the deliberate StdRouter
// semantics: a wrong-method request matches no route, so it is a 404 — not
// a 405 — and must be byte-identical to the canonical 404 (RFC 9110 §15.5.6
// legitimizes the non-disclosing 404).
func methodMismatchByteIdenticalToHTTPNotFound(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	r.GET("/known", okHandler)
	assertByteIdenticalToNotFound(t, r, http.MethodPost, "/known")
}

// headOnGetRouteByteIdenticalToHTTPNotFound pins that HEAD does not
// auto-degrade to GET (no auto-HEAD), matching StdRouter's exact-method
// table.
func headOnGetRouteByteIdenticalToHTTPNotFound(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	r.GET("/known", okHandler)
	assertByteIdenticalToNotFound(t, r, http.MethodHead, "/known")
}

// optionsOnKnownPathByteIdenticalToHTTPNotFound pins that OPTIONS on a known
// path is a 404 (echo's native 204+Allow and gin's auto-OPTIONS are
// deliberately normalized away; the sso-server handles CORS preflight
// outside the router).
func optionsOnKnownPathByteIdenticalToHTTPNotFound(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	r.GET("/known", okHandler)
	assertByteIdenticalToNotFound(t, r, http.MethodOptions, "/known")
}

// trailingSlashByteIdenticalToHTTPNotFound pins exact segment matching: the
// trailing-slash variant of a known path is unmatched (StdRouter's
// matchPath is exact; gin's TSR redirect is pinned off by the adapter; echo
// never redirects).
func trailingSlashByteIdenticalToHTTPNotFound(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	r.GET("/known", okHandler)
	assertByteIdenticalToNotFound(t, r, http.MethodGet, "/known/")
}

// middlewareOrderAndAbortHandlerNotRun pins the Abort contract: middlewares
// run in registration order, a middleware that writes a terminal response
// and calls Abort() must stop the chain, the handler must never run, and
// the response must be exactly the middleware's bytes with no double write.
func middlewareOrderAndAbortHandlerNotRun(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	var order []string
	var handlerRan atomic.Bool
	r.Use(func(c core.HandlerContext) { order = append(order, "m1") })
	r.Use(func(c core.HandlerContext) {
		order = append(order, "m2")
		http.Error(c.ResponseWriter(), "denied", http.StatusUnauthorized)
		c.Abort()
	})
	r.GET("/x", func(c core.HandlerContext) {
		handlerRan.Store(true)
		c.JSON(http.StatusOK, "ok")
	})

	rec := do(r, http.MethodGet, "/x")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if rec.Body.String() != "denied\n" {
		t.Errorf("body = %q, want %q (a double write would append handler output)", rec.Body.String(), "denied\n")
	}
	if handlerRan.Load() {
		t.Error("handler ran after a middleware wrote 401 and aborted")
	}
	if len(order) != 2 || order[0] != "m1" || order[1] != "m2" {
		t.Errorf("middleware order = %v, want [m1 m2]", order)
	}
}

func groupPrefixInheritsMiddleware(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	r.Use(func(c core.HandlerContext) { c.Set("base", "yes") })
	api := r.Group("/api", func(c core.HandlerContext) { c.Set("grp", "yes") })
	read := func(c core.HandlerContext) {
		base, _ := c.Get("base").(string)
		grp, _ := c.Get("grp").(string)
		c.JSON(http.StatusOK, map[string]string{"base": base, "grp": grp})
	}
	api.GET("/x", read)
	r.GET("/y", read)

	rec := do(r, http.MethodGet, "/api/x")
	var got map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["base"] != "yes" || got["grp"] != "yes" {
		t.Errorf("/api/x = %v, want base=yes grp=yes (group inherits parent + own middleware)", got)
	}
	rec = do(r, http.MethodGet, "/y")
	got = map[string]string{}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["base"] != "yes" || got["grp"] != "" {
		t.Errorf("/y = %v, want base=yes grp=\"\" (group middleware must not leak to siblings)", got)
	}
}

// useAfterRegisterDoesNotAffectRegisteredRoutes pins the registration-time
// snapshot contract: a route registered before Use() must not see the new
// middleware; a route registered after must. StdRouter's contract, which
// the adapters now share.
func useAfterRegisterDoesNotAffectRegisteredRoutes(t *testing.T, newRouter func(*testing.T) core.Router) {
	r := newRouter(t)
	read := func(c core.HandlerContext) {
		late, _ := c.Get("late").(string)
		c.JSON(http.StatusOK, map[string]string{"late": late})
	}
	r.GET("/a", read)
	r.Use(func(c core.HandlerContext) { c.Set("late", "yes") })
	r.GET("/b", read)

	rec := do(r, http.MethodGet, "/a")
	var got map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["late"] != "" {
		t.Errorf("/a = %v, want late=\"\" (Use after registration must not affect /a)", got)
	}
	rec = do(r, http.MethodGet, "/b")
	got = map[string]string{}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["late"] != "yes" {
		t.Errorf("/b = %v, want late=yes (Use before registration must affect /b)", got)
	}
}

// gateOffByteIdenticalToNeverMounted reproduces
// TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404 for every
// backend: while live() is false the gated route is byte-identical to a
// path that was never registered — including a WRONG METHOD on the gated
// route, which never reaches the gate (it matches no route at all, same as
// StdRouter's not-matched-at-all semantics). The handler must not execute.
func gateOffByteIdenticalToNeverMounted(t *testing.T, newRouter func(*testing.T) core.Router) {
	live := true
	root := newRouter(t)
	gated := core.NewGatedRouter(root, func() bool { return live })
	var handlerCalls atomic.Int32
	gated.GET("/api/widgets", func(c core.HandlerContext) {
		handlerCalls.Add(1)
		c.JSON(http.StatusOK, map[string]bool{"ok": true})
	})

	live = false
	assertByteIdenticalToNotFound(t, root, http.MethodGet, "/api/widgets")
	assertByteIdenticalToNotFound(t, root, http.MethodPost, "/api/widgets")
	if handlerCalls.Load() != 0 {
		t.Errorf("handler executed %d time(s) while the gate was off, want 0", handlerCalls.Load())
	}

	live = true
	rec := do(root, http.MethodGet, "/api/widgets")
	if rec.Code != http.StatusOK {
		t.Errorf("status after re-enabling live = %d, want 200", rec.Code)
	}
	if handlerCalls.Load() != 1 {
		t.Errorf("handler executed %d time(s) while the gate was on, want 1", handlerCalls.Load())
	}
}

// gateOffSkipsGlobalMiddlewareNoHeaderLeak reproduces
// TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak for every
// backend: a Use()-registered header-stamping middleware added BEFORE the
// gated route must not run while the gate is off — a gated-off response
// carrying a header a never-registered path never gets would be an oracle
// revealing "this route exists but is currently gated off".
func gateOffSkipsGlobalMiddlewareNoHeaderLeak(t *testing.T, newRouter func(*testing.T) core.Router) {
	root := newRouter(t)
	root.Use(func(c core.HandlerContext) {
		c.ResponseWriter().Header().Set("X-Probe-Header", "traced")
	})

	live := false
	gated := core.NewGatedRouter(root.Group("/api"), func() bool { return live })
	gated.GET("/widgets", func(c core.HandlerContext) { c.JSON(http.StatusOK, map[string]bool{"ok": true}) })

	baseline := referenceNotFound(t, http.MethodGet, "/api/never-registered")
	if baseline.Header().Get("X-Probe-Header") != "" {
		t.Fatal("sanity check failed: baseline itself carries the probe header — test setup is wrong")
	}

	gateOff := do(root, http.MethodGet, "/api/widgets")
	if gateOff.Code != baseline.Code {
		t.Errorf("gated-off status = %d, want %d", gateOff.Code, baseline.Code)
	}
	if gateOff.Body.String() != baseline.Body.String() {
		t.Errorf("gated-off body = %q, want %q", gateOff.Body.String(), baseline.Body.String())
	}
	if got := gateOff.Header().Get("X-Probe-Header"); got != "" {
		t.Errorf("gated-off response leaked the global middleware's header %q — the middleware ran despite the gate", got)
	}
	if !headersEqual(gateOff.Header(), baseline.Header()) {
		t.Errorf("gated-off headers = %v, want byte-identical to never-registered %v", gateOff.Header(), baseline.Header())
	}

	// Positive control: the middleware IS wired and runs for live routes.
	live = true
	on := do(root, http.MethodGet, "/api/widgets")
	if on.Code != http.StatusOK {
		t.Errorf("status while live = %d, want 200", on.Code)
	}
	if on.Header().Get("X-Probe-Header") != "traced" {
		t.Errorf("live response missing the probe header — middleware wiring broken")
	}
}

// gatedGroupPreservesGate pins that gating through a derived Group keeps the
// same live check: a GatedRouter.Group(...) child must still gate at the
// route-matching level (the adapter's Group returns a router that still
// implements GatedRegistrar).
func gatedGroupPreservesGate(t *testing.T, newRouter func(*testing.T) core.Router) {
	live := false
	root := newRouter(t)
	gr := core.NewGatedRouter(root, func() bool { return live })
	var calls atomic.Int32
	gr.Group("/admin").GET("/x", func(c core.HandlerContext) {
		calls.Add(1)
		c.JSON(http.StatusOK, "ok")
	})

	assertByteIdenticalToNotFound(t, root, http.MethodGet, "/admin/x")
	if calls.Load() != 0 {
		t.Errorf("handler executed %d time(s) while the group gate was off, want 0", calls.Load())
	}

	live = true
	rec := do(root, http.MethodGet, "/admin/x")
	if rec.Code != http.StatusOK {
		t.Errorf("status after enabling live = %d, want 200", rec.Code)
	}
}

func gateOnServesRoute(t *testing.T, newRouter func(*testing.T) core.Router) {
	live := true
	root := newRouter(t)
	gated := core.NewGatedRouter(root, func() bool { return live })
	gated.GET("/ping", func(c core.HandlerContext) { c.JSON(http.StatusOK, map[string]string{"pong": "yes"}) })

	rec := do(root, http.MethodGet, "/ping")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body %q is not JSON: %v", rec.Body.String(), err)
	}
	if got["pong"] != "yes" {
		t.Errorf("body = %v, want pong=yes", got)
	}
}
