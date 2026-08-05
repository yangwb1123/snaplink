package core

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// HandlerContext is the interface passed to all handlers and middleware.
//
// Implementors MUST honor Aborted() in their chain loops: after a middleware
// calls Abort() (because it wrote — or decided — a terminal response), the
// router must stop running further middlewares and MUST NOT invoke the
// handler. Abort is opt-in and sticky: middleware that never calls it changes
// nothing.
type HandlerContext interface {
	Request() *http.Request
	ResponseWriter() http.ResponseWriter
	Param(name string) string
	Query(name string) string
	Bind(v any) error
	JSON(code int, v any)
	Redirect(code int, url string)
	Set(key string, val any)
	Get(key string) any
	// Abort marks the chain stopped: the middleware has written (or decided)
	// a terminal response and the handler must not run.
	Abort()
	// Aborted reports whether the chain was stopped by a middleware.
	Aborted() bool
	// Written reports whether the response has been committed at least once
	// ("committed", not "finished": a 401 written by Auth followed by an
	// aborted chain reports true).
	Written() bool
	// SetResponseWriter replaces the writer that JSON/Redirect and
	// ResponseWriter() expose; the previous writer is retained by the
	// caller. Request-scoped; never shared across requests.
	SetResponseWriter(w http.ResponseWriter)
}

// Router abstracts the HTTP routing layer so the SSO server can work with any framework.
type Router interface {
	GET(path string, handler HandlerFunc)
	POST(path string, handler HandlerFunc)
	PUT(path string, handler HandlerFunc)
	PATCH(path string, handler HandlerFunc)
	DELETE(path string, handler HandlerFunc)
	Group(prefix string, middlewares ...MiddlewareFunc) Router
	Use(middlewares ...MiddlewareFunc)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// HandlerFunc is the signature for route handlers.
type HandlerFunc func(ctx HandlerContext)

// MiddlewareFunc is the signature for middleware.
type MiddlewareFunc func(ctx HandlerContext)

// RouteLeaseAcquirer pins the backing route generation before middleware.
// Returning false makes the route behave as though it was never registered.
type RouteLeaseAcquirer func(HandlerContext) (release func(), ok bool)

// trackingResponseWriter is the permanent outermost wrapper NewContext
// installs. It flips a written flag on the first Write/WriteHeader so
// Written() stays truthful across SetResponseWriter swaps — a bare flag on
// Context would go stale the moment a capture wrapper is swapped in,
// because writes flow through whatever writer is current. SetResponseWriter
// re-installs it outermost, so after a capture swap the chain is
// tracking → capture → tracking' → original; every write path passes
// through the outermost wrapper. The double wrapper costs one interface
// call and one flag flip per write — harmless.
type trackingResponseWriter struct {
	http.ResponseWriter
	written bool
}

func (w *trackingResponseWriter) WriteHeader(code int) {
	w.written = true
	w.ResponseWriter.WriteHeader(code)
}

func (w *trackingResponseWriter) Write(b []byte) (int, error) {
	w.written = true
	return w.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying writer to http.ResponseController and
// protocol-aware middleware (Flusher, Hijacker, Pusher, ReaderFrom).
// Without it, the wrapper hides those capabilities and Flush-based
// streaming (the SSE event stream) silently fails with ErrNotSupported;
// net/http's unwrap protocol follows the chain until a non-wrapping
// writer is found.
func (w *trackingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// Context implements HandlerContext using the standard library.
type Context struct {
	w       http.ResponseWriter
	r       *http.Request
	params  map[string]string
	values  sync.Map
	aborted bool
}

func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{
		w:      &trackingResponseWriter{ResponseWriter: w},
		r:      r,
		params: make(map[string]string),
	}
}

func (c *Context) Request() *http.Request              { return c.r }
func (c *Context) ResponseWriter() http.ResponseWriter { return c.w }
func (c *Context) Abort()                              { c.aborted = true }
func (c *Context) Aborted() bool                       { return c.aborted }

// Written reports whether the response has been committed at least once.
// c.w is always a *trackingResponseWriter by construction (NewContext and
// SetResponseWriter both install one), so the assertion cannot fail.
func (c *Context) Written() bool {
	tw, ok := c.w.(*trackingResponseWriter)
	return ok && tw.written
}

// SetResponseWriter replaces the underlying ResponseWriter — the capture
// wrapper the idempotency machinery installs — and re-wraps it in a fresh
// trackingResponseWriter so Written() stays truthful across the swap.
func (c *Context) SetResponseWriter(w http.ResponseWriter) {
	c.w = &trackingResponseWriter{ResponseWriter: w}
}
func (c *Context) Param(name string) string { return c.params[name] }
func (c *Context) Query(name string) string { return c.r.URL.Query().Get(name) }

func (c *Context) Bind(v any) error {
	return json.NewDecoder(c.r.Body).Decode(v)
}

func (c *Context) JSON(code int, v any) {
	c.w.Header().Set(HeaderContentType, ContentTypeJSON)
	c.w.WriteHeader(code)
	// Best-effort: the status + headers are already written, so a mid-encode
	// write failure (client hung up) can't be recovered into the response.
	_ = json.NewEncoder(c.w).Encode(v)
}

func (c *Context) Redirect(code int, url string) {
	http.Redirect(c.w, c.r, url, code)
}

func (c *Context) Set(key string, val any) {
	c.values.Store(key, val)
}

func (c *Context) Get(key string) any {
	v, _ := c.values.Load(key)
	return v
}

// StdRoute wraps a handler with middleware.
type StdRoute struct {
	path        string
	method      string
	handler     HandlerFunc
	middlewares []MiddlewareFunc
	// live gates MATCHING itself, not just the handler: nil means always
	// live (every pre-existing route, unchanged). When set and it reports
	// false, ServeHTTP treats this route as NOT MATCHED at all — skipping
	// its middlewares entirely — rather than running them and then having
	// the handler answer 404. This is what makes a gated-off route
	// byte-identical to a route that was never registered: a per-route
	// global middleware (e.g. Tracing, added via Use() before this route
	// was registered) would otherwise still run and stamp response
	// headers before a handler-level gate check ever got a chance to
	// reject the request. See GatedRouter's doc for the full rationale.
	live    func() bool
	acquire RouteLeaseAcquirer
}

// StdRouter implements Router using the standard library. Groups share the
// same underlying route table via a pointer so child registrations are
// visible at the root.
type StdRouter struct {
	mux         *http.ServeMux
	prefix      string       // group prefix, prepended to every registered path
	mu          sync.RWMutex // guards middlewares: Use writes, registrations/Group snapshot
	middlewares []MiddlewareFunc
	routes      *[]StdRoute // shared across root + groups
}

func NewStdRouter() *StdRouter {
	return &StdRouter{
		mux:    http.NewServeMux(),
		routes: &[]StdRoute{},
	}
}

func (r *StdRouter) GET(path string, handler HandlerFunc) {
	r.register(http.MethodGet, path, handler)
}

func (r *StdRouter) POST(path string, handler HandlerFunc) {
	r.register(http.MethodPost, path, handler)
}

func (r *StdRouter) PUT(path string, handler HandlerFunc) {
	r.register(http.MethodPut, path, handler)
}

func (r *StdRouter) PATCH(path string, handler HandlerFunc) {
	r.register(http.MethodPatch, path, handler)
}

func (r *StdRouter) DELETE(path string, handler HandlerFunc) {
	r.register(http.MethodDelete, path, handler)
}

func (r *StdRouter) register(method, path string, handler HandlerFunc) {
	r.RegisterGated(method, path, handler, nil)
}

// RegisterGated is register's superset: live, when non-nil, is consulted by
// ServeHTTP BEFORE this route's own middlewares run (see StdRoute.live).
// Exported as the GatedRegistrar capability so adapter backends (gin/echo)
// can offer the same route-matching-level gating; GatedRouter owns the
// decision of when a route needs live gating.
func (r *StdRouter) RegisterGated(method, path string, handler HandlerFunc, live func() bool) {
	r.mu.RLock()
	mws := append([]MiddlewareFunc{}, r.middlewares...)
	r.mu.RUnlock()
	*r.routes = append(*r.routes, StdRoute{
		path:        r.prefix + r.buildPath(path),
		method:      method,
		handler:     handler,
		middlewares: mws,
		live:        live,
	})
}

// RegisterLeased registers a static route whose backing generation is pinned
// before any route middleware runs and released after the request completes.
func (r *StdRouter) RegisterLeased(method, path string, handler HandlerFunc, acquire RouteLeaseAcquirer) {
	r.mu.RLock()
	mws := append([]MiddlewareFunc{}, r.middlewares...)
	r.mu.RUnlock()
	*r.routes = append(*r.routes, StdRoute{
		path: r.prefix + r.buildPath(path), method: method, handler: handler,
		middlewares: mws, acquire: acquire,
	})
}

// Group returns a child router whose registrations are prefixed with the
// given path and inherit the parent's middlewares (plus any new ones).
// Routes registered on the child end up in the same table the root serves.
func (r *StdRouter) Group(prefix string, middlewares ...MiddlewareFunc) Router {
	r.mu.RLock()
	base := append([]MiddlewareFunc{}, r.middlewares...)
	r.mu.RUnlock()
	return &StdRouter{
		mux:         r.mux,
		prefix:      r.prefix + r.buildPath(prefix),
		middlewares: append(base, middlewares...),
		routes:      r.routes,
	}
}

func (r *StdRouter) Use(middlewares ...MiddlewareFunc) {
	// Registrations snapshot the list; the mutex makes concurrent Use() safe.
	r.mu.Lock()
	r.middlewares = append(r.middlewares, middlewares...)
	r.mu.Unlock()
}

func (r *StdRouter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctx := NewContext(w, req)

	for _, route := range *r.routes {
		if req.Method != route.method {
			continue
		}
		if !matchPath(route.path, req.URL.Path) {
			continue
		}
		// A live-gated route that's currently off is treated as NOT
		// MATCHED — falls through to the shared http.NotFound below,
		// same as if it had never been registered — rather than running
		// its middlewares and then having the handler itself answer 404.
		// That distinction is exactly what would otherwise let a global
		// middleware (Tracing, added via Use() before this route was
		// registered) stamp response headers a genuinely-unmatched
		// request never gets. See StdRoute.live's doc.
		if route.live != nil && !route.live() {
			continue
		}
		if route.acquire != nil {
			release, ok := route.acquire(ctx)
			if !ok {
				continue
			}
			if release != nil {
				defer release()
			}
		}
		extractParams(ctx, route.path, req.URL.Path)
		for _, mw := range route.middlewares {
			mw(ctx)
			if ctx.Aborted() {
				break
			}
		}
		if !ctx.Aborted() {
			route.handler(ctx)
		}
		return
	}

	http.NotFound(w, req)
}

// buildPath normalizes a path fragment to start with "/" and strip duplicates.
// "/health" + "" → "/health"; "/api/v1" + "/clients/:id" → "/api/v1/clients/:id".
func (r *StdRouter) buildPath(path string) string {
	if path == "" || path == "/" {
		return ""
	}
	return "/" + strings.TrimPrefix(path, "/")
}

func matchPath(pattern, actual string) bool {
	pParts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	aParts := strings.Split(strings.TrimPrefix(actual, "/"), "/")
	if len(pParts) != len(aParts) {
		return false
	}
	for i, p := range pParts {
		if strings.HasPrefix(p, ":") {
			continue
		}
		if p != aParts[i] {
			return false
		}
	}
	return true
}

func extractParams(ctx *Context, pattern, actual string) {
	pParts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	aParts := strings.Split(strings.TrimPrefix(actual, "/"), "/")
	for i, p := range pParts {
		if strings.HasPrefix(p, ":") {
			ctx.params[p[1:]] = aParts[i]
		}
	}
}

// GateHandler wraps h so it only actually runs while live() reports true;
// otherwise the caller gets exactly the response StdRouter.ServeHTTP gives a
// genuinely unmatched path (http.NotFound), never h's own logic. This is the
// primitive a hot-reloadable feature gate needs: register a route ONCE, at
// boot, off whatever backing dependency (store, filesystem) already exists,
// then let an independent runtime toggle control reachability afterward
// without re-registering anything — see GatedRouter's doc for the fuller
// rationale (interfaces/sso's admin_api / branding gates are the motivating
// callers).
func GateHandler(live func() bool, h HandlerFunc) HandlerFunc {
	return func(ctx HandlerContext) {
		if !live() {
			http.NotFound(ctx.ResponseWriter(), ctx.Request())
			return
		}
		h(ctx)
	}
}

// GateHTTPHandler is GateHandler's plain net/http analog, for a route
// registered directly on an http.ServeMux (e.g. a static SPA filesystem
// mount) rather than through a Router.
func GateHTTPHandler(live func() bool, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !live() {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GatedRegistrar is the optional capability a Router implementation may
// provide so GatedRouter can gate route MATCHING itself (checked BEFORE
// that route's own middlewares — including Use()-registered global ones —
// run) instead of wrapping the handler. Implementors MUST evaluate live()
// before running any middleware of the route, so a gated-off route is
// byte-identical to a route that was never registered at all (see
// StdRoute.live for why that distinction is security-relevant). StdRouter
// and the gin/echo adapters implement this; a Router that does not falls
// back to handler-wrapping in GatedRouter (reachability still correct, but
// global middleware may observe gated-off requests — see the GET/POST/etc
// methods below).
type GatedRegistrar interface {
	RegisterGated(method, path string, handler HandlerFunc, live func() bool)
}

// LeasedRegistrar is implemented by routers that can pin a route generation
// at match time, before middleware can observe the request.
type LeasedRegistrar interface {
	RegisterLeased(method, path string, handler HandlerFunc, acquire RouteLeaseAcquirer)
}

// GatedRouter wraps a Router so every handler registered through it — and
// through any Router derived from it via Group — shares ONE live() check:
// reachable while live() is true, a byte-identical-to-never-mounted 404
// while false.
//
// When inner is (or is derived via Group from) a *StdRouter, gating is
// done at the ROUTE-MATCHING level (StdRoute.live, checked in
// StdRouter.ServeHTTP before that route's own middlewares run) — this is
// REQUIRED, not a style choice: StdRouter.ServeHTTP always runs a matched
// route's middlewares and THEN the handler unconditionally, so a global
// middleware added via Use() BEFORE this route was registered (e.g.
// Tracing, which stamps X-Request-Id/Traceparent on every response it
// sees) would otherwise still run and leave its fingerprint on the
// response before a handler-level check ever got a chance to reject the
// request — the gate has to prevent the route from matching at all, not
// just prevent the handler's own business logic from executing.
//
// For any OTHER Router implementation (one that doesn't implement
// GatedRegistrar), this falls back to wrapping the handler with
// GateHandler — reachability is still correctly gated, but a global
// middleware on THAT router could still observe a gated-off request
// before the wrapped handler's check runs, same limitation the fallback
// always had. This is a strictly-no-worse-than-before fallback, not a
// silent claim of the same guarantee; the byte-identical-to-never-
// mounted-404 property is only proven for the default StdRouter (see
// TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404, which
// exercises exactly this scenario with a Use()-registered middleware
// ahead of the gated route).
//
// This lets a caller register a whole route GROUP once, at boot, off
// whatever backing dependencies already exist, while a later runtime
// toggle (a hot-reloaded feature gate) controls the group's reachability
// without ever re-registering a route.
type GatedRouter struct {
	inner Router
	live  func() bool
}

// NewGatedRouter wraps inner so every handler subsequently registered on it
// is reachable only while live() returns true.
func NewGatedRouter(inner Router, live func() bool) *GatedRouter {
	return &GatedRouter{inner: inner, live: live}
}

func (g *GatedRouter) GET(path string, h HandlerFunc) { g.register(http.MethodGet, path, h) }

func (g *GatedRouter) POST(path string, h HandlerFunc) { g.register(http.MethodPost, path, h) }

func (g *GatedRouter) PUT(path string, h HandlerFunc) { g.register(http.MethodPut, path, h) }

func (g *GatedRouter) PATCH(path string, h HandlerFunc) { g.register(http.MethodPatch, path, h) }

func (g *GatedRouter) DELETE(path string, h HandlerFunc) { g.register(http.MethodDelete, path, h) }

// register dispatches to the route-matching-level gate (GatedRegistrar)
// when inner supports it, else falls back to handler-wrapping — see
// GatedRouter's doc for why these give different (but both correct,
// reachability-wise) guarantees.
func (g *GatedRouter) register(method, path string, h HandlerFunc) {
	if gr, ok := g.inner.(GatedRegistrar); ok {
		gr.RegisterGated(method, path, h, g.live)
		return
	}
	switch method {
	case http.MethodGet:
		g.inner.GET(path, GateHandler(g.live, h))
	case http.MethodPost:
		g.inner.POST(path, GateHandler(g.live, h))
	case http.MethodPut:
		g.inner.PUT(path, GateHandler(g.live, h))
	case http.MethodPatch:
		g.inner.PATCH(path, GateHandler(g.live, h))
	case http.MethodDelete:
		g.inner.DELETE(path, GateHandler(g.live, h))
	}
}

// Group preserves the SAME live check on the returned child router, so a
// nested Group call inside a gated mount stays gated too.
func (g *GatedRouter) Group(prefix string, middlewares ...MiddlewareFunc) Router {
	return &GatedRouter{inner: g.inner.Group(prefix, middlewares...), live: g.live}
}

func (g *GatedRouter) Use(middlewares ...MiddlewareFunc) { g.inner.Use(middlewares...) }

func (g *GatedRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.inner.ServeHTTP(w, r)
}
