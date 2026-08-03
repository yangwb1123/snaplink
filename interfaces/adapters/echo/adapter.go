package echoadapter

import (
	"errors"
	"net/http"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// errGateOff is the sentinel the gated-route middleware returns after
// writing the 404 itself. The constructor-installed delegating
// HTTPErrorHandler swallows it (the response is already committed); echo's
// default handler would early-return on a committed response anyway, but an
// embedder-replaced handler may not, and echo's Response.Write has no
// committed guard — a second write would corrupt the 404 bytes.
// Package-private: no embedder can construct it, so no legitimate echo
// error collides.
var errGateOff = errors.New("snaplink: gated route off")

// EchoRouter adapts echo.Echo to sso.Router.
type EchoRouter struct {
	engine      *echo.Echo
	group       *echo.Group
	mu          sync.RWMutex
	middlewares []sso.MiddlewareFunc
}

// options configures the adapter's engine wiring. The zero value is the
// normalized default (unmatched responses byte-identical to http.NotFound).
type options struct {
	frameworkNotFound bool
}

// Option customizes adapter construction.
type Option func(*options)

// WithFrameworkNotFound opts out of the unmatched-response normalization:
// the engine keeps its framework-native 404/405 behavior (echo's JSON
// error body). The default is what makes sso.WithRouter(adapter)
// wire-interchangeable with NewStdRouter(); opting out gives up the
// byte-identity guarantee, and the routertest conformance suite must never
// be wired against this configuration. An embedder who registers routes or
// middleware on the engine AFTER construction can override the installed
// RouteNotFound node handler (later registration wins), the same
// precedence the framework always had.
func WithFrameworkNotFound() Option {
	return func(o *options) { o.frameworkNotFound = true }
}

// NewEchoRouter returns an EchoRouter wrapping a fresh echo.New() engine, or
// the supplied engine. Unmatched requests (unknown path, wrong method,
// HEAD/OPTIONS on a GET-only route, trailing-slash variant) are normalized
// to http.NotFound's exact bytes, matching StdRouter.ServeHTTP.
func NewEchoRouter(engine ...*echo.Echo) *EchoRouter {
	e := echo.New()
	if len(engine) > 0 && engine[0] != nil {
		e = engine[0]
	}
	return NewEchoRouterWithOptions(e)
}

// NewEchoRouterWithOptions is NewEchoRouter with constructor options; a nil
// engine means a fresh echo.New().
func NewEchoRouterWithOptions(engine *echo.Echo, opts ...Option) *EchoRouter {
	if engine == nil {
		engine = echo.New()
	}
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	if !o.frameworkNotFound {
		// Normalize every unmatched tuple to http.NotFound's exact bytes.
		// echo's NotFoundHandler/MethodNotAllowedHandler are package-level
		// vars (global, not per-router), so they cannot be assigned here;
		// RouteNotFound("/*") installs a per-node handler that wins over
		// the 405/OPTIONS branches in router.Find for every unmatched
		// tuple (verified against echo v4.15.2). It must be installed
		// before the engine serves its first request: the router's
		// maxParam is fixed at registration and a late add panics on
		// pooled contexts. echo never auto-redirects trailing slashes, so
		// /known/ falls into the same catch-all.
		engine.RouteNotFound("/*", func(c echo.Context) error {
			http.NotFound(c.Response(), c.Request())
			return nil
		})
		// Delegating error handler: swallow the gate sentinel (the 404 was
		// already written) and delegate every other error to the handler
		// current at construction.
		prev := engine.HTTPErrorHandler
		engine.HTTPErrorHandler = func(err error, c echo.Context) {
			if errors.Is(err, errGateOff) {
				return
			}
			prev(err, c)
		}
	}
	return &EchoRouter{engine: engine, group: engine.Group("")}
}

func (e *EchoRouter) GET(path string, handler sso.HandlerFunc) {
	e.group.GET(path, e.wrapHandler(e.snapshotMiddlewares(), handler))
}

func (e *EchoRouter) POST(path string, handler sso.HandlerFunc) {
	e.group.POST(path, e.wrapHandler(e.snapshotMiddlewares(), handler))
}

func (e *EchoRouter) PUT(path string, handler sso.HandlerFunc) {
	e.group.PUT(path, e.wrapHandler(e.snapshotMiddlewares(), handler))
}

func (e *EchoRouter) PATCH(path string, handler sso.HandlerFunc) {
	e.group.PATCH(path, e.wrapHandler(e.snapshotMiddlewares(), handler))
}

func (e *EchoRouter) DELETE(path string, handler sso.HandlerFunc) {
	e.group.DELETE(path, e.wrapHandler(e.snapshotMiddlewares(), handler))
}

// RegisterGated implements sso.GatedRegistrar: the gate is a route-level
// middleware registered BEFORE the wrapped handler, so live() is evaluated
// before any sso middleware runs and a gated-off route is byte-identical to
// a never-registered one. echo's applyMiddleware makes the last middleware
// the outermost, so the gate runs first; returning errGateOff stops the
// chain before the wrapped handler (and its sso middlewares) execute.
func (e *EchoRouter) RegisterGated(method, path string, handler sso.HandlerFunc, live func() bool) {
	e.group.Add(method, path, e.wrapHandler(e.snapshotMiddlewares(), handler),
		func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error {
				if !live() {
					http.NotFound(c.Response(), c.Request())
					return errGateOff
				}
				return next(c)
			}
		})
}

func (e *EchoRouter) Group(prefix string, middlewares ...sso.MiddlewareFunc) sso.Router {
	e.mu.RLock()
	base := append([]sso.MiddlewareFunc{}, e.middlewares...)
	e.mu.RUnlock()
	return &EchoRouter{
		engine:      e.engine,
		group:       e.group.Group(prefix),
		middlewares: append(base, middlewares...),
	}
}

func (e *EchoRouter) Use(middlewares ...sso.MiddlewareFunc) {
	e.mu.Lock()
	e.middlewares = append(e.middlewares, middlewares...)
	e.mu.Unlock()
}

func (e *EchoRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.engine.ServeHTTP(w, r)
}

// snapshotMiddlewares copies the current middleware list. Every route
// registration snapshots at registration time (StdRouter's contract: a
// later Use() does not affect already-registered routes), and the request
// path never reads e.middlewares, so concurrent Use()+ServeHTTP is
// race-free by construction — the -race concurrent test is a regression
// tripwire for reverting to request-time reads, not the proof itself.
func (e *EchoRouter) snapshotMiddlewares() []sso.MiddlewareFunc {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]sso.MiddlewareFunc{}, e.middlewares...)
}

func (e *EchoRouter) wrapHandler(mws []sso.MiddlewareFunc, handler sso.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		ssoCtx := &echoContext{Context: c, values: sync.Map{}}
		for _, mw := range mws {
			mw(ssoCtx)
			if ssoCtx.Aborted() {
				break
			}
		}
		if !ssoCtx.Aborted() {
			handler(ssoCtx)
		}
		return nil
	}
}

// Interface guard: the adapter offers the route-matching-level gate
// StdRouter provides, so core.GatedRouter can gate matching itself on echo
// too (no handler-wrapping fallback, no global-middleware fingerprint).
var _ sso.GatedRegistrar = (*EchoRouter)(nil)

type echoContext struct {
	echo.Context
	values  sync.Map
	aborted bool
}

func (c *echoContext) Request() *http.Request {
	return c.Context.Request()
}

func (c *echoContext) ResponseWriter() http.ResponseWriter {
	return c.Response()
}

func (c *echoContext) Param(name string) string {
	return c.Context.Param(name)
}

func (c *echoContext) Query(name string) string {
	return c.QueryParam(name)
}

func (c *echoContext) Bind(v any) error {
	return c.Context.Bind(v)
}

func (c *echoContext) JSON(code int, v any) {
	// Best-effort response write; a broken client connection is non-actionable here.
	_ = c.Context.JSON(code, v)
}

func (c *echoContext) Redirect(code int, url string) {
	// Best-effort response write; a broken client connection is non-actionable here.
	_ = c.Context.Redirect(code, url)
}

func (c *echoContext) Set(key string, val any) {
	c.values.Store(key, val)
}

func (c *echoContext) Get(key string) any {
	v, _ := c.values.Load(key)
	return v
}

func (c *echoContext) Abort()        { c.aborted = true }
func (c *echoContext) Aborted() bool { return c.aborted }

// Written delegates to echo's Response: it sets Committed inside its own
// Write/WriteHeader, which forward to Response.Writer — so after a
// SetResponseWriter swap the flag still reflects writes through the
// capture.
func (c *echoContext) Written() bool { return c.Response().Committed }

// SetResponseWriter replaces the writer underlying ctx.JSON/raw writes.
// echo's Response.Writer is a plain public http.ResponseWriter field
// (verified against echo v4.15), so the assignment compiles directly and
// Response's own Write/WriteHeader/Committed tracking keeps working —
// they are implemented on Response itself, not on Writer.
func (c *echoContext) SetResponseWriter(w http.ResponseWriter) {
	c.Response().Writer = w
}
