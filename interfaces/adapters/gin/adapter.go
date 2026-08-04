package ginadapter

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// GinRouter adapts gin.Engine to sso.Router.
type GinRouter struct {
	engine      *gin.Engine
	group       *gin.RouterGroup
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
// the engine keeps its framework-native 404/405 behavior (gin's
// "404 page not found" without trailing newline or nosniff; echo's JSON
// error body). The default is what makes sso.WithRouter(adapter)
// wire-interchangeable with NewStdRouter(); opting out gives up the
// byte-identity guarantee, and the routertest conformance suite must never
// be wired against this configuration. An embedder who assigns
// engine.NoRoute / engine.HandleMethodNotAllowed AFTER construction
// replaces the normalization the same way (later assignment wins).
func WithFrameworkNotFound() Option {
	return func(o *options) { o.frameworkNotFound = true }
}

// NewGinRouter returns a GinRouter wrapping a fresh gin.Default() engine, or
// the supplied engine. Unmatched requests (unknown path, wrong method,
// HEAD/OPTIONS on a GET-only route, trailing-slash variant) are normalized
// to http.NotFound's exact bytes, matching StdRouter.ServeHTTP.
func NewGinRouter(engine ...*gin.Engine) *GinRouter {
	e := gin.Default()
	if len(engine) > 0 && engine[0] != nil {
		e = engine[0]
	}
	return NewGinRouterWithOptions(e)
}

// NewGinRouterWithOptions is NewGinRouter with constructor options; a nil
// engine means a fresh gin.Default().
func NewGinRouterWithOptions(engine *gin.Engine, opts ...Option) *GinRouter {
	if engine == nil {
		engine = gin.Default()
	}
	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	if !o.frameworkNotFound {
		// Pin the 404/405 regime so a framework bump cannot silently
		// reintroduce 405s or trailing-slash redirects: method mismatch
		// and path variants must fall through to NoRoute, and NoRoute
		// must answer http.NotFound's exact bytes ("404 page not
		// found\n" + nosniff), matching StdRouter.ServeHTTP.
		engine.HandleMethodNotAllowed = false
		engine.RedirectTrailingSlash = false
		engine.RedirectFixedPath = false
		engine.NoRoute(func(c *gin.Context) {
			http.NotFound(c.Writer, c.Request)
		})
	}
	return &GinRouter{engine: engine, group: &engine.RouterGroup}
}

func (g *GinRouter) GET(path string, handler sso.HandlerFunc) {
	g.group.GET(path, g.wrapHandler(g.snapshotMiddlewares(), handler))
}

func (g *GinRouter) POST(path string, handler sso.HandlerFunc) {
	g.group.POST(path, g.wrapHandler(g.snapshotMiddlewares(), handler))
}

func (g *GinRouter) PUT(path string, handler sso.HandlerFunc) {
	g.group.PUT(path, g.wrapHandler(g.snapshotMiddlewares(), handler))
}

func (g *GinRouter) PATCH(path string, handler sso.HandlerFunc) {
	g.group.PATCH(path, g.wrapHandler(g.snapshotMiddlewares(), handler))
}

func (g *GinRouter) DELETE(path string, handler sso.HandlerFunc) {
	g.group.DELETE(path, g.wrapHandler(g.snapshotMiddlewares(), handler))
}

// RegisterGated implements sso.GatedRegistrar: the gate is a route-level
// handler registered BEFORE the wrapped handler, so live() is evaluated
// before any sso middleware runs and a gated-off route is byte-identical to
// a never-registered one. c.Abort() is MANDATORY here: gin's Next() loop
// advances on its own, so a gate that merely returns would let the wrapped
// handler (and its sso middlewares) run anyway — the exact leak scenario
// the routertest gate-off scenarios pin.
func (g *GinRouter) RegisterGated(method, path string, handler sso.HandlerFunc, live func() bool) {
	g.group.Handle(method, path,
		func(c *gin.Context) {
			if !live() {
				http.NotFound(c.Writer, c.Request)
				c.Abort()
			}
		},
		g.wrapHandler(g.snapshotMiddlewares(), handler),
	)
}

func (g *GinRouter) Group(prefix string, middlewares ...sso.MiddlewareFunc) sso.Router {
	g.mu.RLock()
	base := append([]sso.MiddlewareFunc{}, g.middlewares...)
	g.mu.RUnlock()
	return &GinRouter{
		engine:      g.engine,
		group:       g.group.Group(prefix),
		middlewares: append(base, middlewares...),
	}
}

func (g *GinRouter) Use(middlewares ...sso.MiddlewareFunc) {
	g.mu.Lock()
	g.middlewares = append(g.middlewares, middlewares...)
	g.mu.Unlock()
}

func (g *GinRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.engine.ServeHTTP(w, r)
}

// snapshotMiddlewares copies the current middleware list. Every route
// registration snapshots at registration time (StdRouter's contract: a
// later Use() does not affect already-registered routes), and the request
// path never reads g.middlewares, so concurrent Use()+ServeHTTP is
// race-free by construction — the -race concurrent test is a regression
// tripwire for reverting to request-time reads, not the proof itself.
func (g *GinRouter) snapshotMiddlewares() []sso.MiddlewareFunc {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return append([]sso.MiddlewareFunc{}, g.middlewares...)
}

func (g *GinRouter) wrapHandler(mws []sso.MiddlewareFunc, handler sso.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ssoCtx := &ginContext{Context: c, values: sync.Map{}}
		for _, mw := range mws {
			mw(ssoCtx)
			if ssoCtx.Aborted() {
				break
			}
		}
		if !ssoCtx.Aborted() {
			handler(ssoCtx)
		}
	}
}

// Interface guard: the adapter offers the route-matching-level gate
// StdRouter provides, so core.GatedRouter can gate matching itself on gin
// too (no handler-wrapping fallback, no global-middleware fingerprint).
var _ sso.GatedRegistrar = (*GinRouter)(nil)

type ginContext struct {
	*gin.Context
	values  sync.Map
	aborted bool
}

func (c *ginContext) Request() *http.Request {
	return c.Context.Request
}

func (c *ginContext) ResponseWriter() http.ResponseWriter {
	return c.Writer
}

func (c *ginContext) Param(name string) string {
	return c.Context.Param(name)
}

func (c *ginContext) Query(name string) string {
	return c.Context.Query(name)
}

func (c *ginContext) Bind(v any) error {
	return c.ShouldBindJSON(v)
}

func (c *ginContext) JSON(code int, v any) {
	c.Context.JSON(code, v)
}

func (c *ginContext) Redirect(code int, url string) {
	c.Context.Redirect(code, url)
}

func (c *ginContext) Set(key string, val any) {
	c.values.Store(key, val)
}

func (c *ginContext) Get(key string) any {
	v, _ := c.values.Load(key)
	return v
}

func (c *ginContext) Abort()        { c.aborted = true }
func (c *ginContext) Aborted() bool { return c.aborted }

// Written delegates to gin's writer: gin records the status on the first
// WriteHeader, and through the Decision-4 facade every write path reaches
// the original writer, so this reports exactly "committed at least once".
func (c *ginContext) Written() bool { return c.Writer.Written() }

// SetResponseWriter replaces the writer underlying ctx.JSON/raw writes.
// gin's Context.Writer field is typed gin.ResponseWriter, so a plain
// http.ResponseWriter capture cannot be assigned directly — the facade
// wraps it (see ginCaptureWriter).
func (c *ginContext) SetResponseWriter(w http.ResponseWriter) {
	c.Writer = &ginCaptureWriter{ResponseWriter: c.Writer, capture: w}
}

// ginCaptureWriter is the SetResponseWriter facade gin requires: gin's
// Context.Writer field is typed gin.ResponseWriter, so a plain
// http.ResponseWriter capture cannot be assigned directly. The facade
// embeds the ORIGINAL gin writer (satisfying the full gin.ResponseWriter
// interface) and routes Header/Write/WriteHeader — the three methods a
// capture wrapper intercepts — through the swapped-in capture, so the
// capture sees the body and status. The gin-only methods (Status, Size,
// Written, WriteHeaderNow, WriteString, Pusher, Flush, Hijack,
// CloseNotify) delegate to the original writer, whose own wroteHeader
// guard prevents double-write warnings when gin internally calls
// WriteHeaderNow after an explicit WriteHeader.
//
// One documented edge: a WriteHeaderNow-only path (no prior WriteHeader)
// records the status on the original writer, not in the capture. Every
// Snaplink terminal response goes through ctx.JSON, which calls
// WriteHeader first, so the capture always sees a status.
type ginCaptureWriter struct {
	gin.ResponseWriter
	capture http.ResponseWriter
}

func (w *ginCaptureWriter) Header() http.Header         { return w.capture.Header() }
func (w *ginCaptureWriter) Write(b []byte) (int, error) { return w.capture.Write(b) }
func (w *ginCaptureWriter) WriteHeader(code int)        { w.capture.WriteHeader(code) }
