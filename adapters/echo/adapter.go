package echoadapter

import (
	"net/http"
	"sync"

	"github.com/labstack/echo/v4"
	"github.com/snaplink/sso"
)

// EchoRouter adapts echo.Echo to sso.Router.
type EchoRouter struct {
	engine      *echo.Echo
	group       *echo.Group
	middlewares []sso.MiddlewareFunc
}

func NewEchoRouter(engine ...*echo.Echo) *EchoRouter {
	e := echo.New()
	if len(engine) > 0 {
		e = engine[0]
	}
	return &EchoRouter{engine: e, group: e.Group("")}
}

func (e *EchoRouter) GET(path string, handler sso.HandlerFunc) {
	e.group.GET(path, e.wrapHandler(handler))
}

func (e *EchoRouter) POST(path string, handler sso.HandlerFunc) {
	e.group.POST(path, e.wrapHandler(handler))
}

func (e *EchoRouter) PUT(path string, handler sso.HandlerFunc) {
	e.group.PUT(path, e.wrapHandler(handler))
}

func (e *EchoRouter) PATCH(path string, handler sso.HandlerFunc) {
	e.group.PATCH(path, e.wrapHandler(handler))
}

func (e *EchoRouter) DELETE(path string, handler sso.HandlerFunc) {
	e.group.DELETE(path, e.wrapHandler(handler))
}

func (e *EchoRouter) Group(prefix string, middlewares ...sso.MiddlewareFunc) sso.Router {
	all := append(append([]sso.MiddlewareFunc{}, e.middlewares...), middlewares...)
	return &EchoRouter{
		engine:      e.engine,
		group:       e.group.Group(prefix),
		middlewares: all,
	}
}

func (e *EchoRouter) Use(middlewares ...sso.MiddlewareFunc) {
	e.middlewares = append(e.middlewares, middlewares...)
}

func (e *EchoRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	e.engine.ServeHTTP(w, r)
}

func (e *EchoRouter) wrapHandler(handler sso.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		ssoCtx := &echoContext{Context: c, values: sync.Map{}}
		for _, mw := range e.middlewares {
			mw(ssoCtx)
		}
		handler(ssoCtx)
		return nil
	}
}

type echoContext struct {
	echo.Context
	values sync.Map
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
