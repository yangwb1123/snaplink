package ginadapter

import (
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/snaplink/sso"
)

// GinRouter adapts gin.Engine to sso.Router.
type GinRouter struct {
	engine      *gin.Engine
	group       *gin.RouterGroup
	middlewares []sso.MiddlewareFunc
}

func NewGinRouter(engine ...*gin.Engine) *GinRouter {
	e := gin.Default()
	if len(engine) > 0 {
		e = engine[0]
	}
	return &GinRouter{engine: e, group: &e.RouterGroup}
}

func (g *GinRouter) GET(path string, handler sso.HandlerFunc) {
	g.group.GET(path, g.wrapHandler(handler))
}

func (g *GinRouter) POST(path string, handler sso.HandlerFunc) {
	g.group.POST(path, g.wrapHandler(handler))
}

func (g *GinRouter) DELETE(path string, handler sso.HandlerFunc) {
	g.group.DELETE(path, g.wrapHandler(handler))
}

func (g *GinRouter) Group(prefix string, middlewares ...sso.MiddlewareFunc) sso.Router {
	all := append(append([]sso.MiddlewareFunc{}, g.middlewares...), middlewares...)
	return &GinRouter{
		engine:      g.engine,
		group:       g.group.Group(prefix),
		middlewares: all,
	}
}

func (g *GinRouter) Use(middlewares ...sso.MiddlewareFunc) {
	g.middlewares = append(g.middlewares, middlewares...)
}

func (g *GinRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.engine.ServeHTTP(w, r)
}

func (g *GinRouter) wrapHandler(handler sso.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		ssoCtx := &ginContext{Context: c, values: sync.Map{}}
		for _, mw := range g.middlewares {
			mw(ssoCtx)
		}
		handler(ssoCtx)
	}
}

type ginContext struct {
	*gin.Context
	values sync.Map
}

func (c *ginContext) Request() *http.Request {
	return c.Context.Request
}

func (c *ginContext) ResponseWriter() http.ResponseWriter {
	return c.Context.Writer
}

func (c *ginContext) Param(name string) string {
	return c.Context.Param(name)
}

func (c *ginContext) Query(name string) string {
	return c.Context.Query(name)
}

func (c *ginContext) Bind(v any) error {
	return c.Context.ShouldBindJSON(v)
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
