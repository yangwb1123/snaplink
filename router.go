package sso

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
)

// HandlerContext is the interface passed to all handlers and middleware.
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
}

// Router abstracts the HTTP routing layer so the SSO server can work with any framework.
type Router interface {
	GET(path string, handler HandlerFunc)
	POST(path string, handler HandlerFunc)
	PUT(path string, handler HandlerFunc)
	DELETE(path string, handler HandlerFunc)
	Group(prefix string, middlewares ...MiddlewareFunc) Router
	Use(middlewares ...MiddlewareFunc)
	ServeHTTP(w http.ResponseWriter, r *http.Request)
}

// HandlerFunc is the signature for route handlers.
type HandlerFunc func(ctx HandlerContext)

// MiddlewareFunc is the signature for middleware.
type MiddlewareFunc func(ctx HandlerContext)

// Context implements HandlerContext using the standard library.
type Context struct {
	w      http.ResponseWriter
	r      *http.Request
	params map[string]string
	values sync.Map
}

func NewContext(w http.ResponseWriter, r *http.Request) *Context {
	return &Context{
		w:      w,
		r:      r,
		params: make(map[string]string),
	}
}

func (c *Context) Request() *http.Request              { return c.r }
func (c *Context) ResponseWriter() http.ResponseWriter { return c.w }
func (c *Context) Param(name string) string            { return c.params[name] }
func (c *Context) Query(name string) string            { return c.r.URL.Query().Get(name) }

func (c *Context) Bind(v any) error {
	return json.NewDecoder(c.r.Body).Decode(v)
}

func (c *Context) JSON(code int, v any) {
	c.w.Header().Set(HeaderContentType, ContentTypeJSON)
	c.w.WriteHeader(code)
	json.NewEncoder(c.w).Encode(v)
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
}

// StdRouter implements Router using the standard library. Groups share the
// same underlying route table via a pointer so child registrations are
// visible at the root.
type StdRouter struct {
	mux         *http.ServeMux
	prefix      string // group prefix, prepended to every registered path
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

func (r *StdRouter) DELETE(path string, handler HandlerFunc) {
	r.register(http.MethodDelete, path, handler)
}

func (r *StdRouter) register(method, path string, handler HandlerFunc) {
	*r.routes = append(*r.routes, StdRoute{
		path:        r.prefix + r.buildPath(path),
		method:      method,
		handler:     handler,
		middlewares: append([]MiddlewareFunc{}, r.middlewares...),
	})
}

// Group returns a child router whose registrations are prefixed with the
// given path and inherit the parent's middlewares (plus any new ones).
// Routes registered on the child end up in the same table the root serves.
func (r *StdRouter) Group(prefix string, middlewares ...MiddlewareFunc) Router {
	return &StdRouter{
		mux:         r.mux,
		prefix:      r.prefix + r.buildPath(prefix),
		middlewares: append(append([]MiddlewareFunc{}, r.middlewares...), middlewares...),
		routes:      r.routes,
	}
}

func (r *StdRouter) Use(middlewares ...MiddlewareFunc) {
	r.middlewares = append(r.middlewares, middlewares...)
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
		extractParams(ctx, route.path, req.URL.Path)
		for _, mw := range route.middlewares {
			mw(ctx)
		}
		route.handler(ctx)
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
