package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/yangwb1123/snaplink/domains/permissions"
	commercehttp "github.com/yangwb1123/snaplink/interfaces/commerce"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/rs"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

var errRouteContract = errors.New("billing: route is missing an admin authorization contract")

type routeKey struct {
	method string
	path   string
}

type contractState struct {
	contracts  map[routeKey]string
	registered map[routeKey]struct{}
	err        error
}

// contractRouter applies each declared RouteContract at registration time.
// A handler cannot accidentally inherit a method-wide default or mount without
// an exact contract: an unknown method/path is skipped and recorded as error.
type contractRouter struct {
	inner  core.Router
	prefix string
	state  *contractState
}

func newAdminContractRouter(inner core.Router) (*contractRouter, error) {
	if inner == nil {
		return nil, errRouteContract
	}
	state := &contractState{
		contracts: make(map[routeKey]string), registered: make(map[routeKey]struct{}),
	}
	machine := map[routeKey]string{
		{method: http.MethodGet, path: commercehttp.PathPaymentOrderRead}:    commercehttp.ScopePaymentOrderRead,
		{method: http.MethodPost, path: commercehttp.PathPaymentEventIngest}: commercehttp.ScopePaymentWrite,
	}
	for _, contract := range commercehttp.RouteContracts() {
		key := routeKey{method: contract.Method, path: contract.Path}
		if required, ok := machine[key]; ok {
			if contract.RequiredScope != required {
				return nil, errRouteContract
			}
			delete(machine, key)
			continue
		}
		if contract.RequiredScope != commercehttp.ScopeAdminRead &&
			contract.RequiredScope != commercehttp.ScopeAdminWrite {
			return nil, errRouteContract
		}
		if _, duplicate := state.contracts[key]; duplicate {
			return nil, errRouteContract
		}
		state.contracts[key] = contract.RequiredScope
	}
	if len(machine) != 0 {
		return nil, errRouteContract
	}
	return &contractRouter{inner: inner, state: state}, nil
}

func (router *contractRouter) Err() error { return router.state.err }

func (router *contractRouter) ValidateComplete() error {
	if router.state.err != nil || len(router.state.registered) != len(router.state.contracts) {
		return errRouteContract
	}
	return nil
}

func (router *contractRouter) GET(path string, handler core.HandlerFunc) {
	router.register(http.MethodGet, path, handler)
}

func (router *contractRouter) POST(path string, handler core.HandlerFunc) {
	router.register(http.MethodPost, path, handler)
}

func (router *contractRouter) PUT(path string, handler core.HandlerFunc) {
	router.register(http.MethodPut, path, handler)
}

func (router *contractRouter) PATCH(path string, handler core.HandlerFunc) {
	router.register(http.MethodPatch, path, handler)
}

func (router *contractRouter) DELETE(path string, handler core.HandlerFunc) {
	router.register(http.MethodDelete, path, handler)
}

func (router *contractRouter) register(method, path string, handler core.HandlerFunc) {
	fullPath := joinRoutePath(router.prefix, path)
	scope, ok := router.state.contracts[routeKey{method: method, path: fullPath}]
	if !ok {
		if router.state.err == nil {
			router.state.err = errRouteContract
		}
		return
	}
	if _, duplicate := router.state.registered[routeKey{method: method, path: fullPath}]; duplicate {
		router.state.err = errRouteContract
		return
	}
	router.state.registered[routeKey{method: method, path: fullPath}] = struct{}{}
	protected := router.inner.Group("", adminScopeGate(scope))
	registerMethod(protected, method, path, handler)
}

func registerMethod(router core.Router, method, path string, handler core.HandlerFunc) {
	switch method {
	case http.MethodGet:
		router.GET(path, handler)
	case http.MethodPost:
		router.POST(path, handler)
	case http.MethodPut:
		router.PUT(path, handler)
	case http.MethodPatch:
		router.PATCH(path, handler)
	case http.MethodDelete:
		router.DELETE(path, handler)
	}
}

func (router *contractRouter) Group(prefix string, middleware ...core.MiddlewareFunc) core.Router {
	return &contractRouter{
		inner: router.inner.Group(prefix, middleware...), prefix: joinRoutePath(router.prefix, prefix),
		state: router.state,
	}
}

func (router *contractRouter) Use(middleware ...core.MiddlewareFunc) {
	router.inner.Use(middleware...)
}

func (router *contractRouter) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	router.inner.ServeHTTP(writer, request)
}

func joinRoutePath(prefix, path string) string {
	if prefix == "" {
		return "/" + strings.TrimPrefix(path, "/")
	}
	if path == "" || path == "/" {
		return "/" + strings.Trim(prefix, "/")
	}
	return "/" + strings.Trim(prefix, "/") + "/" + strings.TrimPrefix(path, "/")
}

func adminScopeGate(required string) core.MiddlewareFunc {
	return func(ctx core.HandlerContext) {
		claims, ok := rs.ClaimsFromContext(ctx.Request().Context())
		if !ok || claims == nil {
			writeScopeFailure(ctx, http.StatusUnauthorized, core.ErrInvalidToken, "")
			return
		}
		if !matchesRequiredScope(claims, required) {
			writeScopeFailure(ctx, http.StatusForbidden, commercehttp.ErrorInsufficientScope, required)
		}
	}
}

func matchesRequiredScope(claims *rs.Claims, required string) bool {
	granted := make([]permissions.Permission, 0, len(claims.Scopes()))
	for _, scope := range claims.Scopes() {
		granted = append(granted, permissions.Permission{Code: scope})
	}
	return permissions.Matches(granted, required)
}

func writeScopeFailure(ctx core.HandlerContext, status int, code, scope string) {
	headers := ctx.ResponseWriter().Header()
	headers.Set("Cache-Control", "no-store")
	headers.Set("Pragma", "no-cache")
	challenge := "Bearer realm=" + security.QuoteAuthParam("billing")
	challenge += ", error=" + security.QuoteAuthParam(code)
	if scope != "" {
		challenge += ", scope=" + security.QuoteAuthParam(scope)
	}
	headers.Set("WWW-Authenticate", challenge)
	ctx.JSON(status, core.ErrorBody(code))
	ctx.Abort()
}

var _ core.Router = (*contractRouter)(nil)
