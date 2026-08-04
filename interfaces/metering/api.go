// Package meteringhttp exposes an API-only, machine-to-machine usage and
// entitlement surface. The authenticated client_id is resolved through
// server-owned source bindings; tenant and source never arrive over HTTP.
package meteringhttp

import (
	"net/http"

	"github.com/yangwb1123/snaplink/shared/core"
)

type RouteContract struct {
	Method        string
	Path          string
	RequiredScope string
}

func RouteContracts() []RouteContract {
	return []RouteContract{
		{Method: http.MethodPost, Path: PathUsageAppend, RequiredScope: ScopeMeteringWrite},
		{Method: http.MethodPost, Path: PathReservations, RequiredScope: ScopeMeteringWrite},
		{Method: http.MethodPost, Path: PathReservationCommit, RequiredScope: ScopeMeteringWrite},
		{Method: http.MethodDelete, Path: PathReservation, RequiredScope: ScopeMeteringWrite},
		{Method: http.MethodGet, Path: PathEntitlement, RequiredScope: ScopeEntitlementRead},
	}
}

type API struct {
	deps Deps
}

func New(deps Deps) (*API, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	return &API{deps: deps}, nil
}

// RegisterRoutes mounts only fixed, tenantless paths. The outer HTTP stack
// must first run rs.HTTPMiddleware; each route then enforces its own exact
// scope and resolves the signed client_id to one server-owned source binding.
func (a *API) RegisterRoutes(router core.Router) error {
	if router == nil {
		return ErrRouterRequired
	}
	write := router.Group("", a.authorize(ScopeMeteringWrite))
	write.POST(PathUsageAppend, a.HandleAppendUsage)
	write.POST(PathReservations, a.HandleReserve)
	write.POST(PathReservationCommit, a.HandleCommit)
	write.DELETE(PathReservation, a.HandleRelease)
	read := router.Group("", a.authorize(ScopeEntitlementRead))
	read.GET(PathEntitlement, a.HandleEntitlement)
	return nil
}

func Mount(router core.Router, deps Deps) (*API, error) {
	api, err := New(deps)
	if err != nil {
		return nil, err
	}
	if err := api.RegisterRoutes(router); err != nil {
		return nil, err
	}
	return api, nil
}

func privateNoStore(ctx core.HandlerContext) {
	headers := ctx.ResponseWriter().Header()
	headers.Set(headerCacheControl, cacheControlNoStore)
	headers.Set(headerPragma, pragmaNoCache)
}
