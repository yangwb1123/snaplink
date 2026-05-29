package main

import (
	"net/http"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/scim"
)

// SCIM 2.0 mount prefix. Mounted on the SSO router (so it shares the
// middleware stack) and gated by AdminMiddleware via IsProtectedPath's
// /api/v1/scim/ entry: reads need admin:read, writes need admin:write
// (the middleware maps method -> scope). The "/v2" segment is the SCIM
// protocol version (RFC 7644).
const scimBasePath = "/api/v1/scim/v2"

// scimGroupDeps carries the optional /Groups wiring. Nil (or a nil
// Provider) leaves Groups unmounted — SCIM Users still mount. A SCIM
// group maps onto a permissions.Role under ClientID (members become role
// assignments), so Groups require a permissions.Provider.
type scimGroupDeps struct {
	provider permissions.Provider
	clientID string
}

// mountSCIMRoutes registers the SCIM provisioning endpoints. No-op without
// a UserProvider (nothing to provision against). Users (CRUD + PATCH) are
// always mounted; Groups (CRUD + PATCH) mount only when groups is non-nil
// with a Provider. The default router matches by exact segment count, so
// each SCIM route shape is registered explicitly and delegated to one
// scim.Handler, which strips scimBasePath and dispatches internally on the
// full path.
func mountSCIMRoutes(srv *sso.Server, users core.UserProvider, recorder *audit.Recorder, groups *scimGroupDeps) error {
	if srv == nil || users == nil {
		return nil
	}
	opts := []scim.Option{scim.WithRecorder(recorder)}
	groupsEnabled := groups != nil && groups.provider != nil
	if groupsEnabled {
		opts = append(opts, scim.WithGroups(groups.provider, groups.clientID))
	}
	h := scim.NewHandler(users, scimBasePath, opts...)
	serve := func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }

	type scimRoute struct {
		method string
		path   string
	}
	routes := []scimRoute{
		// Discovery (RFC 7643 §5 + §7).
		{http.MethodGet, scimBasePath + "/ServiceProviderConfig"},
		{http.MethodGet, scimBasePath + "/Schemas"},
		// Users collection (RFC 7644 §3.3 create + §3.4 list).
		{http.MethodGet, scimBasePath + "/Users"},
		{http.MethodPost, scimBasePath + "/Users"},
		// Single User resource (RFC 7644 §3.4.1 get + §3.5.1 replace +
		// §3.5.2 patch + §3.6 delete).
		{http.MethodGet, scimBasePath + "/Users/:id"},
		{http.MethodPut, scimBasePath + "/Users/:id"},
		{http.MethodPatch, scimBasePath + "/Users/:id"},
		{http.MethodDelete, scimBasePath + "/Users/:id"},
	}
	if groupsEnabled {
		routes = append(routes,
			// Groups collection (RFC 7643 §4.2 create + list).
			scimRoute{http.MethodGet, scimBasePath + "/Groups"},
			scimRoute{http.MethodPost, scimBasePath + "/Groups"},
			// Single Group resource (get + replace + patch + delete).
			scimRoute{http.MethodGet, scimBasePath + "/Groups/:id"},
			scimRoute{http.MethodPut, scimBasePath + "/Groups/:id"},
			scimRoute{http.MethodPatch, scimBasePath + "/Groups/:id"},
			scimRoute{http.MethodDelete, scimBasePath + "/Groups/:id"},
		)
	}
	for _, rt := range routes {
		if err := srv.Handle(rt.method, rt.path, serve); err != nil {
			return err
		}
	}
	return nil
}
