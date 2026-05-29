package main

import (
	"net/http"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/scim"
)

// SCIM 2.0 mount prefix. Mounted on the SSO router (so it shares the
// middleware stack) and gated by AdminMiddleware via IsProtectedPath's
// /api/v1/scim/ entry: reads need admin:read, writes need admin:write
// (the middleware maps method -> scope). The "/v2" segment is the SCIM
// protocol version (RFC 7644).
const scimBasePath = "/api/v1/scim/v2"

// mountSCIMRoutes registers the SCIM User provisioning endpoints. No-op
// without a UserProvider (nothing to provision against). The default
// router matches by exact segment count, so each SCIM route shape is
// registered explicitly and delegated to one scim.Handler, which strips
// scimBasePath and dispatches internally on the full path.
func mountSCIMRoutes(srv *sso.Server, users core.UserProvider, recorder *audit.Recorder) error {
	if srv == nil || users == nil {
		return nil
	}
	h := scim.NewHandler(users, scimBasePath, scim.WithRecorder(recorder))
	serve := func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }

	routes := []struct {
		method string
		path   string
	}{
		// Discovery (RFC 7643 §5 + §7).
		{http.MethodGet, scimBasePath + "/ServiceProviderConfig"},
		{http.MethodGet, scimBasePath + "/Schemas"},
		// Users collection (RFC 7644 §3.3 create + §3.4 list).
		{http.MethodGet, scimBasePath + "/Users"},
		{http.MethodPost, scimBasePath + "/Users"},
		// Single User resource (RFC 7644 §3.4.1 get + §3.5.1 replace + §3.6 delete).
		{http.MethodGet, scimBasePath + "/Users/:id"},
		{http.MethodPut, scimBasePath + "/Users/:id"},
		{http.MethodDelete, scimBasePath + "/Users/:id"},
	}
	for _, rt := range routes {
		if err := srv.Handle(rt.method, rt.path, serve); err != nil {
			return err
		}
	}
	return nil
}
