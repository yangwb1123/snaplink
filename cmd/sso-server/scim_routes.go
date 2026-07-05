package main

import (
	"net/http"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/admin"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/lifecycle/webhook"
	"github.com/snaplink/sso/protocols/scim"
	"github.com/snaplink/sso/protocols/scimprovision"
	"github.com/snaplink/sso/shared/core"
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
	opts := []scim.Option{
		scim.WithRecorder(recorder),
		// /Me resolves to the bearer's own user resource. The AdminMiddleware
		// that gates SCIM records the authenticated actor in the request
		// context; ActorFromContext recovers its user id.
		scim.WithMeResolver(func(r *http.Request) (string, bool) {
			userID, _, ok := admin.ActorFromContext(r.Context())
			return userID, ok
		}),
	}
	groupsEnabled := groups != nil && groups.provider != nil
	if groupsEnabled {
		// Pass the authz-policy-bundle invalidator so a SCIM group role
		// create/rename/delete evicts the local bundle cache + publishes
		// KindAuthzPolicyChange to peers (matching the gRPC PermissionAdmin path).
		opts = append(opts, scim.WithGroups(groups.provider, groups.clientID, srv.InvalidateAuthzPolicyBundleCache))
	}
	h := scim.NewHandler(users, scimBasePath, opts...)
	serve := func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }

	for _, rt := range scimRouteTable(groupsEnabled) {
		if err := srv.Handle(rt.method, rt.path, serve); err != nil {
			return err
		}
	}
	return nil
}

type scimRoute struct {
	method string
	path   string
}

// scimRouteTable enumerates every SCIM route shape registered on the router.
// Groups routes append only when groupsEnabled (they require a
// permissions.Provider). Kept separate so mountSCIMRoutes stays a thin wiring
// loop and the route inventory is reviewable in one place.
func scimRouteTable(groupsEnabled bool) []scimRoute {
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
		// Bulk (RFC 7644 §3.7).
		{http.MethodPost, scimBasePath + "/Bulk"},
		// /Me alias (RFC 7644 §3.11) — the bearer's own resource.
		{http.MethodGet, scimBasePath + "/Me"},
		{http.MethodPut, scimBasePath + "/Me"},
		{http.MethodPatch, scimBasePath + "/Me"},
		{http.MethodDelete, scimBasePath + "/Me"},
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
	return routes
}

// wireSCIMProvisioning builds the OUTBOUND SCIM 2.0 provisioning push
// (protocols/scimprovision) — the reverse direction of mountSCIMRoutes'
// inbound receiver — and wires it as an additional audit Sink
// (sso.WithSCIMProvisioner, the same AddSink/MultiSink seam
// wireWebhookEngine uses). Default-off: skipping this leaves b.opts
// untouched, so a build without scim.push.enabled is byte-identical.
//
// GroupClientID falls back to scim.groups.group_client_id so a deployment
// that already configured inbound Groups doesn't have to repeat itself; a
// nil b.provider (permissions not configured) is safe — group/role events
// simply become no-ops, matching how the inbound receiver's own /Groups
// surface is independently optional.
func (b *appBuilder) wireSCIMProvisioning() {
	pc := b.cfg.SCIM.Push
	if !pc.Enabled {
		return
	}
	groupClientID := pc.GroupClientID
	if groupClientID == "" {
		groupClientID = b.cfg.SCIM.Groups.GroupClientID
	}

	var provOpts []scimprovision.HTTPOption
	if pc.BearerToken != "" {
		provOpts = append(provOpts, scimprovision.WithBearerToken(pc.BearerToken))
	}
	if pc.Timeout > 0 {
		provOpts = append(provOpts, scimprovision.WithHTTPTimeout(pc.Timeout))
	}
	provisioner := scimprovision.NewHTTPSCIMProvisioner(pc.BaseURL, provOpts...)

	sinkOpts := []scimprovision.Option{
		scimprovision.WithLogger(b.logger),
		scimprovision.WithFailureRecorder(b.recorder),
		// Process-local dead-letter ring (mirrors wireWebhookEngine's
		// MemoryDeadLetterStore — a restart loses undelivered entries,
		// the same discipline the primary audit ring buffer has).
		scimprovision.WithDeadLetterStore(webhook.NewMemoryDeadLetterStore(0)),
	}
	if pc.Retry.MaxAttempts > 0 || pc.Retry.InitialBackoff > 0 || pc.Retry.MaxBackoff > 0 {
		sinkOpts = append(sinkOpts, scimprovision.WithDeliveryRetry(pc.Retry.MaxAttempts, pc.Retry.InitialBackoff, pc.Retry.MaxBackoff))
	}
	sink := scimprovision.NewSink(b.userProvider, b.provider, groupClientID, provisioner, sinkOpts...)
	b.opts = append(b.opts, sso.WithSCIMProvisioner(sink))
	b.logger.Info("scim: outbound provisioning push enabled", "base_url", pc.BaseURL, "group_client_id", groupClientID)
}
