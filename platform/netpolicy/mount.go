package netpolicy

import "github.com/yangwb1123/snaplink/shared/core"

// RoutesDeps is what MountRoutes needs beyond the handler deps: the
// net-policy API enable flag (WithNetPolicyAPI) — a boot-time wiring
// decision the mount branches on. *sso.Server satisfies it via accessors.
type RoutesDeps interface {
	HandlerDeps
	NetAPI() bool
}

// MountRoutes registers the network-policy admin surface (CRUD + classify +
// resolve-me under /api/v1/netpolicy/*) on the /api/v1 admin group, wrapped
// in a core.GatedRouter keyed on the AdminAPI live gate. Byte-identical to
// the registration interfaces/sso performed before this direction: mounted
// only when the net-policy API is enabled AND a store is wired. gate must be
// non-nil — the Server's live adminAPIGateOn method value; nil is a
// programmer error.
func MountRoutes(r core.Router, d RoutesDeps, gate func() bool) {
	if gate == nil {
		panic("netpolicy: MountRoutes requires a non-nil gate")
	}
	if !d.NetAPI() || d.NetStore() == nil {
		return
	}
	api := core.NewGatedRouter(r.Group(core.PathAPIPrefix), gate)
	api.GET(core.PathNetPolicies, func(ctx core.HandlerContext) { HandleList(d, ctx) })
	api.GET(core.PathNetPolicyByName, func(ctx core.HandlerContext) { HandleGet(d, ctx) })
	api.POST(core.PathNetPolicies, func(ctx core.HandlerContext) { HandleApply(d, ctx) })
	api.DELETE(core.PathNetPolicyByName, func(ctx core.HandlerContext) { HandleDelete(d, ctx) })
	api.GET(core.PathNetPolicyClassify, func(ctx core.HandlerContext) { HandleClassify(d, ctx) })
	api.GET(core.PathNetPolicyResolveMe, func(ctx core.HandlerContext) { HandleResolveMe(d, ctx) })
}
