package rebac

import "github.com/yangwb1123/snaplink/shared/core"

// RoutesDeps is the union of the FGA product-API and admin-check handler
// deps. *sso.Server satisfies it via accessors.
type RoutesDeps interface {
	TupleDeps
	HandlerDeps
}

// MountRoutes registers the ReBAC surface: the FGA product API (tuple CRUD +
// Check + Batch + Graph, client-credentials-gated by the handlers themselves)
// on r directly, and the ONE operational-debugging admin route
// (GET /api/v1/admin/rebac/check) on the /api/v1 admin group wrapped in a
// core.GatedRouter keyed on the AdminAPI live gate. Byte-identical to the
// registrations interfaces/sso performed before this direction: the product
// routes mount only with a relation-tuple store, the Check routes only with
// an engine. gate must be non-nil — the Server's live adminAPIGateOn method
// value; nil is a programmer error.
func MountRoutes(r core.Router, d RoutesDeps, gate func() bool) {
	if gate == nil {
		panic("rebac: MountRoutes requires a non-nil gate")
	}
	if d.RebacStore() != nil {
		r.POST(core.PathAuthzTuples, func(ctx core.HandlerContext) { HandleWriteTuple(d, ctx) })
		r.GET(core.PathAuthzTuples, func(ctx core.HandlerContext) { HandleReadTuples(d, ctx) })
		r.DELETE(core.PathAuthzTuples, func(ctx core.HandlerContext) { HandleDeleteTuple(d, ctx) })
		r.POST(core.PathAuthzTuplesBatch, func(ctx core.HandlerContext) { HandleBatchWriteTuples(d, ctx) })
		r.GET(core.PathAuthzGraph, func(ctx core.HandlerContext) { HandleReverseExpand(d, ctx) })
	}
	if d.RebacEngine() != nil {
		r.GET(core.PathAuthzCheck, func(ctx core.HandlerContext) { HandleCheckAccess(d, ctx) })
		api := core.NewGatedRouter(r.Group(core.PathAPIPrefix), gate)
		api.GET(core.PathAdminRebacCheck, func(ctx core.HandlerContext) { HandleCheck(d, ctx) })
	}
}

// MountHotCheckRoute registers the product check route through the active
// generation slot when the engine owns a lifecycle runtime. It uses fallback
// for custom routers without match-time lease support.
func MountHotCheckRoute(r core.Router, d TupleDeps, fallback core.HandlerFunc) {
	if r == nil || d == nil || d.RebacEngine() == nil {
		return
	}
	runtime := d.RebacEngine().HotRuntime()
	if runtime != nil && runtime.RegisterCheckRoute(r, d) {
		return
	}
	r.GET(core.PathAuthzCheck, fallback)
}
