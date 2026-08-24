package configaudit

import "github.com/yangwb1123/snaplink/shared/core"

// RoutesDeps is what MountRoutes needs beyond the handler deps: a single
// boot-time wiring predicate collapsing the two snapshot-source fields
// (applied-snapshot + running-snapshot function) the mount branches on.
// *sso.Server satisfies it via accessors.
type RoutesDeps interface {
	HandlerDeps
	// ConfigSnapshotsWired reports whether at least one config-snapshot
	// source is wired (WithConfigSnapshots) — the mount condition for the
	// running/applied/diff/cluster-diff routes.
	ConfigSnapshotsWired() bool
}

// MountRoutes registers the admin config-audit surface (GET/POST
// /api/v1/admin/config/*) on the /api/v1 admin group, wrapped in a
// core.GatedRouter keyed on the AdminAPI live gate. Byte-identical to the
// registration interfaces/sso performed before this direction: snapshot
// routes mount only when a snapshot source exists; the history route mounts
// only with a config-audit store. gate must be non-nil — the Server's live
// adminAPIGateOn method value; nil is a programmer error.
func MountRoutes(r core.Router, d RoutesDeps, gate func() bool) {
	if gate == nil {
		panic("configaudit: MountRoutes requires a non-nil gate")
	}
	api := core.NewGatedRouter(r.Group(core.PathAPIPrefix), gate)
	if d.ConfigSnapshotsWired() {
		api.GET(core.PathAdminConfigRunning, func(ctx core.HandlerContext) { HandleRunning(d, ctx) })
		api.GET(core.PathAdminConfigApplied, func(ctx core.HandlerContext) { HandleApplied(d, ctx) })
		api.GET(core.PathAdminConfigDiff, func(ctx core.HandlerContext) { HandleDiff(d, ctx) })
		api.POST(core.PathAdminConfigClusterDiff, func(ctx core.HandlerContext) { HandleClusterDiff(d, ctx) })
	}
	if d.ConfigAuditStore() != nil {
		api.GET(core.PathAdminConfigHistory, func(ctx core.HandlerContext) { HandleHistory(d, ctx) })
	}
	// The declared peer-config baseline write path mounts only when BOTH a
	// snapshot source (the baseline's initial state + the response diff) and
	// a store (the baseline persistence) exist — a build with either missing
	// keeps today's route set byte-identical.
	if d.ConfigSnapshotsWired() && d.ConfigAuditStore() != nil {
		api.POST(core.PathAdminConfigApply, func(ctx core.HandlerContext) { HandleApply(d, ctx) })
		api.POST(core.PathAdminConfigRollback, func(ctx core.HandlerContext) { HandleRollback(d, ctx) })
	}
}
