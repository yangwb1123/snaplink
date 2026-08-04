package wasmauthz

import "github.com/yangwb1123/snaplink/shared/core"

// MountRoutes registers the opt-in WASM authorization-engine debug route
// (POST /api/v1/admin/wasmauthz/check) on the /api/v1 admin group, wrapped
// in a core.GatedRouter keyed on the AdminAPI live gate — byte-identical to
// the registration interfaces/sso performed before this direction: not
// mounted without an engine, and hot-toggleable with the admin surface when
// one is wired. gate must be non-nil — the Server's live adminAPIGateOn
// method value; nil is a programmer error.
func MountRoutes(r core.Router, d HandlerDeps, gate func() bool) {
	if gate == nil {
		panic("wasmauthz: MountRoutes requires a non-nil gate")
	}
	if d.WASMAuthzEngine() == nil {
		return
	}
	api := core.NewGatedRouter(r.Group(core.PathAPIPrefix), gate)
	api.POST(core.PathAdminWASMAuthzCheck, func(ctx core.HandlerContext) { HandleCheck(d, ctx) })
}
