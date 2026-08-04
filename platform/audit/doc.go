// Package audit records security-relevant events from the SSO server (logins,
// logouts, token issuance, code sends, etc.) into a pluggable Sink and
// supports filtered querying.
//
// The package has zero dependency on the sso package — the sso package
// imports audit and creates Events from its internal state. Callers who want
// to write events from other layers (a custom Authenticator, a downstream
// gateway) can use the same Recorder/Sink without going through sso.
package audit

import "github.com/yangwb1123/snaplink/shared/core"

// RoutesDeps is what MountRoutes needs beyond the handler deps: the audit-API
// enable flag (WithAuditAPI) — a boot-time wiring decision the mount branches
// on. *sso.Server satisfies it via accessors.
type RoutesDeps interface {
	HandlerDeps
	AuditAPI() bool
}

// MountRoutes registers the admin audit-query surface (GET /api/v1/audit/*)
// on the /api/v1 admin group, wrapped in a core.GatedRouter keyed on the
// AdminAPI live gate. Byte-identical to the registration interfaces/sso
// performed before this direction: mounted only when the audit API is
// enabled AND an Auditor is wired; gate must be non-nil — the Server's live
// adminAPIGateOn method value; nil is a programmer error.
func MountRoutes(r core.Router, d RoutesDeps, gate func() bool) {
	if gate == nil {
		panic("audit: MountRoutes requires a non-nil gate")
	}
	if !d.AuditAPI() || d.Auditor() == nil {
		return
	}
	api := core.NewGatedRouter(r.Group(core.PathAPIPrefix), gate)
	api.GET(core.PathAuditEvents, func(ctx core.HandlerContext) { HandleEvents(d, ctx) })
	api.GET(core.PathAuditEventByID, func(ctx core.HandlerContext) { HandleEventByID(d, ctx) })
	api.GET(core.PathAuditFacets, func(ctx core.HandlerContext) { HandleFacets(d, ctx) })
}
