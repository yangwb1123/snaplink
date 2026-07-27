package tenant

import "github.com/yangwb1123/snaplink/shared/core"

// ClientOK reports whether the given client may be served from the
// request's resolved tenant context. Returns true when:
//   - the client has no TenantID (single-tenant deployment or
//     platform-admin client that belongs to no operator tenant), OR
//   - no tenant resolved on this request (tenant middleware not
//     wired, or unknown host) — pre-multi-tenant deployments never
//     resolved a tenant, and we don't want to suddenly reject every
//     request when the operator first enables a tenant store, OR
//   - the resolved tenant matches the client's TenantID.
//
// Returns false ONLY when both sides are set AND disagree — the
// genuine "client X belongs to tenant Y but is being requested
// under tenant Z" case.
func ClientOK(ctx core.HandlerContext, client *core.Client) bool {
	if client == nil || client.TenantID == "" {
		return true
	}
	r, ok := FromHandlerContext(ctx)
	if !ok || r == nil || r.Tenant == nil {
		return true
	}
	return r.Tenant.ID == client.TenantID
}
