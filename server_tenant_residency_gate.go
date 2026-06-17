package sso

import (
	"net/http"

	"github.com/snaplink/sso/region"
)

// residencyGateTokenGrant is the data-residency write-gate for the /token grant
// endpoint. Token issuance is the WRITE side of residency, but previously only
// the interactive-login mint (residencyGateLogin) and the resource read
// (residencyDeniedForAccess) were gated — so a refresh rotation, token-exchange,
// CIBA, device, or authorization_code mint executed from a disallowed serving
// region slipped through, minting fresh credentials for a region-constrained
// tenant outside its residency boundary. The login write-gate is the primary
// control, but a refresh/exchange that rotates a previously-issued grant never
// re-traversed it; this closes that grant-side hole.
//
// The /token handler authenticates the client up-front and runs inside the
// HandlerContext pipeline, so the live serving region the region middleware
// stashed is in scope here — no plumbing through the bare-context issuance
// helpers is needed (the choke point has everything). Gate on the client's
// tenant: a grant carries no tenant of its own, and client.TenantID is the same
// binding the read-gate resolves. isWrite=true so EnforceWrites applies (a mint
// in a non-home region for a write-enforced tenant is blocked, matching login).
//
// Oracle-safe: runs ONLY after the client is authenticated (HTTP Basic / body
// secret / private_key_jwt all verified above), so it can't probe residency
// without valid client credentials. region_not_allowed / residency_violation
// are governance codes — exactly like the tenant_mismatch 403 already on this
// endpoint — not credential oracles, so they keep their distinct wire codes.
// The /token error shape (errorBody, no RFC 9207 iss) mirrors that sibling
// tenant_mismatch denial rather than the authorization-response authzErrorBody.
//
// Returns true when it WROTE the 403 and the caller MUST return without minting;
// false when the mint may proceed. Byte-identical when residency is unwired or
// no serving region is resolved: the first guard returns false before any work.
func (s *Server) residencyGateTokenGrant(ctx HandlerContext, client *Client) (handled bool) {
	if !s.tenantResidencyEnabled || client == nil || client.TenantID == "" {
		return false
	}
	servingRegion, ok := region.FromHandlerContext(ctx)
	if !ok || servingRegion == "" {
		return false
	}
	if err := s.checkTenantResidency(ctx.Request().Context(), client.TenantID, servingRegion, true); err != nil {
		ctx.JSON(http.StatusForbidden, errorBody(s.mapResidencyError(err)))
		return true
	}
	return false
}
