package admin

import (
	"errors"
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

// Enterprise-connection email-domain ownership verification (DNS-TXT challenge).
// A domain routes to at most one connection; when verification is enabled on the
// store, a competing connection cannot steal a VERIFIED domain's home-realm
// routing without proving DNS control through the verify endpoint here.

// domainClaimJSON is the wire shape for one (connection, domain) claim.
//
// Token is intentionally returned in this admin listing: a DNS-TXT challenge
// token is published in public DNS by design (the proof is control of the DNS
// zone, ACME dns-01 style), so it is not a bearer secret and the admin needs it
// to create the TXT record. It is never logged.
type domainClaimJSON struct {
	Domain     string `json:"domain"`
	Status     string `json:"status"`
	Record     string `json:"record"`
	Token      string `json:"token"`
	CreatedAt  string `json:"created_at,omitempty"`
	VerifiedAt string `json:"verified_at,omitempty"`
}

func domainClaimToJSON(c *connections.DomainVerification) domainClaimJSON {
	j := domainClaimJSON{Domain: c.Domain, Status: string(c.Status), Record: c.Record, Token: c.Token}
	if !c.CreatedAt.IsZero() {
		j.CreatedAt = c.CreatedAt.UTC().Format(time.RFC3339)
	}
	if !c.VerifiedAt.IsZero() {
		j.VerifiedAt = c.VerifiedAt.UTC().Format(time.RFC3339)
	}
	return j
}

// HandleAdminListConnectionDomains serves GET
// /api/v1/admin/connections/:id/domains — the connection's OWN email-domain
// claims (pending + verified) with the DNS TXT record to publish. admin:read.
// 404 when the connection does not exist. Returns only this connection's claims
// (no cross-connection lookup).
func HandleAdminListConnectionDomains(d Deps, ctx core.HandlerContext) {
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.ConnectionStore()
	if _, err := store.Get(ctx.Request().Context(), id); err != nil {
		if errors.Is(err, connections.ErrNoConnection) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin list connection domains: get failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	claims, err := store.DomainClaims(ctx.Request().Context(), id)
	if err != nil {
		d.Logger().Error("admin list connection domains failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]domainClaimJSON, 0, len(claims))
	for _, c := range claims {
		out = append(out, domainClaimToJSON(c))
	}
	ctx.JSON(http.StatusOK, map[string]any{"domains": out})
}

// HandleAdminVerifyConnectionDomain serves POST
// /api/v1/admin/connections/:id/domains/:domain/verify — a synchronous DNS-TXT
// ownership check. admin:write. Returns 200 in BOTH outcomes (not-yet-verified
// is a state, not an error — mirrors /introspect's {"active":false}); 404 only
// when the connection has not claimed the domain. On a successful verification
// it invalidates the connection cache and audits the event.
func HandleAdminVerifyConnectionDomain(d Deps, ctx core.HandlerContext) {
	id, domain := ctx.Param("id"), ctx.Param("domain")
	if id == "" || domain == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.ConnectionStore()
	verified, err := connections.VerifyDomainOwnership(ctx.Request().Context(), store, d.DomainResolver(), id, domain, 0)
	if errors.Is(err, connections.ErrNoDomainClaim) {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	if err != nil {
		// Fail-closed: a store/lookup error is never reported as verified.
		d.Logger().Error("admin verify connection domain failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	claim, err := store.DomainClaim(ctx.Request().Context(), id, domain)
	if err != nil {
		d.Logger().Error("admin verify connection domain: reload failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if verified {
		d.InvalidateConnectionCache(id)
		recordConnectionDomainVerified(d, ctx, store, id)
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"verified": verified, "status": string(claim.Status),
		"record": claim.Record, "token": claim.Token,
	})
}

// recordConnectionDomainVerified emits the audit event with the owning tenant.
func recordConnectionDomainVerified(d Deps, ctx core.HandlerContext, store connections.Store, id string) {
	tenantID := ""
	if conn, err := store.Get(ctx.Request().Context(), id); err == nil {
		tenantID = conn.TenantID
	}
	recordAdminConnectionAction(d, ctx, audit.EventAdminConnectionDomainVerified, id, tenantID)
}
