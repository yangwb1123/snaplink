package admin

import (
	"context"
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

// Break-glass LIVE impersonation: an active+approved impersonate/escalate grant
// mints a bearer that authenticates AS the target user under the target's OWN
// permission boundary (NON-BYPASS). Split out of break_glass.go so neither file
// exceeds the per-file budget. Lives in the same package, so it reuses the
// shared helpers (recordBreakGlassEvent, ActorFromContext, the metaKey* keys).

// respKeyKind names the impersonation-response field that isn't already a core
// wire key, kept as a const to avoid a literal leak.
const respKeyKind = "kind"

// HandleImpersonateBreakGlass serves POST /api/v1/admin/break-glass/:id/impersonate
// — the grant's designated admin mints a LIVE bearer that authenticates AS the
// target user, for an ACTIVE + APPROVED impersonate/escalate grant ONLY.
// admin:write. The minted token carries the target user's OWN permission
// boundary (NON-BYPASS: sub=target, no admin scope, act=admin), expires no later
// than the grant window, and is registered under the grant so the existing
// revoke/expiry cascade destroys it. Records admin_break_glass_impersonation_started
// with the full SOC 2 evidence chain. readonly grants are STRUCTURALLY rejected
// here AND again at mint — no bearer can ever exist for them. No-store on the
// response (it carries a credential); the 401 challenge is owned by AdminMiddleware.
func HandleImpersonateBreakGlass(d Deps, ctx core.HandlerContext) {
	// No-store FIRST so EVERY response (200 AND the 403/404/409/500 errors below)
	// carries the credential-endpoint cache headers — an error path still touched
	// a credential-minting endpoint (RFC 6749 §5.1 / AGENTS.md credential contract).
	middleware.TokenNoStoreHeaders(ctx)
	store := d.BreakGlassStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()
	a, err := store.Get(rctx, id)
	if err != nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	if code, status, ok := checkImpersonable(rctx, a); !ok {
		ctx.JSON(status, core.ErrorBody(code))
		return
	}
	if refuseTargetPrivileged(d, ctx, a) {
		return
	}
	mintAndRespondImpersonation(d, ctx, store, a)
}

// refuseTargetPrivileged blocks minting an impersonation credential for a target
// that holds an admin scope — impersonating an admin would let support act with
// the ADMIN's OWN boundary, the one thing break-glass must never do. Fail-CLOSED:
// a permissions-provider error refuses (we cannot prove the target is safe). No
// provider wired ⇒ TargetHoldsAdminScope returns (false, nil) ⇒ the floor is a
// no-op, preserving break-glass for deployments without RBAC. clientID is the
// acting admin's token audience (the same the admin gate authorized against).
// Oracle-safe 403 with a generic code — the endpoint is already admin:write gated.
func refuseTargetPrivileged(d Deps, ctx core.HandlerContext, a core.AdminSession) bool {
	_, clientID, _ := ActorFromContext(ctx.Request().Context())
	privileged, err := d.TargetHoldsAdminScope(ctx.Request().Context(), a.TargetUserID, clientID)
	if err != nil {
		d.Logger().Error("break-glass target privilege check failed", "id", a.ID, "error", err)
	}
	if err != nil || privileged {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(core.ErrBreakGlassTargetPrivileged))
		return true
	}
	return false
}

// checkImpersonable is the gate a grant MUST clear before an impersonation
// bearer is minted. Order matters: scope first (readonly can NEVER impersonate),
// then live status (pending/expired/revoked all read as non-active after the
// store's lazy expiry), then ownership (only the grant's designated admin may
// act as the target — no other admin:write holder may hijack the grant).
func checkImpersonable(rctx context.Context, a core.AdminSession) (code string, status int, ok bool) {
	if a.Scope != core.AdminScopeImpersonate && a.Scope != core.AdminScopeEscalate {
		return core.ErrBreakGlassNotImpersonable, http.StatusForbidden, false
	}
	if a.Status != core.AdminSessionActive {
		return core.ErrBreakGlassNotActive, http.StatusConflict, false
	}
	actor, _, _ := ActorFromContext(rctx)
	if actor == "" || actor != a.AdminUserID {
		return core.ErrBreakGlassNotOwner, http.StatusForbidden, false
	}
	return "", 0, true
}

// mintAndRespondImpersonation mints the bearer, persists it onto the grant, and
// writes the credential response. AttachImpersonationToken re-checks the grant
// is still active under the store lock — if it ended in the race between the
// gate and here, the just-minted bearer is revoked so nothing outlives the
// window. Split from HandleImpersonateBreakGlass for the function-length budget.
func mintAndRespondImpersonation(d Deps, ctx core.HandlerContext, store core.BreakGlassStore, a core.AdminSession) {
	rctx := ctx.Request().Context()
	cred, err := d.MintImpersonationToken(rctx, a)
	if err != nil {
		d.Logger().Error("break-glass mint impersonation token failed", "id", a.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrImpersonationUnavailable))
		return
	}
	updated, err := store.AttachImpersonationToken(rctx, a.ID, cred.Token)
	if err != nil {
		d.RevokeToken(rctx, cred.Token)
		writeAttachError(ctx, d, a.ID, err)
		return
	}
	recordBreakGlassEvent(d, rctx, audit.ClientIP(ctx.Request()), audit.EventAdminBreakGlassImpersonationStarted, updated)
	// No-store headers were already set at HandleImpersonateBreakGlass entry so
	// every response (incl. errors) carries them; the 200 credential body inherits
	// them here without a second call.
	ctx.JSON(http.StatusOK, impersonationResponse(updated, cred))
}

// writeAttachError maps a BreakGlassStore.AttachImpersonationToken failure to its
// HTTP response. The just-minted token has ALREADY been revoked by the caller.
func writeAttachError(ctx core.HandlerContext, d Deps, id string, err error) {
	switch {
	case errors.Is(err, core.ErrAdminSessionNotActive):
		ctx.JSON(http.StatusConflict, core.ErrorBody(core.ErrBreakGlassNotActive))
	case errors.Is(err, core.ErrAdminSessionNotFound):
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
	default:
		d.Logger().Error("break-glass attach impersonation token failed", "id", id, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	}
}

// impersonationResponse is the credential body returned to the admin, echoing
// the evidence chain (admin_session_id/admin_id/target_user_id/kind) alongside
// the bearer so the caller knows exactly which grant it acts under.
func impersonationResponse(a core.AdminSession, cred core.ImpersonationCredential) map[string]any {
	return map[string]any{
		core.KeyAccessToken:   cred.Token,
		core.KeyTokenType:     cred.TokenType,
		core.KeyExpiresIn:     cred.ExpiresIn,
		core.KeySessionID:     cred.SessionID,
		metaKeyAdminSessionID: a.ID,
		metaKeyAdminID:        a.AdminUserID,
		metaKeyTargetUserID:   a.TargetUserID,
		respKeyKind:           core.SessionKindAdminImpersonation,
	}
}

// cascadeRevokeImpersonationTokens denies every impersonation bearer minted
// under a break-glass grant across all issuers, so a revoked/expired grant's
// live credential is invalidated the instant the window closes — the TTL bound
// on each token is only the backstop; this is what makes revocation IMMEDIATE
// (a stateless JWT can't self-revoke). Best-effort per token, mirroring the
// session cascade: one unknown/expired token can't abort the rest.
func cascadeRevokeImpersonationTokens(d Deps, ctx context.Context, tokens []string) {
	for _, tok := range tokens {
		d.RevokeToken(ctx, tok)
	}
}

// HandleAdminGetBranding returns tenant branding settings.
func HandleAdminGetBranding(d BrandingDeps, ctx core.HandlerContext) {
	tenantID := ctx.Query("tenant_id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.TenantStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	t, err := store.GetTenant(ctx.Request().Context(), tenantID)
	if err != nil || t == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	settings := t.Settings
	if settings == nil {
		settings = map[string]string{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"tenant_id": tenantID, "branding": settings})
}

// HandleAdminUpdateBranding updates tenant branding settings.
func HandleAdminUpdateBranding(d BrandingDeps, ctx core.HandlerContext) {
	tenantID := ctx.Query("tenant_id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Branding map[string]string `json:"branding"`
	}
	if err := ctx.Bind(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBodyDesc(core.ErrInvalidRequest, "invalid JSON"))
		return
	}
	if req.Branding == nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBodyDesc(core.ErrInvalidRequest, "branding object required"))
		return
	}
	store := d.TenantStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	t, err := store.GetTenant(ctx.Request().Context(), tenantID)
	if err != nil || t == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	t.Settings = req.Branding
	if err := store.PutTenant(ctx.Request().Context(), t); err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok", "tenant_id": tenantID, "branding": req.Branding})
}

// HandleAdminDeleteBranding clears tenant branding settings.
func HandleAdminDeleteBranding(d BrandingDeps, ctx core.HandlerContext) {
	tenantID := ctx.Query("tenant_id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.TenantStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	t, err := store.GetTenant(ctx.Request().Context(), tenantID)
	if err != nil || t == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	t.Settings = map[string]string{}
	if err := store.PutTenant(ctx.Request().Context(), t); err != nil {
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok", "tenant_id": tenantID})
}

// BrandingDeps is what the admin branding handlers need.
type BrandingDeps interface {
	TenantStore() tenant.Store
	ErrorBody(code string) map[string]any
	ErrorBodyDesc(code, desc string) map[string]any
}
