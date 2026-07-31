package admin

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

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
		_ = d.RevokeToken(rctx, cred.Token)
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
type derivedCredentialResult struct {
	IdempotencyKey string `json:"idempotency_key"`
	Kind           string `json:"kind"`
	ID             string `json:"id"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
}

func cascadeRevokeSessions(d Deps, ctx context.Context, sessionIDs []string) []derivedCredentialResult {
	out := make([]derivedCredentialResult, 0, len(sessionIDs))
	for _, sid := range sessionIDs {
		result := derivedCredentialResult{
			IdempotencyKey: "break-glass:session:" + sid,
			Kind:           "session", ID: sid, Status: "revoked",
		}
		if d.SessionMgr() == nil {
			result.Status, result.Error = "failed", "session manager is not configured"
		} else if err := d.SessionMgr().Destroy(ctx, sid); err != nil {
			result.Status, result.Error = "failed", err.Error()
		}
		out = append(out, result)
	}
	return out
}

func cascadeRevokeImpersonationTokens(
	d Deps, ctx context.Context, tokens []string,
) []derivedCredentialResult {
	out := make([]derivedCredentialResult, 0, len(tokens))
	for _, tok := range tokens {
		sum := sha256.Sum256([]byte(tok))
		id := fmt.Sprintf("token_%x", sum[:8])
		result := derivedCredentialResult{
			IdempotencyKey: "break-glass:token:" + id,
			Kind:           "token", ID: id, Status: "revoked",
		}
		if err := d.RevokeToken(ctx, tok); err != nil {
			result.Status, result.Error = "failed", err.Error()
		}
		out = append(out, result)
	}
	return out
}

func allDerivedCredentialsRevoked(results []derivedCredentialResult) bool {
	for _, result := range results {
		if result.Status != "revoked" {
			return false
		}
	}
	return true
}

func writeBreakGlassCompensation(
	ctx core.HandlerContext, grantID string, results []derivedCredentialResult,
) {
	status := http.StatusInternalServerError
	if !allDerivedCredentialsRevoked(results) {
		status = http.StatusMultiStatus
	}
	ctx.JSON(status, map[string]any{
		core.KeyError: "break_glass_activation_failed", "grant_id": grantID,
		"grant_status": "revoked", "credential_results": results,
	})
}

// HandleAdminGetBranding returns tenant branding settings.
func HandleAdminGetBranding(d BrandingDeps, ctx core.HandlerContext) {
	tenantID := ctx.Query("tenant_id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store, ok := d.TenantStore().(tenant.BrandingStore)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrNotFound))
		return
	}
	branding, err := store.GetBranding(ctx.Request().Context(), tenantID)
	if err != nil {
		writeBrandingStoreError(d, ctx, err)
		return
	}
	writeBrandingResponse(ctx, tenantID, branding)
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
	updateBranding(d, ctx, tenantID, req.Branding)
}

// HandleAdminDeleteBranding clears tenant branding settings.
func HandleAdminDeleteBranding(d BrandingDeps, ctx core.HandlerContext) {
	tenantID := ctx.Query("tenant_id")
	if tenantID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	updateBranding(d, ctx, tenantID, map[string]string{})
}

func updateBranding(
	d BrandingDeps, ctx core.HandlerContext, tenantID string, values map[string]string,
) {
	expected, ok := parseBrandingETag(ctx.Request().Header.Get("If-Match"))
	if !ok {
		ctx.JSON(http.StatusPreconditionRequired, d.ErrorBodyDesc(
			core.ErrInvalidRequest, "a current branding If-Match value is required",
		))
		return
	}
	store, ok := d.TenantStore().(tenant.BrandingStore)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrNotFound))
		return
	}
	branding, err := store.PutBranding(ctx.Request().Context(), tenantID, values, expected)
	if err != nil {
		writeBrandingStoreError(d, ctx, err)
		return
	}
	writeBrandingResponse(ctx, tenantID, branding)
}

func writeBrandingResponse(ctx core.HandlerContext, tenantID string, branding tenant.Branding) {
	ctx.ResponseWriter().Header().Set("ETag", brandingETag(branding.Version))
	ctx.JSON(http.StatusOK, map[string]any{
		"status": "ok", "tenant_id": tenantID,
		"branding": branding.Values, "version": branding.Version,
	})
}

func writeBrandingStoreError(d BrandingDeps, ctx core.HandlerContext, err error) {
	switch {
	case errors.Is(err, tenant.ErrBrandingPrecondition):
		ctx.JSON(http.StatusPreconditionFailed, d.ErrorBodyDesc(
			core.ErrInvalidRequest, "branding changed; refresh before saving",
		))
	case errors.Is(err, tenant.ErrTenantNotFound):
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
	default:
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
	}
}

func brandingETag(version string) string { return `"branding-` + version + `"` }

func parseBrandingETag(value string) (string, bool) {
	value = strings.TrimSpace(value)
	if len(value) < len(`"branding-0"`) || value[0] != '"' || value[len(value)-1] != '"' {
		return "", false
	}
	version := strings.TrimSuffix(strings.TrimPrefix(value, `"branding-`), `"`)
	if version == "" || strings.ContainsAny(version, `" ,`) {
		return "", false
	}
	return version, true
}

// BrandingDeps is what the admin branding handlers need.
type BrandingDeps interface {
	TenantStore() tenant.Store
	ErrorBody(code string) map[string]any
	ErrorBodyDesc(code, desc string) map[string]any
}
