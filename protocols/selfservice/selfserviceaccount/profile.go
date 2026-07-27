package selfserviceaccount

import (
	"net/http"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// safeProfileAttrs is the OIDC Core §5.1 standard-claim set — the ONLY
// User.Attributes keys safe to return from the self-service /me profile view.
// DEFAULT-DENY: User.Attributes is a shared bag that also holds credentials
// (password_hash, seeded_password) and internal metadata; only the operator-
// visible profile keys belong in an API response. Matches the allowlist that
// /userinfo enforces (protocols/oidc/oidcsupport).
var safeProfileAttrs = map[string]struct{}{
	"name": {}, "given_name": {}, "family_name": {}, "middle_name": {},
	"nickname": {}, "preferred_username": {}, "profile": {}, "picture": {},
	"website": {}, "email": {}, "email_verified": {}, "gender": {},
	"birthdate": {}, "zoneinfo": {}, "locale": {}, "phone_number": {},
	"phone_number_verified": {}, "address": {}, "updated_at": {},
}

// sanitizeProfileUser returns a shallow copy of u with Attributes filtered to
// the allowlist above so credentials never appear in /me responses.
func sanitizeProfileUser(u *core.User) *core.User {
	if u == nil {
		return u
	}
	var clean map[string]string
	for k, v := range u.Attributes {
		if _, ok := safeProfileAttrs[k]; ok {
			if clean == nil {
				clean = make(map[string]string, len(u.Attributes))
			}
			clean[k] = v
		}
	}
	cp := *u
	cp.Attributes = clean
	return &cp
}

// HandleMe serves GET /me — the authenticated user's self-service account
// overview: their own profile plus active-session and granted-app counts. The
// landing entry for a self-service portal, consolidating data the SPA would
// otherwise assemble from /sessions/me + /consents/me + the token.
//
// Credential-adjacent (same no-store headers as /userinfo). Each enrichment is
// best-effort: a store outage drops that field rather than failing the whole
// response, and the sub/iss baseline is always present.
func HandleMe(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	userID := claims.Subject
	out := map[string]any{
		core.KeyIss: d.ResolveIssuer(ctx),
		core.KeySub: userID,
	}
	if up := d.UserProvider(); up != nil {
		if u, err := up.GetByID(ctx.Request().Context(), userID); err == nil && u != nil {
			out["user"] = sanitizeProfileUser(u)
		}
	}
	if sm := d.SessionManager(); sm != nil {
		if sessions, err := sm.ListByUser(ctx.Request().Context(), userID); err == nil {
			out["active_sessions"] = len(sessions)
		}
	}
	if cs := d.ConsentStore(); cs != nil {
		if grants, err := cs.ListByUser(ctx.Request().Context(), userID); err == nil {
			out["granted_apps"] = len(grants)
		}
	}
	ctx.JSON(http.StatusOK, out)
}

// HandleMyProfileUpdate serves PATCH /me — the authenticated user edits their own
// profile. Body: {name?, attributes?}. The display name is always editable (an
// empty/omitted name leaves it unchanged); attributes are applied ONLY for
// keys in the operator's self-editable allowlist (WithSelfEditableProfileAttributes)
// — every other key is silently dropped, so a user can never escalate by
// writing an authz-relevant attribute the operator keeps alongside presentation
// data. Identity-critical fields (id, external_id, provider, email, timestamps)
// are never self-editable: email in particular needs a verification flow that
// lives outside self-service. Credential-adjacent: no-store headers.
func HandleMyProfileUpdate(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateWrite(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	userID := claims.Subject
	var req struct {
		Name       string            `json:"name"`
		Attributes map[string]string `json:"attributes"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	u, err := d.UserProvider().GetByID(ctx.Request().Context(), userID)
	if err != nil || u == nil {
		// The caller authenticated, so their record should exist; collapse a
		// lookup miss/outage into 404 rather than leak store internals.
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	if req.Name != "" {
		u.Name = req.Name
	}
	editable := d.SelfEditableAttrs()
	if len(req.Attributes) > 0 && len(editable) > 0 {
		if u.Attributes == nil {
			u.Attributes = make(map[string]string, len(req.Attributes))
		}
		for k, v := range req.Attributes {
			if _, allowed := editable[k]; allowed {
				u.Attributes[k] = v
			}
		}
	}
	if err := d.UserProvider().CreateOrUpdate(ctx.Request().Context(), u); err != nil {
		d.Logger().Error("update profile failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"user": sanitizeProfileUser(u), core.KeyIss: d.ResolveIssuer(ctx)})
}
