package selfserviceaccount

import (
	"errors"
	"net/http"

	"github.com/snaplink/sso/domains/identitylink"
	"github.com/snaplink/sso/shared/core"
)

// HandleMyIdentities serves GET /me/identities — lists the authenticated
// user's linked external identities (federated IdP subjects, or another
// local account folded in). Credential-adjacent; same cache headers as
// /userinfo. See domains/identitylink for the feature this backs.
func HandleMyIdentities(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	links, err := d.IdentityLinkStore().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list identity links failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if links == nil {
		links = []identitylink.Identity{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"identities": links})
}

// HandleUnlinkMyIdentity serves DELETE /me/identities/:id — removes one of
// the authenticated user's own linked identities. Guards against unlinking
// the user's LAST remaining authentication method (identitylink.GuardUnlink)
// so a user can never lock themselves out via this endpoint: unlinking a
// SOLE remaining identity is refused with 409 identity_unlink_last_method
// UNLESS the account also has a local password credential (checked via the
// OPTIONAL identitylink.PasswordPresenceChecker capability — see its doc for
// the fail-closed behavior when a wired PasswordCredentialStore doesn't
// implement it).
//
// An id belonging to another user, or unknown, responds with the same 404 as
// the session/MFA self-service endpoints (oracle-safe: ownership is enforced
// via the user-scoped list, so a cross-user delete can never remove someone
// else's link).
func HandleUnlinkMyIdentity(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	linkID := ctx.Param("id")
	if linkID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	links, err := d.IdentityLinkStore().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list identity links failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	target, found := findIdentityByID(links, linkID)
	if !found {
		// Not owned by this user, or never existed — one response either way.
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	if err := identitylink.GuardUnlink(len(links), hasOtherAuthMethod(d, ctx, userID)); err != nil {
		ctx.JSON(http.StatusConflict, d.ErrorBody(core.ErrIdentityUnlinkLastMethod))
		return
	}
	if err := d.IdentityLinkStore().Unlink(ctx.Request().Context(), userID, linkID); err != nil {
		if errors.Is(err, identitylink.ErrNotFound) {
			ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("unlink identity failed", "user_id", userID, "link_id", linkID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	d.RecordIdentityUnlinked(ctx, userID, linkID, target.Provider)
	ctx.JSON(http.StatusNoContent, nil)
}

// findIdentityByID returns the link matching id within links (the caller's
// own, already user-scoped list), and whether it was found.
func findIdentityByID(links []identitylink.Identity, id string) (identitylink.Identity, bool) {
	for _, l := range links {
		if l.ID == id {
			return l, true
		}
	}
	return identitylink.Identity{}, false
}

// hasOtherAuthMethod reports whether userID has a usable authentication
// method OTHER than their identity links — today, a local password
// credential. See identitylink.PasswordPresenceChecker for why a
// PasswordCredentialStore that doesn't implement it is treated as false
// (fail closed: never silently allow a lockout).
func hasOtherAuthMethod(d Deps, ctx core.HandlerContext, userID string) bool {
	store := d.PasswordCredentialStore()
	if store == nil {
		return false
	}
	checker, ok := store.(identitylink.PasswordPresenceChecker)
	if !ok {
		return false
	}
	has, err := checker.HasPassword(ctx.Request().Context(), userID)
	if err != nil {
		return false
	}
	return has
}
