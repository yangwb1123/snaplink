package selfserviceaccount

import (
	"errors"
	"net/http"

	"github.com/snaplink/sso/shared/core"
)

// HandleMyConsents serves GET /consents/me — lists the authenticated user's
// consent grants. Credential-adjacent; same cache headers as /userinfo.
func HandleMyConsents(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	grants, err := d.ConsentStore().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list consents failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if grants == nil {
		grants = []core.ConsentGrant{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"consents": grants})
}

// HandleDeleteMyConsent serves DELETE /consents/me/:client_id — revokes the
// authenticated user's consent grant for a given client. Idempotent per the
// ConsentStore contract; a missing grant returns 404.
func HandleDeleteMyConsent(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	clientID := ctx.Param("client_id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if _, err := d.ConsentStore().GetConsent(ctx.Request().Context(), userID, clientID); err != nil {
		if errors.Is(err, core.ErrNoConsentGrant) {
			ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("get consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if err := d.ConsentStore().RevokeConsent(ctx.Request().Context(), userID, clientID); err != nil {
		d.Logger().Error("revoke consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	d.RecordConsentRevoked(ctx, userID, clientID)
	ctx.JSON(http.StatusNoContent, nil)
}
