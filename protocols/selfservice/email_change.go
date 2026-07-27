package selfservice

import (
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// HandleMyEmailChange serves POST /me/email/change — the first leg of a verified
// email change for the AUTHENTICATED bearer. Body: {new_email}. It mints a
// single-use token bound to (subject, new_email) and delivers it to the NEW
// address (proving the user controls it). Returns 200 {status:"sent"}. This is
// the verification flow PATCH /me deliberately routes email edits through.
// Credential-adjacent: no-store headers.
func HandleMyEmailChange(d Deps, ctx core.HandlerContext, userID string) {
	middleware.TokenNoStoreHeaders(ctx)
	var req struct {
		NewEmail string `json:"new_email"`
	}
	newEmail := ""
	if err := oauth.BindParams(ctx, &req); err == nil {
		newEmail = strings.TrimSpace(req.NewEmail)
	}
	// A new email is required + must look like an address (minimal sanity — full
	// validation is the deliverability of the token, which only the real owner
	// receives).
	if newEmail == "" || !strings.Contains(newEmail, "@") {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()
	token, err := d.GenerateAuthCodeBytes()
	if err != nil {
		d.Logger().Error("email change: mint token failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ttl := d.EmailChangeTTL()
	if ttl <= 0 {
		ttl = core.DefaultEmailChangeTTL
	}
	if err := d.EmailChangeStore().Issue(rctx, &core.EmailChangeToken{
		Token: token, UserID: userID, NewEmail: newEmail, ExpiresAt: time.Now().Add(ttl),
	}); err != nil {
		d.Logger().Error("email change: store issue failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if err := d.EmailChangeSender().SendEmailChangeToken(rctx, newEmail, token); err != nil {
		d.Logger().Error("email change: delivery failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if d.Auditor() != nil {
		evt := &audit.Event{Type: audit.EventEmailChangeRequested, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		d.Auditor().Record(rctx, evt)
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "sent"})
}

// HandleMyEmailVerify serves POST /me/email/verify — the second leg. Body:
// {token}. It consumes the token (single-use), checks it belongs to the
// authenticated bearer (a token delivered to a new address can only be
// completed by the user who started the change), and commits the new email via
// the UserProvider. Oracle-safe: unknown/expired/consumed token, or a token
// for a different user, ALL collapse to one email_change_invalid (400).
// Consuming the token IS proof the bearer controls the new address, so this
// also stamps email_verified=true — the same guarantee signup verification
// gives via updateVerifiedEmail in verify_email.go — otherwise a stale/unset
// flag would carry forward onto the new address and could wrongly lock the
// account out of login when mandatory verification is enabled.
func HandleMyEmailVerify(d Deps, ctx core.HandlerContext, userID string) {
	middleware.TokenNoStoreHeaders(ctx)
	var req struct {
		Token string `json:"token"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || req.Token == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrEmailChangeInvalid))
		return
	}
	rctx := ctx.Request().Context()
	tok, err := d.EmailChangeStore().Consume(rctx, req.Token)
	if err != nil || tok.UserID != userID {
		// Unknown/expired/consumed, or someone else's token — one response.
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrEmailChangeInvalid))
		return
	}
	u, err := d.UserProvider().GetByID(rctx, userID)
	if err != nil || u == nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrEmailChangeInvalid))
		return
	}
	// Clone the user (and its Attributes map) before mutating: u may alias a
	// pointer a concurrent reader holds in the provider's cache — same race
	// documented on verify_email.go's updateVerifiedEmail, which this mirrors.
	updated := *u
	attrs := make(map[string]string, len(u.Attributes)+1)
	for k, v := range u.Attributes {
		attrs[k] = v
	}
	attrs["email_verified"] = "true"
	updated.Attributes = attrs
	updated.Email = tok.NewEmail
	if err := d.UserProvider().CreateOrUpdate(rctx, &updated); err != nil {
		d.Logger().Error("email change: commit failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if d.Auditor() != nil {
		evt := &audit.Event{Type: audit.EventEmailChanged, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		d.Auditor().Record(rctx, evt)
	}
	ctx.JSON(http.StatusOK, map[string]any{"status": "ok", "email": tok.NewEmail})
}
