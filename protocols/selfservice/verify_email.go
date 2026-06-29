package selfservice

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// HandleVerifyEmail serves POST /auth/verify-email — the second leg of
// mandatory signup email verification. Body: {token}. It consumes the
// single-use token (SHA-256 hashed for store lookup), checks expiry, then
// atomically creates the user with email_verified=true. Oracle-safe: all
// token failure modes collapse to a single verification_invalid (400).
// Credential-adjacent: no-store headers.
func HandleVerifyEmail(d Deps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	var req struct {
		Token string `json:"token"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || req.Token == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrVerificationInvalid))
		return
	}

	tok, err := consumeVerificationToken(d, ctx, req.Token)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrVerificationInvalid))
		return
	}

	createVerifiedUser(d, ctx, tok)
	ctx.JSON(http.StatusOK, map[string]any{"status": "verified"})
}

// consumeVerificationToken hashes the raw token and atomically consumes it
// from the store. Returns the token data or an error (oracle-safe).
func consumeVerificationToken(d Deps, ctx core.HandlerContext, rawToken string) (*core.EmailVerificationToken, error) {
	rctx := ctx.Request().Context()
	h := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(h[:])

	tok, err := d.EmailVerificationStore().Consume(rctx, hash)
	if err != nil {
		return nil, err
	}
	if tok.IsExpired() {
		return nil, fmt.Errorf("expired")
	}
	return tok, nil
}

// createVerifiedUser creates the user record from a consumed verification
// token, setting email_verified=true and emitting an audit event.
func createVerifiedUser(d Deps, ctx core.HandlerContext, tok *core.EmailVerificationToken) {
	rctx := ctx.Request().Context()
	attrs := map[string]string{"email_verified": "true"}
	u := &core.User{
		ID:         tok.Username,
		Email:      tok.Email,
		Attributes: attrs,
	}
	if err := d.UserProvider().CreateOrUpdate(rctx, u); err != nil {
		d.Logger().Error("verify-email: create user failed", "username", tok.Username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if d.Auditor() != nil {
		evt := &audit.Event{
			Type:    audit.EventSelfRegistered,
			Outcome: audit.OutcomeSuccess,
			ActorID: tok.Username,
			ActorIP: audit.ClientIP(ctx.Request()),
		}
		d.Auditor().Record(rctx, evt)
	}
}
