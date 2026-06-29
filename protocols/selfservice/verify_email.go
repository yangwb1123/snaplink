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
		if d.Auditor() != nil {
			evt := &audit.Event{
				Type:    audit.EventSelfRegistered,
				Outcome: audit.OutcomeFailure,
				Reason:  "verification_invalid",
				ActorIP: audit.ClientIP(ctx.Request()),
			}
			d.Auditor().Record(ctx.Request().Context(), evt)
		}
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrVerificationInvalid))
		return
	}

	if !createVerifiedUser(d, ctx, tok) {
		return
	}
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
// token, setting email_verified=true, installing the password hash, and
// emitting the self-registered audit event. It writes the response on error.
// Returns true on success so HandleVerifyEmail can write the 200.
func createVerifiedUser(d Deps, ctx core.HandlerContext, tok *core.EmailVerificationToken) bool {
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
		return false
	}

	// Install the password that was hashed at issue time. Mode B requires a
	// PasswordCredentialStore that implements core.PasswordHashImporter so the
	// pre-hashed credential can be stored without re-transmitting the plaintext.
	if tok.PasswordHash != "" {
		importer, ok := d.PasswordCredentialStore().(core.PasswordHashImporter)
		if !ok {
			d.Logger().Error("verify-email: password store does not implement PasswordHashImporter — Mode B signup requires it", "username", tok.Username)
			if derr := d.UserProvider().Delete(rctx, tok.Username); derr != nil {
				d.Logger().Error("verify-email: rollback delete failed", "username", tok.Username, "error", derr)
			}
			ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrServerMisconfigured))
			return false
		}
		if err := importer.SetPasswordHash(rctx, tok.Username, tok.PasswordHash); err != nil {
			d.Logger().Error("verify-email: set password hash failed", "username", tok.Username, "error", err)
			if derr := d.UserProvider().Delete(rctx, tok.Username); derr != nil {
				d.Logger().Error("verify-email: rollback delete failed", "username", tok.Username, "error", derr)
			}
			ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
			return false
		}
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
	return true
}
