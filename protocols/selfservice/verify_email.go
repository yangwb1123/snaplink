package selfservice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
	existing, lookupErr := d.UserProvider().GetByID(rctx, tok.Username)
	if lookupErr != nil && !errors.Is(lookupErr, core.ErrNoSuchUser) {
		// Transient store error: fail closed rather than falling through to creation
		// which could produce a duplicate or overwrite a live record on retry.
		d.Logger().Error("verify-email: user lookup failed", "username", tok.Username, "error", lookupErr)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return false
	}
	if existing != nil {
		// Mode A opt-in verify: user was created immediately at register time so
		// no password hash was stored in the token. Stamp email_verified=true on
		// the live record rather than treating it as a conflict.
		if tok.PasswordHash == "" {
			return updateVerifiedEmail(d, ctx, rctx, existing)
		}
		// Mode B conflict: username was claimed between token issue and verify.
		// Oracle-safe: indistinguishable from a bad or expired token.
		d.Logger().Error("verify-email: username already taken at verify time", "username", tok.Username)
		recordSelfRegisteredFailure(d, ctx, rctx, "", "username_taken")
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrVerificationInvalid))
		return false
	}
	u := &core.User{
		ID:         tok.Username,
		Email:      tok.Email,
		Attributes: map[string]string{"email_verified": "true"},
	}
	if err := d.UserProvider().CreateOrUpdate(rctx, u); err != nil {
		d.Logger().Error("verify-email: create user failed", "username", tok.Username, "error", err)
		recordSelfRegisteredFailure(d, ctx, rctx, tok.Username, "create_failed")
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return false
	}
	if !installVerifiedPassword(d, ctx, rctx, tok.Username, tok.PasswordHash) {
		return false
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

// installVerifiedPassword installs the pre-hashed password from a verification
// token into the credential store. Mode B requires core.PasswordHashImporter;
// if the store does not implement it, the user record is rolled back and a 500
// is written. Returns true on success or when no hash is present (Mode A).
func installVerifiedPassword(d Deps, ctx core.HandlerContext, rctx context.Context, username, hash string) bool {
	if hash == "" {
		return true
	}
	importer, ok := d.PasswordCredentialStore().(core.PasswordHashImporter)
	if !ok {
		d.Logger().Error("verify-email: password store lacks PasswordHashImporter — Mode B requires it", "username", username)
		if derr := d.UserProvider().Delete(rctx, username); derr != nil {
			d.Logger().Error("verify-email: rollback delete failed", "username", username, "error", derr)
		}
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrServerMisconfigured))
		return false
	}
	if err := importer.SetPasswordHash(rctx, username, hash); err != nil {
		d.Logger().Error("verify-email: set password hash failed", "username", username, "error", err)
		recordSelfRegisteredFailure(d, ctx, rctx, username, "password_install_failed")
		if derr := d.UserProvider().Delete(rctx, username); derr != nil {
			d.Logger().Error("verify-email: rollback delete failed", "username", username, "error", derr)
		}
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return false
	}
	return true
}

// recordSelfRegisteredFailure emits an EventSelfRegistered/OutcomeFailure audit event
// when a non-nil Auditor is present. actorID may be empty for pre-user-creation failures.
func recordSelfRegisteredFailure(d Deps, ctx core.HandlerContext, rctx context.Context, actorID, reason string) {
	if d.Auditor() == nil {
		return
	}
	d.Auditor().Record(rctx, &audit.Event{
		Type:    audit.EventSelfRegistered,
		Outcome: audit.OutcomeFailure,
		Reason:  reason,
		ActorID: actorID,
		ActorIP: audit.ClientIP(ctx.Request()),
	})
}

// updateVerifiedEmail stamps email_verified=true on an already-existing user
// record (Mode A opt-in verify). Clones the user and its Attributes map before
// mutating to avoid a data race with concurrent readers that may hold the same
// pointer returned by the provider's cache. Emits EventSelfRegistered/success.
func updateVerifiedEmail(d Deps, ctx core.HandlerContext, rctx context.Context, u *core.User) bool {
	updated := *u
	attrs := make(map[string]string, len(u.Attributes)+1)
	for k, v := range u.Attributes {
		attrs[k] = v
	}
	attrs["email_verified"] = "true"
	updated.Attributes = attrs
	if err := d.UserProvider().CreateOrUpdate(rctx, &updated); err != nil {
		d.Logger().Error("verify-email: update email_verified failed", "user_id", u.ID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return false
	}
	if d.Auditor() != nil {
		d.Auditor().Record(rctx, &audit.Event{
			Type:    audit.EventSelfRegistered,
			Outcome: audit.OutcomeSuccess,
			ActorID: u.ID,
			ActorIP: audit.ClientIP(ctx.Request()),
		})
	}
	return true
}
