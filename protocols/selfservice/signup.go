package selfservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// HandleSelfRegister serves POST /auth/register — the opt-in UNAUTHENTICATED
// self-service signup. Body: {username, password, email?}. It creates the
// account and sets the password, reusing the wired UserProvider +
// PasswordCredentialStore. The username becomes the userID (the same identity
// assumption the default forgot-password resolver makes).
//
// When require_verification is true (Mode B — mandatory email verification):
//   - Email is required (400 if empty)
//   - A verification token is issued, stored as SHA-256 hash, and sent
//   - Returns 201 {"status":"pending"} — user is NOT created yet
//   - POST /auth/verify-email (HandleVerifyEmail) completes the flow
//
// When require_verification is false (Mode A — optional, default):
//   - Current flow preserved for backward compatibility
//   - When email is provided, sets email_verified="true" (short-circuit trust)
//   - Supports ?send_verification=true query param for optional verification
//
// NEVER overwrites an existing account: it pre-checks GetByID and rejects a
// taken username with 409 account_exists (CreateOrUpdate is an upsert, so the
// guard is essential). The check is safe against takeover — an attacker can't
// pass it for an existing victim (GetByID returns the victim → 409); the only
// race is two concurrent NEW signups of the same fresh username (benign; the
// loser retries). Rate-limited by the standard middleware. no-store headers.
func HandleSelfRegister(d Deps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	var req struct {
		Username     string `json:"username"`
		Password     string `json:"password"`
		Email        string `json:"email"`
		CaptchaToken string `json:"captcha_token"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	username := strings.TrimSpace(req.Username)
	if username == "" || req.Password == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()

	// Run registration gates (abuse protection) BEFORE user creation. All
	// gate errors collapse to 403 registration_denied.
	if !runRegistrationGates(d, ctx, username, strings.TrimSpace(req.Email), req.CaptchaToken) {
		return
	}

	if existing, err := d.UserProvider().GetByID(rctx, username); err == nil && existing != nil {
		// Username taken — signup must not overwrite. (Operators who treat the
		// username as PII/email and want anti-enumeration should front this.)
		recordSelfRegister(d, ctx, username, false)
		ctx.JSON(http.StatusConflict, d.ErrorBody(core.ErrAccountExists))
		return
	}

	if d.SignupRequiresVerification() {
		handleMandatoryVerificationSignup(d, ctx, username, req.Password, strings.TrimSpace(req.Email))
		return
	}
	handleOptionalVerificationSignup(d, ctx, username, req.Password, strings.TrimSpace(req.Email))
}

// handleMandatoryVerificationSignup implements Mode B: requires email, issues
// a verification token, sends it, and returns 201 {"status":"pending"} without
// creating the user. They complete via POST /auth/verify-email.
func handleMandatoryVerificationSignup(d Deps, ctx core.HandlerContext, username, password, email string) {
	if email == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	rctx := ctx.Request().Context()
	if !checkPasswordPolicy(d, rctx, ctx, password) {
		return
	}
	// Generate a 32-byte random token.
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		d.Logger().Error("signup: generate verification token failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	rawToken := hex.EncodeToString(raw)

	// SHA-256 hash for storage.
	h := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(h[:])

	ttl := d.EmailVerificationTTL()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	tok := &core.EmailVerificationToken{
		Token:     hash,
		Username:  username,
		Email:     email,
		ExpiresAt: time.Now().Add(ttl),
	}

	if err := d.EmailVerificationStore().Issue(rctx, tok); err != nil {
		d.Logger().Error("signup: issue verification token failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}

	// Send the plaintext token (never persisted).
	if err := d.EmailVerificationSender().SendEmailVerificationToken(rctx, email, rawToken); err != nil {
		d.Logger().Error("signup: send verification token failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}

	recordSelfRegister(d, ctx, username, true)
	ctx.JSON(http.StatusCreated, map[string]any{"status": "pending"})
}

// handleOptionalVerificationSignup implements Mode A: creates the user
// immediately. When email is provided, sets email_verified="true" (short-
// circuit trust). Supports ?send_verification=true for optional verification.
func handleOptionalVerificationSignup(d Deps, ctx core.HandlerContext, username, password, email string) {
	rctx := ctx.Request().Context()

	// Validate password policy before creating the user.
	if !checkPasswordPolicy(d, rctx, ctx, password) {
		return
	}

	attrs := make(map[string]string)
	if email != "" {
		attrs["email_verified"] = "true"
	}

	u := &core.User{
		ID:         username,
		Email:      email,
		Attributes: attrs,
	}
	if err := d.UserProvider().CreateOrUpdate(rctx, u); err != nil {
		d.Logger().Error("signup: create user failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if err := d.PasswordCredentialStore().SetPassword(rctx, username, password); err != nil {
		// Roll back the just-created user so we don't leave a passwordless
		// orphan account (best-effort; Delete is idempotent).
		d.Logger().Error("signup: set password failed, rolling back user", "username", username, "error", err)
		if derr := d.UserProvider().Delete(rctx, username); derr != nil {
			d.Logger().Error("signup: rollback delete failed", "username", username, "error", derr)
		}
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}

	// Optional: send verification token even in Mode A if ?send_verification=true.
	if email != "" && ctx.Query("send_verification") == "true" {
		sendOptionalVerification(d, ctx, username, email)
	}

	recordSelfRegister(d, ctx, username, true)
	ctx.JSON(http.StatusCreated, map[string]any{"status": "created", "user_id": username})
}

// sendOptionalVerification sends a verification token for Mode A when the
// ?send_verification=true query param is set. Best-effort; failures are
// logged but do not block the signup response.
func sendOptionalVerification(d Deps, ctx core.HandlerContext, username, email string) {
	if d.EmailVerificationStore() == nil || d.EmailVerificationSender() == nil {
		return
	}
	rctx := ctx.Request().Context()

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		d.Logger().Error("signup: optional verification token generation failed", "username", username, "error", err)
		return
	}
	rawToken := hex.EncodeToString(raw)

	h := sha256.Sum256([]byte(rawToken))
	hash := hex.EncodeToString(h[:])

	ttl := d.EmailVerificationTTL()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}

	tok := &core.EmailVerificationToken{
		Token:     hash,
		Username:  username,
		Email:     email,
		ExpiresAt: time.Now().Add(ttl),
	}
	if err := d.EmailVerificationStore().Issue(rctx, tok); err != nil {
		d.Logger().Error("signup: optional verification issue failed", "username", username, "error", err)
		return
	}
	if err := d.EmailVerificationSender().SendEmailVerificationToken(rctx, email, rawToken); err != nil {
		d.Logger().Error("signup: optional verification send failed", "username", username, "error", err)
	}
}

// runRegistrationGates runs the registration gate chain. Returns true if all
// gates pass, false if a gate rejected the request (response already written).
func runRegistrationGates(d Deps, ctx core.HandlerContext, username, email, captchaToken string) bool {
	gates := d.RegistrationGates()
	if len(gates) == 0 {
		return true
	}
	rctx := ctx.Request().Context()
	if captchaToken != "" {
		rctx = context.WithValue(rctx, spi.CaptchaTokenContextKey{}, captchaToken)
	}
	ip := ctx.Request().RemoteAddr
	for _, gate := range gates {
		if err := gate.CheckRegistration(rctx, username, email, ip); err != nil {
			recordSelfRegister(d, ctx, username, false)
			ctx.JSON(http.StatusForbidden, d.ErrorBody(core.ErrRegistrationDenied))
			return false
		}
	}
	return true
}

func recordSelfRegister(d Deps, ctx core.HandlerContext, username string, ok bool) {
	if d.Auditor() == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventSelfRegistered,
		Outcome: audit.OutcomeSuccess,
		ActorID: username,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	if !ok {
		evt.Outcome = audit.OutcomeFailure
		evt.Reason = "account_exists"
	}
	d.Auditor().Record(ctx.Request().Context(), evt)
}

// checkPasswordPolicy validates the proposed password against the wired policy.
// Returns true when the password is acceptable or no policy is configured.
// On violation, writes a 400 response and returns false.
func checkPasswordPolicy(d Deps, rctx context.Context, ctx core.HandlerContext, password string) bool {
	v := d.PasswordPolicyValidator()
	if v == nil {
		return true
	}
	if err := v.ValidatePassword(rctx, password); err != nil {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrPasswordPolicyViolation))
		return false
	}
	return true
}
