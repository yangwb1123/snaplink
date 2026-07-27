package selfservice

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/selfservice/selfservicecore"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
	"golang.org/x/crypto/bcrypt"
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
	if rejectSignupRateLimit(d, ctx) {
		return
	}
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

// rejectSignupRateLimit enforces the optional per-IP rate limit for signup.
// Returns true and writes a 429 response when the request must be rejected.
func rejectSignupRateLimit(d Deps, ctx core.HandlerContext) bool {
	lim := d.SignupRateLimiter()
	if lim == nil {
		return false
	}
	key := middleware.RealClientIP(ctx.Request())
	if ok, retryAfter := lim.Allow(key); !ok {
		if retryAfter > 0 {
			// Ceiling division: RFC 7231 interprets Retry-After: 0 as "retry
			// immediately", so sub-second durations round up to 1.
			secs := int(retryAfter / time.Second)
			if retryAfter%time.Second > 0 {
				secs++
			}
			ctx.ResponseWriter().Header().Set(selfservicecore.HeaderRetryAfter, strconv.Itoa(secs))
		}
		ctx.JSON(http.StatusTooManyRequests, d.ErrorBody("rate_limited"))
		return true
	}
	return false
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
	// Hash the password now so the raw plaintext never leaves this frame.
	// Mode B: the hash is stored in the pending token and committed to the
	// password store only when the email is verified (createVerifiedUser).
	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		d.Logger().Error("signup: hash password failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if !issueVerificationToken(d, ctx, rctx, username, email, string(pwHash)) {
		return
	}
	// Audit fires at verify-email (createVerifiedUser), not here: the user
	// does not exist yet and the token may expire without being consumed.
	ctx.JSON(http.StatusCreated, map[string]any{"status": "pending"})
}

// issueVerificationToken generates, stores, and sends a signup verification
// token. Cancels any prior pending token for the same username so only the
// latest token is valid (prevents last-writer-wins races on concurrent
// duplicate registrations). Returns false when it has already written an error
// response.
func issueVerificationToken(d Deps, ctx core.HandlerContext, rctx context.Context, username, email, pwHash string) bool {
	if revoker, ok := d.EmailVerificationStore().(core.EmailVerificationRevoker); ok {
		_, _ = revoker.RevokeByUsername(rctx, username)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		d.Logger().Error("signup: generate verification token failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return false
	}
	rawToken := hex.EncodeToString(raw)
	h := sha256.Sum256([]byte(rawToken))
	ttl := d.EmailVerificationTTL()
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	tok := &core.EmailVerificationToken{
		Token:        hex.EncodeToString(h[:]),
		Username:     username,
		Email:        email,
		PasswordHash: pwHash,
		ExpiresAt:    time.Now().Add(ttl),
	}
	if err := d.EmailVerificationStore().Issue(rctx, tok); err != nil {
		d.Logger().Error("signup: issue verification token failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return false
	}
	if err := d.EmailVerificationSender().SendEmailVerificationToken(rctx, email, rawToken); err != nil {
		d.Logger().Error("signup: send verification token failed", "username", username, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return false
	}
	return true
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
	ip := middleware.RealClientIP(ctx.Request())
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

// checkPasswordHistory rejects a new password that matches one of userID's
// recent password-history entries, when a history store is wired. Returns
// true when the password is acceptable or no store is configured. Fails OPEN
// on a store error (logged) — an outage must not block an otherwise-
// legitimate password change. Not called at signup: a brand new account has
// no prior password to check against.
func checkPasswordHistory(d Deps, rctx context.Context, ctx core.HandlerContext, userID, password string) bool {
	store := d.PasswordHistoryStore()
	if store == nil {
		return true
	}
	reused, err := store.CheckHistory(rctx, userID, password)
	if err != nil {
		d.Logger().Error("password history check failed", "user_id", userID, "error", err)
		return true
	}
	if reused {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrPasswordPolicyViolation))
		return false
	}
	return true
}

// recordPasswordHistory best-effort records the just-set password so a
// future change can detect reuse. Non-fatal: the password change already
// succeeded, so a history-store write failure is logged, not surfaced.
func recordPasswordHistory(d Deps, rctx context.Context, userID, password string) {
	store := d.PasswordHistoryStore()
	if store == nil {
		return
	}
	if err := store.Record(rctx, userID, password); err != nil {
		d.Logger().Error("password history record failed", "user_id", userID, "error", err)
	}
}

