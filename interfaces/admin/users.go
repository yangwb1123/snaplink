package admin

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// Admin/helpdesk management-plane handlers for a user's self-service state
// (consents, MFA factors, password, email, account lockout, and the various
// pending-token stores). Extracted from package sso (root) into the admin
// domain; *sso.Server keeps thin wrappers that delegate here. Behavior-identical
// to the prior inline definitions — every handler is gated by AdminMiddleware.

// HandleAdminListUserConsents serves GET /api/v1/admin/users/:id/consents — an
// operator/helpdesk views which apps a user has authorized. admin:read.
func HandleAdminListUserConsents(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	grants, err := d.ConsentStore().ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin list consents failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if grants == nil {
		grants = []core.ConsentGrant{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"consents": grants})
}

// HandleAdminRevokeUserConsent serves DELETE /api/v1/admin/users/:id/consents/:client_id
// — revoke a user's grant for an app on their behalf. admin:write. A missing
// grant is a 404 so the caller knows it wasn't there; emits admin_consent_revoked.
func HandleAdminRevokeUserConsent(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	clientID := ctx.Param("client_id")
	if userID == "" || clientID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if _, err := d.ConsentStore().GetConsent(ctx.Request().Context(), userID, clientID); err != nil {
		if errors.Is(err, core.ErrNoConsentGrant) {
			ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
			return
		}
		d.Logger().Error("admin get consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if err := d.ConsentStore().RevokeConsent(ctx.Request().Context(), userID, clientID); err != nil {
		d.Logger().Error("admin revoke consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminConsentRevoked, userID, core.KeyClientID, clientID)
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleAdminListUserMFA serves GET /api/v1/admin/users/:id/mfa — an
// operator/helpdesk views a user's registered second factors. admin:read.
func HandleAdminListUserMFA(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := d.MFAEnrollmentStore().ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if factors == nil {
		factors = []core.MFAEnrolledFactor{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"factors": factors})
}

// HandleAdminRemoveUserMFA serves DELETE /api/v1/admin/users/:id/mfa/:factor_id
// — unbind a user's second factor on their behalf (helpdesk "lost phone, reset
// MFA"). admin:write. A factor the user doesn't have is a 404 (ownership is
// enforced via the user-scoped list, same as the self-service path); emits
// admin_mfa_factor_removed.
func HandleAdminRemoveUserMFA(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	factorID := ctx.Param("factor_id")
	if userID == "" || factorID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := d.MFAEnrollmentStore().ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	if !slices.ContainsFunc(factors, func(f core.MFAEnrolledFactor) bool { return f.ID == factorID }) {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	if err := d.MFAEnrollmentStore().RemoveFactor(ctx.Request().Context(), userID, factorID); err != nil {
		d.Logger().Error("admin remove mfa factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminMFAFactorRemoved, userID, "factor_id", factorID)
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleAdminResetUserRecoveryCodes serves POST
// /api/v1/admin/users/:id/mfa/recovery-codes — the helpdesk MFA recovery reset.
// admin:write. It ONLY revokes the user's remaining recovery codes and NEVER
// returns codes to the operator: exposing a user's credentials to helpdesk is a
// security smell, so the user regenerates their own via /me/mfa/recovery-codes.
// Emits admin_recovery_codes_reset.
func HandleAdminResetUserRecoveryCodes(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.RecoveryCodeStore().RevokeAll(ctx.Request().Context(), userID); err != nil {
		d.Logger().Error("admin reset recovery codes failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminRecoveryCodesReset, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// recordAdminUserAction emits an admin_* audit event for a helpdesk action on a
// user's self-service state. ActorID is the acting ADMIN (from the
// AdminMiddleware-stamped context); the target user + the affected
// client_id/factor_id ride in metadata.
func recordAdminUserAction(d Deps, ctx core.HandlerContext, evtType audit.EventType, targetUser, metaKey, metaVal string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	actor, _, _ := ActorFromContext(ctx.Request().Context())
	evt := &audit.Event{
		Type:    evtType,
		Outcome: audit.OutcomeSuccess,
		ActorID: actor,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "target_user", targetUser)
	if metaKey != "" {
		audit.SetMeta(evt, metaKey, metaVal)
	}
	aud.Record(ctx.Request().Context(), evt)
}

// HandleAdminResetUserPassword serves POST /api/v1/admin/users/:id/password —
// a helpdesk/admin sets a user's password on their behalf. admin:write. Body:
// {new_password}. Emits admin_password_reset (never the password). The new
// password takes effect on the user's next login (the same credential the
// self-service /me/password change writes). When a PasswordHistoryStore is
// wired, this path is checked/recorded exactly like the self-service reset —
// the highest-privilege path to change a credential must not be a back door
// around history enforcement (protocols/selfservice/password_reset.go).
func HandleAdminResetUserPassword(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || req.NewPassword == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if !checkAdminPasswordHistory(d, ctx, userID, req.NewPassword) {
		return
	}
	if err := d.PasswordCredentialStore().SetPassword(ctx.Request().Context(), userID, req.NewPassword); err != nil {
		d.Logger().Error("admin set password failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminPasswordHistory(d, ctx, userID, req.NewPassword)
	revokeAdminPasswordResetCredentials(d, ctx, userID)
	recordAdminUserAction(d, ctx, audit.EventAdminPasswordReset, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// checkAdminPasswordHistory rejects a new password that matches userID's
// recent password history, when a history store is wired. Fails OPEN on a
// store error (logged) — an outage must not block an otherwise-legitimate
// admin reset. Mirrors protocols/selfservice's checkPasswordHistory.
func checkAdminPasswordHistory(d Deps, ctx core.HandlerContext, userID, password string) bool {
	store := d.PasswordHistoryStore()
	if store == nil {
		return true
	}
	reused, err := store.CheckHistory(ctx.Request().Context(), userID, password)
	if err != nil {
		d.Logger().Error("admin password history check failed", "user_id", userID, "error", err)
		return true
	}
	if reused {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrPasswordPolicyViolation))
		return false
	}
	return true
}

// recordAdminPasswordHistory best-effort records the just-set password so a
// future change (admin or self-service) can detect reuse. Non-fatal: the
// password change already succeeded, so a history-store write failure is
// logged, not surfaced.
func recordAdminPasswordHistory(d Deps, ctx core.HandlerContext, userID, password string) {
	store := d.PasswordHistoryStore()
	if store == nil {
		return
	}
	if err := store.Record(ctx.Request().Context(), userID, password); err != nil {
		d.Logger().Error("admin password history record failed", "user_id", userID, "error", err)
	}
}

// HandleAdminSetUserEmail serves POST /api/v1/admin/users/:id/email — a
// helpdesk/admin force-sets a user's email on their behalf (onboarding-typo
// correction, domain migration), bypassing the user-facing verified
// email-change flow. admin:write. Body: {email}. A missing user is a 404. Emits
// admin_user_email_changed (never the email value — it's PII).
func HandleAdminSetUserEmail(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	u, err := d.UserProvider().GetByID(ctx.Request().Context(), userID)
	if err != nil || u == nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrNotFound))
		return
	}
	u.Email = strings.TrimSpace(req.Email)
	if err := d.UserProvider().CreateOrUpdate(ctx.Request().Context(), u); err != nil {
		d.Logger().Error("admin set email failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminUserEmailChanged, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleAdminClearAccountLockout serves POST /api/v1/admin/account-lockout/clear
// — a helpdesk clears a brute-force lockout so a legitimately-locked user can
// retry immediately. admin:write. Body: {client_id, identifier}. The lockout is
// keyed on <client_id>:<identifier>, so both are required. Reuses RegisterSuccess
// (resets the failure counter AND any active lock), so it is idempotent. Emits
// admin_account_unlocked.
func HandleAdminClearAccountLockout(d Deps, ctx core.HandlerContext) {
	var req struct {
		ClientID   string `json:"client_id"`
		Identifier string `json:"identifier"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || req.ClientID == "" || req.Identifier == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	// Clear BOTH the raw key and the email-normalized (lower+trim) key. The email
	// authenticator keys its lockout on the NORMALIZED address (core.LockoutKeyer),
	// so a helpdesk supplying the on-file mixed-case address must still hit the
	// live lock; username/phone locks use the raw identifier. The redundant clear
	// is an idempotent no-op when the two keys coincide (already-lowercase input).
	for _, id := range []string{req.Identifier, strings.ToLower(strings.TrimSpace(req.Identifier))} {
		key := security.LockoutKey(req.ClientID, map[string]string{"username": id})
		if err := d.AccountLockout().RegisterSuccess(ctx.Request().Context(), key); err != nil {
			d.Logger().Error("admin clear lockout failed", "client_id", req.ClientID, "error", err)
			ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
			return
		}
	}
	recordAdminUserAction(d, ctx, audit.EventAdminAccountUnlocked, req.Identifier, core.KeyClientID, req.ClientID)
	ctx.JSON(http.StatusNoContent, nil)
}

// HandleAdminRevokeUserDeviceSecrets serves DELETE /api/v1/admin/users/:id/device-secrets
// — revoke all of a user's Native SSO device-secret bindings. admin:write. 501
// when the wired DeviceSecretStore can't revoke by subject; emits
// admin_device_secrets_revoked with the count.
func HandleAdminRevokeUserDeviceSecrets(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := d.DeviceSecretStore().(core.DeviceSecretRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeBySubject(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin revoke device secrets failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminDeviceSecretsRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// HandleAdminRevokeUserPasswordResetTokens serves
// DELETE /api/v1/admin/users/:id/password-reset-tokens — invalidate every
// pending forgot-password token for a user. admin:write. 501 when the wired
// PasswordResetStore can't revoke by user; emits
// admin_password_reset_tokens_revoked with the count. Idempotent.
func HandleAdminRevokeUserPasswordResetTokens(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := d.PasswordResetStore().(core.PasswordResetRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin revoke password reset tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminPasswordResetTokensRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// HandleAdminRevokeUserEmailChangeTokens serves
// DELETE /api/v1/admin/users/:id/email-change-tokens — invalidate every pending
// email-change verification token for a user. admin:write. 501 when the wired
// EmailChangeStore can't revoke by user; emits admin_email_change_tokens_revoked
// with the count. Idempotent.
func HandleAdminRevokeUserEmailChangeTokens(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := d.EmailChangeStore().(core.EmailChangeRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin revoke email change tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminEmailChangeTokensRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// HandleAdminRevokeUserRefreshTokens serves
// DELETE /api/v1/admin/users/:id/refresh-tokens — revoke EVERY outstanding
// OAuth 2.0 refresh token a user holds, across ALL clients (helpdesk
// "compromised account, log out everywhere right now"). admin:write.
// Complements the self-service /token/revoke-all and /me/sessions/revoke-all,
// which only reach the AUTHENTICATED caller's own (subject, client) pair; this
// reaches an arbitrary user, every client, on an admin's behalf. 501 when the
// wired RefreshTokenStore can't enumerate by subject; emits
// admin_refresh_tokens_revoked with the count. Idempotent.
func HandleAdminRevokeUserRefreshTokens(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	idx, ok := d.RefreshTokenStore().(oauth.RefreshTokenSubjectIndex)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotFound))
		return
	}
	// Empty clientID = no client filter — every client the user holds a
	// refresh token for, not just one (oauthspi.RefreshTokenSubjectIndex).
	n, err := idx.DeleteAllForSubject(ctx.Request().Context(), userID, "")
	if err != nil {
		d.Logger().Error("admin revoke refresh tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventAdminRefreshTokensRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// HandleAdminListUserPasswordResetTokens serves
// GET /api/v1/admin/users/:id/password-reset-tokens — a helpdesk checks whether
// a user has pending forgot-password tokens and when they expire. admin:read.
// 501 when the wired store can't list. NEVER returns the token value — only
// expiry + an expired flag (the token is a live credential).
func HandleAdminListUserPasswordResetTokens(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	lister, ok := d.PasswordResetStore().(core.PasswordResetLister)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotFound))
		return
	}
	toks, err := lister.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin list password reset tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{"expires_at": t.ExpiresAt, "expired": t.IsExpired()})
	}
	ctx.JSON(http.StatusOK, map[string]any{"tokens": out, "count": len(out)})
}

// HandleAdminListUserEmailChangeTokens serves
// GET /api/v1/admin/users/:id/email-change-tokens — a helpdesk checks a user's
// pending email-change tokens (target address + expiry). admin:read. 501 when
// the wired store can't list. NEVER returns the token value.
func HandleAdminListUserEmailChangeTokens(d Deps, ctx core.HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	lister, ok := d.EmailChangeStore().(core.EmailChangeLister)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrNotFound))
		return
	}
	toks, err := lister.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("admin list email change tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{"new_email": t.NewEmail, "expires_at": t.ExpiresAt, "expired": t.IsExpired()})
	}
	ctx.JSON(http.StatusOK, map[string]any{"tokens": out, "count": len(out)})
}
