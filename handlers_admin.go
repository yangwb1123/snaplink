package sso

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/security"
)

// Admin/helpdesk management-plane handlers plus the B2B org
// (connections, tenant membership, invitations) handlers — extracted from
// handlers.go to keep that file from sprawling. Same package; imports are
// managed by goimports. Behavior-identical to the prior inline definitions.

// handleAdminListUserConsents serves GET /api/v1/admin/users/:id/consents — an
// operator/helpdesk views which apps a user has authorized. admin:read (gated
// by AdminMiddleware via the /api/v1/admin/ prefix).
func (s *Server) handleAdminListUserConsents(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	grants, err := s.consentStore.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list consents failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if grants == nil {
		grants = []core.ConsentGrant{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"consents": grants})
}

// handleAdminRevokeUserConsent serves DELETE /api/v1/admin/users/:id/consents/:client_id
// — revoke a user's grant for an app on their behalf. admin:write. A missing
// grant is a 404 so the caller knows it wasn't there; emits admin_consent_revoked.
func (s *Server) handleAdminRevokeUserConsent(ctx HandlerContext) {
	userID := ctx.Param("id")
	clientID := ctx.Param("client_id")
	if userID == "" || clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if _, err := s.consentStore.GetConsent(ctx.Request().Context(), userID, clientID); err != nil {
		if errors.Is(err, core.ErrNoConsentGrant) {
			ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
			return
		}
		s.logger.Error("admin get consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if err := s.consentStore.RevokeConsent(ctx.Request().Context(), userID, clientID); err != nil {
		s.logger.Error("admin revoke consent failed", "user_id", userID, "client_id", clientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminConsentRevoked, userID, KeyClientID, clientID)
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminListUserMFA serves GET /api/v1/admin/users/:id/mfa — an
// operator/helpdesk views a user's registered second factors. admin:read.
func (s *Server) handleAdminListUserMFA(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if factors == nil {
		factors = []core.MFAEnrolledFactor{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"factors": factors})
}

// handleAdminRemoveUserMFA serves DELETE /api/v1/admin/users/:id/mfa/:factor_id
// — unbind a user's second factor on their behalf (helpdesk "lost phone, reset
// MFA"). admin:write. A factor the user doesn't have is a 404 (ownership is
// enforced via the user-scoped list, same as the self-service path); emits
// admin_mfa_factor_removed.
func (s *Server) handleAdminRemoveUserMFA(ctx HandlerContext) {
	userID := ctx.Param("id")
	factorID := ctx.Param("factor_id")
	if userID == "" || factorID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := s.mfaEnrollmentStore.ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if !slices.ContainsFunc(factors, func(f core.MFAEnrolledFactor) bool { return f.ID == factorID }) {
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	if err := s.mfaEnrollmentStore.RemoveFactor(ctx.Request().Context(), userID, factorID); err != nil {
		s.logger.Error("admin remove mfa factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminMFAFactorRemoved, userID, "factor_id", factorID)
	ctx.JSON(http.StatusNoContent, nil)
}

// recordAdminUserAction emits an admin_* audit event for a helpdesk action on a
// user's self-service state. ActorID is the acting ADMIN (from the
// AdminMiddleware-stamped context); the target user + the affected
// client_id/factor_id ride in metadata.
func (s *Server) recordAdminUserAction(ctx HandlerContext, evtType audit.EventType, targetUser, metaKey, metaVal string) {
	if s.auditor == nil {
		return
	}
	actor, _, _ := AdminActorFromContext(ctx.Request().Context())
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
	s.auditor.Record(ctx.Request().Context(), evt)
}

// handleAdminResetUserPassword serves POST /api/v1/admin/users/:id/password —
// a helpdesk/admin sets a user's password on their behalf. admin:write. Body:
// {new_password}. Emits admin_password_reset (never the password). The new
// password takes effect on the user's next login (the same credential the
// self-service /me/password change writes).
func (s *Server) handleAdminResetUserPassword(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.NewPassword == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	if err := s.passwordCredentialStore.SetPassword(ctx.Request().Context(), userID, req.NewPassword); err != nil {
		s.logger.Error("admin set password failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminPasswordReset, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminSetUserEmail serves POST /api/v1/admin/users/:id/email — a
// helpdesk/admin force-sets a user's email on their behalf (onboarding-typo
// correction, domain migration), bypassing the user-facing verified
// email-change flow (which requires the user to control the new address).
// admin:write. Body: {email}. A missing user is a 404. Emits
// admin_user_email_changed (never the email value — it's PII).
func (s *Server) handleAdminSetUserEmail(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	var req struct {
		Email string `json:"email"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || strings.TrimSpace(req.Email) == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	u, err := s.userProvider.GetByID(ctx.Request().Context(), userID)
	if err != nil || u == nil {
		ctx.JSON(http.StatusNotFound, errorBody(core.ErrNotFound))
		return
	}
	u.Email = strings.TrimSpace(req.Email)
	if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), u); err != nil {
		s.logger.Error("admin set email failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminUserEmailChanged, userID, "", "")
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminClearAccountLockout serves POST /api/v1/admin/account-lockout/clear
// — a helpdesk clears a brute-force lockout so a legitimately-locked user can
// retry immediately, without waiting out the auto-unlock duration. admin:write.
// Body: {client_id, identifier}. The lockout is keyed on
// <client_id>:<identifier> (the credential the user authenticates with), NOT the
// userID, so both are required. Reuses RegisterSuccess, which the AccountLockout
// contract defines as resetting the failure counter AND any active lock for the
// key — so this is idempotent (clearing a non-locked key succeeds). Emits
// admin_account_unlocked.
func (s *Server) handleAdminClearAccountLockout(ctx HandlerContext) {
	var req struct {
		ClientID   string `json:"client_id"`
		Identifier string `json:"identifier"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil || req.ClientID == "" || req.Identifier == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	// Build the same key the login path uses (security.LockoutKey →
	// "<client_id>:<identifier>"). The field name is immaterial — the key format
	// is identical regardless of which credential field locked the account.
	key := security.LockoutKey(req.ClientID, map[string]string{"username": req.Identifier})
	if err := s.accountLockout.RegisterSuccess(ctx.Request().Context(), key); err != nil {
		s.logger.Error("admin clear lockout failed", "client_id", req.ClientID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminAccountUnlocked, req.Identifier, KeyClientID, req.ClientID)
	ctx.JSON(http.StatusNoContent, nil)
}

// handleAdminRevokeUserDeviceSecrets serves DELETE /api/v1/admin/users/:id/device-secrets
// — revoke all of a user's Native SSO device-secret bindings (lost/compromised
// device lockout). admin:write. 501 when the wired DeviceSecretStore can't
// revoke by subject; emits admin_device_secrets_revoked with the count.
func (s *Server) handleAdminRevokeUserDeviceSecrets(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := s.deviceSecretStore.(core.DeviceSecretRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeBySubject(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin revoke device secrets failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminDeviceSecretsRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// handleAdminRevokeUserPasswordResetTokens serves
// DELETE /api/v1/admin/users/:id/password-reset-tokens — invalidate every
// pending forgot-password token for a user (wrong-address / leak / lost-channel
// recovery). admin:write. 501 when the wired PasswordResetStore can't revoke by
// user; emits admin_password_reset_tokens_revoked with the count. Idempotent.
func (s *Server) handleAdminRevokeUserPasswordResetTokens(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := s.passwordResetStore.(core.PasswordResetRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin revoke password reset tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminPasswordResetTokensRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// handleAdminRevokeUserEmailChangeTokens serves
// DELETE /api/v1/admin/users/:id/email-change-tokens — invalidate every pending
// email-change verification token for a user (wrong-address / ownership-dispute
// recovery). admin:write. 501 when the wired EmailChangeStore can't revoke by
// user; emits admin_email_change_tokens_revoked with the count. Idempotent.
func (s *Server) handleAdminRevokeUserEmailChangeTokens(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	revoker, ok := s.emailChangeStore.(core.EmailChangeRevoker)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	n, err := revoker.RevokeByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin revoke email change tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	s.recordAdminUserAction(ctx, audit.EventAdminEmailChangeTokensRevoked, userID, "revoked", fmt.Sprintf("%d", n))
	ctx.JSON(http.StatusOK, map[string]any{"revoked": n})
}

// handleAdminListUserPasswordResetTokens serves
// GET /api/v1/admin/users/:id/password-reset-tokens — a helpdesk checks whether
// a user has pending forgot-password tokens and when they expire ("I didn't get
// the reset email"). admin:read. 501 when the wired store can't list. NEVER
// returns the token value — only expiry + an expired flag (the token is a live
// credential).
func (s *Server) handleAdminListUserPasswordResetTokens(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	lister, ok := s.passwordResetStore.(core.PasswordResetLister)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	toks, err := lister.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list password reset tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{"expires_at": t.ExpiresAt, "expired": t.IsExpired()})
	}
	ctx.JSON(http.StatusOK, map[string]any{"tokens": out, "count": len(out)})
}

// handleAdminListUserEmailChangeTokens serves
// GET /api/v1/admin/users/:id/email-change-tokens — a helpdesk checks a user's
// pending email-change tokens (target address + expiry) for verification-loop
// debugging. admin:read. 501 when the wired store can't list. NEVER returns the
// token value.
func (s *Server) handleAdminListUserEmailChangeTokens(ctx HandlerContext) {
	userID := ctx.Param("id")
	if userID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return
	}
	lister, ok := s.emailChangeStore.(core.EmailChangeLister)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, errorBody(core.ErrNotFound))
		return
	}
	toks, err := lister.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("admin list email change tokens failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	out := make([]map[string]any, 0, len(toks))
	for _, t := range toks {
		out = append(out, map[string]any{"new_email": t.NewEmail, "expires_at": t.ExpiresAt, "expired": t.IsExpired()})
	}
	ctx.JSON(http.StatusOK, map[string]any{"tokens": out, "count": len(out)})
}
