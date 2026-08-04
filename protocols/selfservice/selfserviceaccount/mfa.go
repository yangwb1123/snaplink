package selfserviceaccount

import (
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// HandleMyMFAFactors serves GET /me/mfa — lists the authenticated user's
// registered second factors (non-sensitive metadata only). Credential-adjacent;
// same cache headers as /userinfo.
func HandleMyMFAFactors(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	factors, err := d.MFAEnrollmentStore().ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if factors == nil {
		factors = []core.MFAEnrolledFactor{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"factors": factors})
}

// HandleDeleteMyMFAFactor serves DELETE /me/mfa/:id — unbinds one of the
// authenticated user's own factors. A factor belonging to another user (or a
// missing id) responds with the same 404 (oracle-safe: ownership is enforced
// via the user-scoped list, so a cross-user delete can never remove someone
// else's factor).
func HandleDeleteMyMFAFactor(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	factorID := ctx.Param("id")
	if factorID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	factors, err := d.MFAEnrollmentStore().ListFactors(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list mfa factors failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if !slices.ContainsFunc(factors, func(f core.MFAEnrolledFactor) bool { return f.ID == factorID }) {
		// Not owned by this user, or never existed — one response either way.
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	if err := d.MFAEnrollmentStore().RemoveFactor(ctx.Request().Context(), userID, factorID); err != nil {
		d.Logger().Error("remove mfa factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordMFARemoved(d, ctx, userID, factorID)
	ctx.JSON(http.StatusNoContent, nil)
}

func recordMFARemoved(d Deps, ctx core.HandlerContext, userID, factorID string) {
	if d.Auditor() == nil {
		return
	}
	event := &audit.Event{Type: audit.EventMFARemoved, Outcome: audit.OutcomeSuccess,
		ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
	audit.SetMeta(event, "factor_id", factorID)
	d.Auditor().Record(ctx.Request().Context(), event)
}

// HandleTOTPEnrollBegin serves POST /me/mfa/totp/begin — the first leg of
// self-service TOTP enrollment. It mints a fresh secret and returns it (base32)
// plus an otpauth:// URI the SPA renders as a QR code. The secret is NOT
// persisted here: the flow is stateless, and the client returns it to the
// confirm leg alongside a code proving possession. Round-tripping the secret is
// safe because it only ever becomes a second factor for the caller's OWN
// authenticated account — no cross-user exposure. Credential-adjacent headers.
func HandleTOTPEnrollBegin(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	enroller := d.TOTPEnroller()
	if enroller == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrTOTPEnrollmentNotSupported))
		return
	}
	secret, err := enroller.GenerateSecret()
	if err != nil {
		d.Logger().Error("totp enroll: generate secret failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		"secret":      enroller.EncodeSecret(secret),
		"otpauth_uri": enroller.OTPAuthURI(d.ResolveIssuer(ctx), userID, secret),
	})
}

// HandleTOTPEnrollConfirm serves POST /me/mfa/totp/confirm — the second leg.
// Body: {secret, code, label?}. It verifies code against the supplied secret
// (proof of possession), then persists the secret + records the factor via the
// TOTPEnrollmentWriter so the factor is immediately usable at login AND listed
// by GET /me/mfa. Oracle-safe: a malformed secret and a wrong code collapse to
// one totp_invalid_code response; the operator-side cause lives only in the
// mfa_totp_enroll_failed audit event. Credential-adjacent headers.
func HandleTOTPEnrollConfirm(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	enroller := d.TOTPEnroller()
	writer, ok := d.MFAEnrollmentStore().(core.TOTPEnrollmentWriter)
	if !ok || enroller == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrTOTPEnrollmentNotSupported))
		return
	}
	var req struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
		Label  string `json:"label"`
	}
	if err := oauth.BindParams(ctx, &req); err != nil || req.Secret == "" || req.Code == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	secret, err := enroller.DecodeSecret(req.Secret)
	if err != nil || !enroller.VerifyCode(secret, req.Code) {
		// Bad secret encoding and wrong code collapse to one response.
		recordTOTPEnrollFailure(d, ctx, userID, "invalid_code")
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrTOTPInvalidCode))
		return
	}
	factorID, err := d.NewMFAFactorID()
	if err != nil {
		d.Logger().Error("totp enroll: mint factor id failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		label = "Authenticator app"
	}
	if err := writer.AddTOTPFactor(ctx.Request().Context(), userID, factorID, label, secret); err != nil {
		d.Logger().Error("totp enroll: persist factor failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordTOTPEnrollSuccess(d, ctx, userID, factorID)
	ctx.JSON(http.StatusCreated, map[string]any{"factor_id": factorID, "label": label})
}

// HandleGenerateRecoveryCodes serves POST /me/mfa/recovery-codes — regenerate
// the caller's single-use MFA recovery codes. It revokes any prior batch first
// so a leaked earlier set dies, then mints a fresh batch and returns the
// plaintext codes EXACTLY ONCE (they are hashed at rest and never retrievable
// again). Recovery codes are credentials, so the no-store headers are mandatory.
func HandleGenerateRecoveryCodes(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.RecoveryCodeStore()
	if store == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrNotFound))
		return
	}
	if err := store.RevokeAll(ctx.Request().Context(), userID); err != nil {
		d.Logger().Error("recovery codes: revoke failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	codes, err := store.Generate(ctx.Request().Context(), userID, core.DefaultRecoveryCodeCount)
	if err != nil {
		d.Logger().Error("recovery codes: generate failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordRecoveryCodesRegenerated(d, ctx, userID, len(codes))
	ctx.JSON(http.StatusCreated, map[string]any{"recovery_codes": codes, "count": len(codes)})
}

// HandleGetRecoveryCodesCount serves GET /me/mfa/recovery-codes — return the
// number of unused codes the caller has left (for a low-pool warning). It NEVER
// returns the codes themselves; the plaintext is shown once at generation only.
func HandleGetRecoveryCodesCount(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.RecoveryCodeStore()
	if store == nil {
		ctx.JSON(http.StatusNotImplemented, d.ErrorBody(core.ErrNotFound))
		return
	}
	n, err := store.CountRemaining(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("recovery codes: count failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{"remaining": n})
}

// recordRecoveryCodesRegenerated emits the self-service regeneration audit
// event. The codes are NEVER recorded — only the count, for operator context.
func recordRecoveryCodesRegenerated(d Deps, ctx core.HandlerContext, userID string, count int) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventRecoveryCodesRegenerated,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "count", strconv.Itoa(count))
	aud.Record(ctx.Request().Context(), evt)
}

// recordTOTPEnrollSuccess / recordTOTPEnrollFailure emit the enrollment audit
// events. The secret is NEVER recorded; only the opaque factor_id (success) or
// the operator-side reason (failure, never returned to the caller).
func recordTOTPEnrollSuccess(d Deps, ctx core.HandlerContext, userID, factorID string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventTOTPEnrolled,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "factor_id", factorID)
	aud.Record(ctx.Request().Context(), evt)
}

func recordTOTPEnrollFailure(d Deps, ctx core.HandlerContext, userID, reason string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventTOTPEnrollFailed,
		Outcome: audit.OutcomeFailure,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "reason", reason)
	aud.Record(ctx.Request().Context(), evt)
}
