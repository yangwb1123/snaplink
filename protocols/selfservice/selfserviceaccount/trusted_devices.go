package selfserviceaccount

import (
	"net/http"
	"slices"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// HandleMyTrustedDevices serves GET /me/devices — lists the authenticated
// user's live "remember this device" MFA-skip grants. Metadata only (id,
// client_id, label, timestamps) — the store never returns the token or its
// hash once Trust has minted it. Credential-adjacent; no-store headers.
func HandleMyTrustedDevices(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	store := d.TrustedDeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	devices, err := store.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list trusted devices failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if devices == nil {
		devices = []core.TrustedDevice{}
	}
	ctx.JSON(http.StatusOK, map[string]any{"devices": devices})
}

// HandleTrustMyDevice serves POST /me/devices/trust — marks the device
// presenting THIS bearer token trusted for the token's client, so a later
// /auth/login to the SAME client can skip a risk-scorer-demanded MFA
// challenge for up to the configured TTL.
//
// Gated on the caller's access token having completed MFA THIS session
// (amr contains RFC 8176 "mfa"): a bearer token minted from a plain
// password login — even a perfectly valid, unexpired one — cannot mint a
// skip grant. This is the load-bearing invariant against "steal a live
// session, silently upgrade to a standing MFA bypass": an attacker who
// steals a non-stepped-up access or refresh token gains nothing by calling
// this endpoint, because the token they present will never carry "mfa" in
// amr. Oracle-safe to name the failure explicitly (RFC 9470
// insufficient_user_authentication) rather than collapse it to a generic
// 403 — this is a legitimate step-up demand on the caller's OWN account,
// not a credential-guessing surface.
func HandleTrustMyDevice(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	claims, ok := d.MeClaimsOrChallenge(ctx)
	if !ok {
		return
	}
	if code, denied := d.ResidencyGateWrite(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(code))
		return
	}
	if !slices.Contains(claims.AMR, "mfa") {
		ctx.JSON(http.StatusForbidden, d.ErrorBody(security.ErrInsufficientUserAuthentication))
		return
	}
	store := d.TrustedDeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	var req struct {
		Label string `json:"label"`
	}
	// label is a cosmetic display hint only — an empty/missing body is fine.
	_ = oauth.BindParams(ctx, &req)

	token, device, err := store.Trust(ctx.Request().Context(), claims.Subject, claims.ClientID, req.Label, d.TrustedDeviceTTL())
	if err != nil {
		d.Logger().Error("trust device failed", "user_id", claims.Subject, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordDeviceTrusted(d, ctx, claims.Subject, claims.ClientID, device.ID)
	// device_token is a bearer-equivalent MFA-skip credential, returned
	// EXACTLY ONCE — the store persists only its hash from here on, so this
	// response body is the caller's only chance to capture it.
	ctx.JSON(http.StatusCreated, map[string]any{
		"device_id":    device.ID,
		"device_token": token,
		"label":        device.Label,
		"expires_at":   device.ExpiresAt,
	})
}

// HandleRevokeMyTrustedDevice serves DELETE /me/devices/:id — revokes one of
// the authenticated user's own trusted-device grants. A grant belonging to
// another user (or a missing id) responds with the same 404 as a missing
// grant — oracle-safe, mirrors HandleDeleteMyMFAFactor: ownership is
// enforced via the user-scoped list, so a cross-user delete can never
// remove someone else's grant.
func HandleRevokeMyTrustedDevice(d Deps, ctx core.HandlerContext) {
	d.TokenNoStoreHeaders(ctx)
	userID, ok := d.MeSubjectOrChallenge(ctx)
	if !ok {
		return
	}
	deviceID := ctx.Param("id")
	if deviceID == "" {
		ctx.JSON(http.StatusBadRequest, d.ErrorBody(core.ErrInvalidRequest))
		return
	}
	store := d.TrustedDeviceStore()
	if store == nil {
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	devices, err := store.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("list trusted devices failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	if !slices.ContainsFunc(devices, func(dev core.TrustedDevice) bool { return dev.ID == deviceID }) {
		// Not owned by this user, or never existed — one response either way.
		ctx.JSON(http.StatusNotFound, d.ErrorBody(core.ErrNotFound))
		return
	}
	if err := store.Revoke(ctx.Request().Context(), userID, deviceID); err != nil {
		d.Logger().Error("revoke trusted device failed", "user_id", userID, "error", err)
		ctx.JSON(http.StatusInternalServerError, d.ErrorBody(core.ErrInternal))
		return
	}
	recordDeviceTrustRevoked(d, ctx, userID, deviceID, "self_service")
	ctx.JSON(http.StatusNoContent, nil)
}

// recordDeviceTrusted / recordDeviceTrustRevoked emit the trusted-device
// lifecycle audit events. Neither records the token or its hash — only the
// opaque device_id, which grants nothing on its own.
func recordDeviceTrusted(d Deps, ctx core.HandlerContext, userID, clientID, deviceID string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:     audit.EventDeviceTrusted,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  userID,
		ClientID: clientID,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "device_id", deviceID)
	aud.Record(ctx.Request().Context(), evt)
}

func recordDeviceTrustRevoked(d Deps, ctx core.HandlerContext, userID, deviceID, reason string) {
	aud := d.Auditor()
	if aud == nil {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventDeviceTrustRevoked,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "device_id", deviceID)
	audit.SetMeta(evt, "reason", reason)
	aud.Record(ctx.Request().Context(), evt)
}
