package selfservicecore

import (
	"strconv"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
)

// RevokeTrustedDevicesOnCompromiseSignal invalidates every "remember this
// device" MFA-skip grant for userID. Lives here (rather than in
// selfserviceaccount, where it originated alongside HandleChangeMyPassword)
// so every account-compromise-adjacent self-service signal can share ONE
// call site: a changed password, and "sign out everywhere" / "revoke all
// sessions" (selfservice/sessions.go) are all strong enough signals that a
// trusted-device grant minted before the signal must not silently outlive
// it — otherwise an attacker who minted a grant with a transiently-stolen
// already-MFA'd bearer token keeps a standing MFA-skip for up to the
// remaining TTL even after the legitimate user's remediation.
//
// Best-effort / fail-open: the store error is logged, not surfaced, because
// the caller's real request (password change, sign-out) already succeeded
// — the caller must not see a 500 for a cleanup step that failed after
// their real request was honored. No-op when no store is wired
// (byte-identical to a build without this feature).
func RevokeTrustedDevicesOnCompromiseSignal(d Deps, ctx core.HandlerContext, userID, reason string) {
	store := d.TrustedDeviceStore()
	if store == nil {
		return
	}
	n, err := store.RevokeAll(ctx.Request().Context(), userID)
	if err != nil {
		d.Logger().Error("revoke trusted devices failed", "user_id", userID, "reason", reason, "error", err)
		return
	}
	recordDeviceTrustRevokedBulk(d, ctx, userID, n, reason)
}

// recordDeviceTrustRevokedBulk emits ONE device_trust_revoked audit event
// for a RevokeAll sweep — a count instead of a device_id, so a bulk cleanup
// doesn't fan out into N events for what the caller experiences as a single
// action. No-op when count is 0 (the user had no trusted devices — not
// audit-worthy) or no auditor is wired.
func recordDeviceTrustRevokedBulk(d Deps, ctx core.HandlerContext, userID string, count int, reason string) {
	aud := d.Auditor()
	if aud == nil || count == 0 {
		return
	}
	evt := &audit.Event{
		Type:    audit.EventDeviceTrustRevoked,
		Outcome: audit.OutcomeSuccess,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "count", strconv.Itoa(count))
	audit.SetMeta(evt, "reason", reason)
	aud.Record(ctx.Request().Context(), evt)
}
