// Recorder convenience functions for common Server-level audit events.
// Each is a thin wrapper around EventFromRequest + Record that fixes
// the event Type + Outcome and lifts caller-supplied identifiers onto
// the event. Callers pass the *Recorder explicitly (nil-safe — every
// helper short-circuits on a nil recorder), so handlers in any
// subpackage can emit consistent audit events without going through
// *sso.Server.

package audit

import (
	"time"

	"github.com/snaplink/sso/core"
)

// RecordTokenIssued emits a token_issued event (any /token grant).
func RecordTokenIssued(rec *Recorder, ctx core.HandlerContext, clientID, strategy, subjectID string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventTokenIssued
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	e.TokenStrategy = strategy
	e.ActorID = subjectID
	rec.Record(ctx.Request().Context(), e)
}

// RecordRefreshTokenIssued emits a refresh_token_issued event. Set
// rotation=true on the rotation path so SIEMs can separate first-
// issue (login / authz_code) from rotation (refresh_token grant).
func RecordRefreshTokenIssued(rec *Recorder, ctx core.HandlerContext, clientID, subjectID string, rotation bool) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventRefreshTokenIssued
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subjectID
	if rotation {
		SetMeta(e, "rotation", "true")
	}
	rec.Record(ctx.Request().Context(), e)
}

// RecordIDTokenIssued emits an id_token_issued event whenever an
// OIDC id_token is appended to the response.
func RecordIDTokenIssued(rec *Recorder, ctx core.HandlerContext, clientID, subjectID string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventIDTokenIssued
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subjectID
	rec.Record(ctx.Request().Context(), e)
}

// RecordDeviceCodeIssued emits a device_code_issued event at the start
// of an RFC 8628 device authorization grant.
func RecordDeviceCodeIssued(rec *Recorder, ctx core.HandlerContext, clientID string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventDeviceCodeIssued
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	rec.Record(ctx.Request().Context(), e)
}

// RecordDeviceCodeDecision emits at the device-flow consent step.
// userID is the user who hit /device/verify; deviceClientID is the
// client_id that originally requested the device authorization.
func RecordDeviceCodeDecision(rec *Recorder, ctx core.HandlerContext, userID, deviceClientID string, approved bool) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	if approved {
		e.Type = EventDeviceCodeApproved
		e.Outcome = OutcomeSuccess
	} else {
		e.Type = EventDeviceCodeDenied
		e.Outcome = OutcomeFailure
	}
	e.ActorID = userID
	SetMeta(e, "device_client_id", deviceClientID)
	rec.Record(ctx.Request().Context(), e)
}

// RecordRefreshTokenReuse emits a refresh_token_reuse_detected event
// after a refresh-token-reuse attack invalidates a whole family.
func RecordRefreshTokenReuse(rec *Recorder, ctx core.HandlerContext, clientID, familyID string, killed int) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventRefreshTokenReuse
	e.Outcome = OutcomeFailure
	e.ClientID = clientID
	e.Reason = "family=" + familyID
	if killed > 0 {
		SetMeta(e, "killed", itoa(killed))
	}
	rec.Record(ctx.Request().Context(), e)
}

// RecordLogout emits a logout event after a /logout / /end_session
// successfully tears down a session.
func RecordLogout(rec *Recorder, ctx core.HandlerContext, sessionID string, revoked []string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventLogout
	e.Outcome = OutcomeSuccess
	if sessionID != "" {
		SetMeta(e, "session_id", sessionID)
	}
	if len(revoked) > 0 {
		SetMeta(e, "revoked", joinComma(revoked))
	}
	rec.Record(ctx.Request().Context(), e)
}

// RecordLogoutNotifySuccess / Failure emit per-RP BCL fan-out outcomes
// — both use EventLogoutNotified with distinct Outcome.
func RecordLogoutNotifySuccess(rec *Recorder, ctx core.HandlerContext, clientID, subject, uri string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventLogoutNotified
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subject
	SetMeta(e, "uri", uri)
	rec.Record(ctx.Request().Context(), e)
}

func RecordLogoutNotifyFailure(rec *Recorder, ctx core.HandlerContext, clientID, subject, reason string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventLogoutNotified
	e.Outcome = OutcomeFailure
	e.ClientID = clientID
	e.ActorID = subject
	e.Reason = reason
	rec.Record(ctx.Request().Context(), e)
}

// RecordAccountLocked emits an account_locked event when per-account
// lockout engages.
func RecordAccountLocked(rec *Recorder, ctx core.HandlerContext, clientID, provider, lockKey string, until time.Time) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventAccountLocked
	e.Outcome = OutcomeFailure
	e.ClientID = clientID
	e.Provider = provider
	e.ActorID = lockKey
	if !until.IsZero() {
		SetMeta(e, "until", until.UTC().Format(time.RFC3339))
	}
	rec.Record(ctx.Request().Context(), e)
}

// RecordCallbackFailure emits a callback_failure event when an
// external provider callback fails (oidc_federation).
func RecordCallbackFailure(rec *Recorder, ctx core.HandlerContext, provider, reason string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventCallbackFailure
	e.Outcome = OutcomeFailure
	e.Provider = provider
	e.Reason = reason
	rec.Record(ctx.Request().Context(), e)
}

// RecordMFAFailure emits an mfa_failure event with caller-supplied
// details on the failed factor.
func RecordMFAFailure(rec *Recorder, ctx core.HandlerContext, subjectID, challengeID, method, reason string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventMFAFailure
	e.Outcome = OutcomeFailure
	e.ActorID = subjectID
	e.Reason = reason
	SetMeta(e, "challenge_id", challengeID)
	SetMeta(e, "method", method)
	rec.Record(ctx.Request().Context(), e)
}

// itoa avoids importing strconv just for the tiny one-shot integer
// conversion in RecordRefreshTokenReuse.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	const digits = "0123456789"
	negative := n < 0
	if negative {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = digits[n%10]
		n /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func joinComma(s []string) string {
	if len(s) == 0 {
		return ""
	}
	n := len(s) - 1
	for _, e := range s {
		n += len(e)
	}
	b := make([]byte, 0, n)
	for i, e := range s {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, e...)
	}
	return string(b)
}
