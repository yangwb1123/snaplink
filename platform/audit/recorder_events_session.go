// Recorder convenience functions for login, logout, lockout,
// credential-health, code-send, callback, and MFA audit events. Split
// out of recorder_events.go to keep each file under the size budget;
// same package, so no call-site changes. Each helper is a thin wrapper
// around EventFromRequest + Record and is nil-safe.

package audit

import (
	"time"

	"github.com/snaplink/sso/shared/core"
)

// RecordCredentialHealth emits a non-blocking credential-health signal
// after a successful login. A Weak signal yields a password_weak event; a
// Compromised signal yields a password_compromised event (Compromised
// wins when a checker somehow sets both). Outcome is success — the login
// was NOT blocked; this is informational. The operator-facing Reason
// lands in Metadata via SetMeta so geo/tenant enrichment is preserved.
// nil health short-circuits (no event).
func RecordCredentialHealth(rec *Recorder, ctx core.HandlerContext, clientID, subjectID string, health *core.CredentialHealth) {
	if rec == nil || health == nil {
		return
	}
	e := EventFromRequest(ctx)
	if health.Compromised {
		e.Type = EventPasswordCompromised
	} else {
		e.Type = EventPasswordWeak
	}
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subjectID
	if health.Reason != "" {
		SetMeta(e, "reason", health.Reason)
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
	e.SessionID = sessionID
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

// RecordLoginSuccess emits a login event (Outcome=success) with the
// authenticated subject + the issuance strategy.
func RecordLoginSuccess(rec *Recorder, ctx core.HandlerContext, clientID, provider, strategy, userID, sessionID string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventLogin
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	e.Provider = provider
	e.TokenStrategy = strategy
	e.ActorID = userID
	e.SessionID = sessionID
	rec.Record(ctx.Request().Context(), e)
}

// RecordLoginFailure emits a login_failure event with the caller-supplied
// reason. SubjectID isn't included (unknown for failed logins by design).
func RecordLoginFailure(rec *Recorder, ctx core.HandlerContext, clientID, provider, reason string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventLoginFailure
	e.Outcome = OutcomeFailure
	e.ClientID = clientID
	e.Provider = provider
	e.Reason = reason
	rec.Record(ctx.Request().Context(), e)
}

// RecordCodeSent emits a code_sent event for two-step flows (phone/email).
// target is intentionally not stored in full to limit PII spread; only its
// type lives in Provider, the value goes into a short metadata key.
func RecordCodeSent(rec *Recorder, ctx core.HandlerContext, provider, target string, ok bool) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventCodeSent
	e.Provider = provider
	if ok {
		e.Outcome = OutcomeSuccess
	} else {
		e.Outcome = OutcomeFailure
	}
	if target != "" {
		SetMeta(e, "target", maskTarget(target))
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
// details on the failed factor. Mirrors the metadata key shape used
// by the original Server.recordMFAFailure (mfa_method / mfa_challenge_id).
func RecordMFAFailure(rec *Recorder, ctx core.HandlerContext, subjectID, challengeID, method, reason string) {
	if rec == nil {
		return
	}
	e := &Event{
		Type:    EventMFAFailure,
		Outcome: OutcomeFailure,
		ActorID: subjectID,
		ActorIP: ClientIP(ctx.Request()),
		Reason:  reason,
	}
	if method != "" {
		SetMeta(e, core.KeyMFAMethod, method)
	}
	if challengeID != "" {
		SetMeta(e, core.KeyMFAChallengeID, challengeID)
	}
	rec.Record(ctx.Request().Context(), e)
}
