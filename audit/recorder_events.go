// Recorder convenience functions for common Server-level audit events.
// Each is a thin wrapper around EventFromRequest + Record that fixes
// the event Type + Outcome and lifts caller-supplied identifiers onto
// the event. Callers pass the *Recorder explicitly (nil-safe — every
// helper short-circuits on a nil recorder), so handlers in any
// subpackage can emit consistent audit events without going through
// *sso.Server.

package audit

import (
	"context"
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

// RecordCIBAAuthRequest emits a ciba_auth_request event when
// /backchannel-authentication issues an auth_req_id.
func RecordCIBAAuthRequest(rec *Recorder, ctx core.HandlerContext, clientID, subjectID, authReqID string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventCIBAAuthRequest
	e.Outcome = OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subjectID
	SetMeta(e, "auth_req_id", authReqID)
	rec.Record(ctx.Request().Context(), e)
}

// RecordCIBADecision emits a ciba_approved / ciba_denied event when the
// CIBA token poll resolves a request.
func RecordCIBADecision(rec *Recorder, ctx core.HandlerContext, clientID, subjectID string, approved bool) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	if approved {
		e.Type = EventCIBAApproved
		e.Outcome = OutcomeSuccess
	} else {
		e.Type = EventCIBADenied
		e.Outcome = OutcomeFailure
	}
	e.ClientID = clientID
	e.ActorID = subjectID
	rec.Record(ctx.Request().Context(), e)
}

// RecordCIBAPingFailed emits a ciba_ping_failed event when the detached
// post-resolution ping notifier fails (Notify returned an error or panicked).
// It runs from a BACKGROUND goroutine with no HandlerContext (the request that
// triggered the resolution has already returned), so it takes a plain
// context.Context and builds the Event directly — mirroring
// RecordSigningKeyAggregationDegraded. reason carries the operator-side detail
// (the error string or "panic: ..."); auth_req_id lands in Metadata so SIEMs
// can correlate the failed ping with its originating request.
func RecordCIBAPingFailed(rec *Recorder, ctx context.Context, clientID, authReqID, reason string) {
	if rec == nil {
		return
	}
	e := &Event{
		Type:     EventCIBAPingFailed,
		Outcome:  OutcomeFailure,
		ClientID: clientID,
		Reason:   reason,
	}
	if authReqID != "" {
		SetMeta(e, "auth_req_id", authReqID)
	}
	rec.Record(ctx, e)
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

// maskTarget redacts the bulk of a phone number or email so the event
// remains auditable without storing the raw identifier.
func maskTarget(t string) string {
	if at := indexByte(t, '@'); at > 0 {
		// email: keep first char + domain
		if at == 1 {
			return t[:1] + "***" + t[at:]
		}
		return t[:1] + "***" + t[at-1:]
	}
	if len(t) > 4 {
		return t[:2] + repeat("*", len(t)-4) + t[len(t)-2:]
	}
	return "***"
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func repeat(s string, n int) string {
	if n <= 0 {
		return ""
	}
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
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

// RecordFAPIViolation emits a fapi_compliance_violation event for one
// failed FAPI 2.0 baseline rule. mode is the active profile mode
// ("inspection" | "enforce") so an operator reading the audit log can
// tell whether the request was rejected or only flagged. Plain-string
// args keep audit decoupled from the fapi package.
func RecordFAPIViolation(rec *Recorder, ctx core.HandlerContext, clientID, ruleID, detail, mode string) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventFAPIComplianceViolation
	e.Outcome = OutcomeFailure
	e.ClientID = clientID
	e.Reason = ruleID
	SetMeta(e, "fapi_rule", ruleID)
	SetMeta(e, "fapi_detail", detail)
	SetMeta(e, "fapi_mode", mode)
	rec.Record(ctx.Request().Context(), e)
}

// RecordSigningKeyAggregationDegraded emits a signing_key_aggregation_degraded
// event when the leaderless aggregation subscriber loses its registry
// subscription (Subscribe channel closed while the run context is still live).
// It runs from a BACKGROUND goroutine with no HandlerContext, so it takes a
// plain context.Context and builds the Event directly. reason lands in
// Metadata via SetMeta. Emitted exactly once per transition-to-degraded by the
// caller (the loop tracks the degraded flag), not per retry.
func RecordSigningKeyAggregationDegraded(rec *Recorder, ctx context.Context, reason string) {
	if rec == nil {
		return
	}
	e := &Event{
		Type:    EventSigningKeyAggregationDegraded,
		Outcome: OutcomeFailure,
	}
	SetMeta(e, "reason", reason)
	rec.Record(ctx, e)
}

// RecordSigningKeyAggregationRecovered emits a
// signing_key_aggregation_recovered event when a degraded aggregation
// subscriber successfully resubscribes and resumes adopting peers' keys.
// Like its degraded counterpart it runs off the request path. Emitted once per
// transition back to healthy.
func RecordSigningKeyAggregationRecovered(rec *Recorder, ctx context.Context) {
	if rec == nil {
		return
	}
	rec.Record(ctx, &Event{
		Type:    EventSigningKeyAggregationRecovered,
		Outcome: OutcomeSuccess,
	})
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
