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
	"strconv"

	"github.com/yangwb1123/snaplink/shared/core"
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

// RecordRefreshRotationVelocityExceeded emits a
// refresh_rotation_velocity_exceeded event after the rotation grant
// trips the per-family velocity cap and kills the family. The wire
// response stays the generic invalid_grant — this audit event is the
// ONLY place the velocity detail surfaces (count = rotations seen in the
// window, killed = active descendants invalidated). Metadata is set via
// SetMeta so geo/tenant enrichment is preserved.
func RecordRefreshRotationVelocityExceeded(rec *Recorder, ctx core.HandlerContext, clientID, familyID string, count, killed int) {
	if rec == nil {
		return
	}
	e := EventFromRequest(ctx)
	e.Type = EventRefreshRotationVelocityExceeded
	e.Outcome = OutcomeFailure
	e.ClientID = clientID
	e.Reason = "family=" + familyID
	if count > 0 {
		SetMeta(e, "count", itoa(count))
	}
	if killed > 0 {
		SetMeta(e, "killed", itoa(killed))
	}
	rec.Record(ctx.Request().Context(), e)
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

// RecordTokenRevoked emits a token_revoked event whenever
// *sso.Server.RevokeAcrossIssuers — the single per-replica choke point every
// /token/revoke, /token/revoke-all, the admin TokenAdminService.Revoke RPC,
// and the break-glass revoke-on-expiry sweep all funnel through, and the SAME
// site that already publishes the cluster.KindTokenRevoked cross-replica
// Event — actually revokes the token from at least one TokenIssuer. Before
// this existed, EventTokenRevoked was a declared, CEF/OCSF-mapped,
// SOC2-control-area event type that NOTHING ever recorded, so no consumer of
// the generic platform/lifecycle/webhook.Engine (already wired with admin
// CRUD, retry, and dead-letter — see that package's doc.go) could ever
// observe an ordinary revocation; this is the missing emission that lets it.
//
// Some callers (the admin RPC, the break-glass sweep) have only a plain
// context.Context, not a core.HandlerContext, so — like
// RecordSigningKeyAggregationDegraded — this builds the Event directly
// rather than via EventFromRequest.
//
// clientID/subjectID are best-effort, UNVERIFIED claims read from the
// token's own payload (see handler.JWTClaimsUnsafe): annotation only, never a
// security decision — the token was already revoked via the verified
// per-issuer Revoke path before this fires.
func RecordTokenRevoked(rec *Recorder, ctx context.Context, clientID, subjectID string, issuers []string) {
	if rec == nil {
		return
	}
	e := &Event{
		Type:     EventTokenRevoked,
		Outcome:  OutcomeSuccess,
		ClientID: clientID,
		ActorID:  subjectID,
	}
	if len(issuers) > 0 {
		SetMeta(e, "issuers", joinComma(issuers))
	}
	rec.Record(ctx, e)
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

// RecordSessionTrustStepUp emits a session_trust_stepup event when the zero-trust
// ContinuousVerificationAgent marks a live session for step-up because its decayed
// trust fell below the floor. Runs off the request path (the agent's sweep
// goroutine), so it takes a plain context.Context like the aggregation siblings.
// The decayed score + floor land in Metadata via SetMeta (bounded, numeric — no
// PII); the session + subject identify the affected login. Outcome is failure to
// surface it as a security signal in outcome-filtered views.
func RecordSessionTrustStepUp(rec *Recorder, ctx context.Context, sessionID, userID string, score, floor float64) {
	if rec == nil {
		return
	}
	e := &Event{
		Type:      EventSessionTrustStepUp,
		Outcome:   OutcomeFailure,
		SessionID: sessionID,
		ActorID:   userID,
	}
	SetMeta(e, "score", strconv.FormatFloat(score, 'f', 2, 64))
	SetMeta(e, "floor", strconv.FormatFloat(floor, 'f', 2, 64))
	rec.Record(ctx, e)
}

// RecordSigningKeyRotationCoordinated emits a signing_key_rotation_coordinated
// event when this replica acted on a received cross-replica
// cluster.KindSigningKeyRotation Event (deferring the demoted kid's retirement
// to the carried deadline and/or adopting the new kid verify-only). Runs off
// the request path (the bus subscriber goroutine), so it takes a plain
// context.Context like its aggregation siblings. outcome ∈ {deferred, extended,
// adopted_only, noop} lands in Metadata via SetMeta — NO kid is recorded
// (bounded cardinality + no key-timeline leak; the originating
// signing_key_rotated event already carries the from/to kids on the rotating
// replica).
func RecordSigningKeyRotationCoordinated(rec *Recorder, ctx context.Context, outcome string) {
	if rec == nil {
		return
	}
	e := &Event{
		Type:    EventSigningKeyRotationCoordinated,
		Outcome: OutcomeSuccess,
	}
	SetMeta(e, "outcome", outcome)
	rec.Record(ctx, e)
}

// RecordConnectionAuthenticatorBuildFailed emits a
// connection_authenticator_build_failed event when a resolved B2B connection's
// upstream authenticator cannot be built from its stored Config. This is the
// OPERATOR's misconfiguration signal: the wire response collapses to the same
// unsupported_provider shape as an unknown provider (anti-enumeration), so
// this event + the server log are the only places the detail may appear.
// reason is the build error text — Connection.Config is admin:write-only
// trusted input and the validation errors name missing KEYS, never secret
// VALUES, so it is safe to record.
func RecordConnectionAuthenticatorBuildFailed(rec *Recorder, ctx context.Context, connectionID, tenantID, reason string) {
	if rec == nil {
		return
	}
	e := &Event{
		Type:     EventConnectionAuthenticatorBuildFailed,
		Outcome:  OutcomeFailure,
		TenantID: tenantID,
	}
	SetMeta(e, "connection_id", connectionID)
	SetMeta(e, "reason", reason)
	rec.Record(ctx, e)
}
