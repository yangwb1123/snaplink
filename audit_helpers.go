package sso

import (
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/metrics"
)
func (s *Server) observeLoginDuration(ctx HandlerContext, provider, outcome string) {
	if s.metrics == nil {
		return
	}
	v := ctx.Get(ctxKeyLoginStart)
	start, ok := v.(time.Time)
	if !ok {
		return
	}
	s.metrics.LoginDuration.WithLabelValues(provider, outcome).Observe(time.Since(start).Seconds())
}

// recordLoginFailure emits a login-failure audit event AND bumps the
// failure counter on the metrics registry (nil-safe). Reason is one of
// the Err* constants describing why authentication was refused.
func (s *Server) recordLoginFailure(ctx HandlerContext, clientID, provider, reason string) {
	if s.metrics != nil {
		s.metrics.LoginAttemptsTotal.WithLabelValues(provider, "failure").Inc()
	}
	s.recordTenantLoginAttempt(ctx, clientID, "failure")
	s.observeLoginDuration(ctx, provider, "failure")
	s.dispatchLoginAnomaly(ctx, "", clientID, provider, "failure", reason)
	if s.auditor == nil {
		return
	}
	audit.RecordLoginFailure(s.auditor, ctx, clientID, provider, reason)
}

// dispatchLoginAnomaly hands a anomaly.LoginEvent to the AnomalyRunner.
// Nil-safe — no runner = no-op zero overhead. SubjectID is
// optional on failure paths (the credential validator may not
// have resolved a user); detectors needing it skip the subject-
// scoped checks.
func (s *Server) dispatchLoginAnomaly(ctx HandlerContext, subjectID, clientID, provider, outcome, failureReason string) {
	if s.anomalyRunner == nil {
		return
	}
	r := ctx.Request()
	event := &anomaly.LoginEvent{
		SubjectID:     subjectID,
		ClientID:      clientID,
		Provider:      provider,
		Outcome:       outcome,
		FailureReason: failureReason,
		RemoteIP:      audit.ClientIP(r),
		UserAgent:     r.Header.Get("User-Agent"),
		Timestamp:     time.Now(),
	}
	if info, ok := GeoFromHandlerContext(ctx); ok {
		event.Geo = info
	}
	if tp := r.Header.Get(HeaderTraceparent); tp != "" {
		if tc, err := tracer.ParseTraceparent(tp); err == nil {
			event.TraceID = tc.TraceID
		}
	}
	s.anomalyRunner.Dispatch(r.Context(), event)
}

// recordLoginSuccess emits a login event after a fully successful login flow
// AND bumps the success counter + tokens_issued counter on the metrics
// registry (nil-safe).
func (s *Server) recordLoginSuccess(ctx HandlerContext, clientID, provider, strategy, userID, sessionID string) {
	if s.metrics != nil {
		s.metrics.LoginAttemptsTotal.WithLabelValues(provider, "success").Inc()
		s.metrics.TokensIssuedTotal.WithLabelValues(strategy).Inc()
	}
	s.recordTenantLoginAttempt(ctx, clientID, "success")
	s.recordTenantTokenIssued(ctx, clientID, strategy)
	s.observeLoginDuration(ctx, provider, "success")
	s.dispatchLoginAnomaly(ctx, userID, clientID, provider, "success", "")
	if s.auditor == nil {
		return
	}
	audit.RecordLoginSuccess(s.auditor, ctx, clientID, provider, strategy, userID, sessionID)
}

// recordCredentialHealth emits a non-blocking credential-health signal
// after a successful login (password_weak / password_compromised). It is
// purely informational — the login already succeeded and was not blocked.
// nil health short-circuits with zero overhead (no checker wired, or a
// healthy credential). Counts the signal toward the bounded
// credential-health metric before auditing.
func (s *Server) recordCredentialHealth(ctx HandlerContext, clientID, userID string, health *CredentialHealth) {
	if health == nil {
		return
	}
	if s.metrics != nil {
		signal := metrics.SignalWeak
		if health.Compromised {
			signal = metrics.SignalCompromised
		}
		s.metrics.CredentialHealthSignalsTotal.WithLabelValues(signal).Inc()
	}
	audit.RecordCredentialHealth(s.auditor, ctx, clientID, userID, health)
}

// recordLogout emits a logout event with what was actually revoked.
func (s *Server) recordLogout(ctx HandlerContext, sessionID string, revoked []string) {
	audit.RecordLogout(s.auditor, ctx, sessionID, revoked)
}

// recordLogoutNotifySuccess emits a `logout_notified` audit
// event for a successful back-channel logout fanout. ClientID is
// the RP that was notified; ActorID is the user whose logout
// triggered the notification.
func (s *Server) recordLogoutNotifySuccess(ctx HandlerContext, clientID, subject, uri string) {
	audit.RecordLogoutNotifySuccess(s.auditor, ctx, clientID, subject, uri)
}

// recordLogoutNotifyFailure emits a `logout_notified` audit
// event with Outcome=failure when the back-channel POST failed
// or the RP returned a non-2xx status. The error string lands
// in Reason so SIEMs can alert on patterns ("rp-X always 503").
func (s *Server) recordLogoutNotifyFailure(ctx HandlerContext, clientID, subject, reason string) {
	audit.RecordLogoutNotifyFailure(s.auditor, ctx, clientID, subject, reason)
}

// recordAccountLocked emits an account_locked audit event. Fires
// both when a NEW lockout engages (after the failure crossed the
// threshold) and when a subsequent attempt arrives while the
// lock is still active — operators want both signals to
// distinguish "lock just engaged" from "attacker keeps trying
// against a locked account". The lockoutKey lands in ActorID so
// SIEMs can pivot on it.
func (s *Server) recordAccountLocked(ctx HandlerContext, clientID, provider, lockKey string, until time.Time) {
	audit.RecordAccountLocked(s.auditor, ctx, clientID, provider, lockKey, until)
}

// recordCodeSent emits a code_sent event for two-step flows (phone/email).
// target is intentionally not stored in full to limit PII spread; only its
// type lives in Provider, the value goes into a short metadata key.
func (s *Server) recordCodeSent(ctx HandlerContext, provider, target string, ok bool) {
	audit.RecordCodeSent(s.auditor, ctx, provider, target, ok)
}

// recordTokenIssued emits a token_issued event (used for grant flows).
func (s *Server) recordTokenIssued(ctx HandlerContext, clientID, strategy, subjectID string) {
	s.recordTenantTokenIssued(ctx, clientID, strategy)
	audit.RecordTokenIssued(s.auditor, ctx, clientID, strategy, subjectID)
}

// recordRefreshTokenIssued emits a refresh_token_issued event. Set
// rotation=true on the rotation path so SIEMs can separate first-
// issue (login / authz_code) from rotation (refresh_token grant).
func (s *Server) recordRefreshTokenIssued(ctx HandlerContext, clientID, subjectID string, rotation bool) {
	audit.RecordRefreshTokenIssued(s.auditor, ctx, clientID, subjectID, rotation)
}

// recordIDTokenIssued emits an id_token_issued event whenever an
// OIDC id_token is appended to the response.
func (s *Server) recordIDTokenIssued(ctx HandlerContext, clientID, subjectID string) {
	audit.RecordIDTokenIssued(s.auditor, ctx, clientID, subjectID)
}

// recordDeviceCodeIssued emits a device_code_issued event at the
// start of an RFC 8628 device authorization grant.
func (s *Server) recordDeviceCodeIssued(ctx HandlerContext, clientID string) {
	audit.RecordDeviceCodeIssued(s.auditor, ctx, clientID)
}

// recordDeviceCodeApproved / Denied emit at the consent step.
// userID is the user who hit /device/verify; deviceClientID is the
// client_id that originally requested the device authorization.
func (s *Server) recordDeviceCodeDecision(ctx HandlerContext, userID, deviceClientID string, approved bool) {
	audit.RecordDeviceCodeDecision(s.auditor, ctx, userID, deviceClientID, approved)
}

// recordRefreshTokenReuse emits a refresh_token_reuse_detected event.
// Fired from the rotation grant when the store signals
// oauth.ErrRefreshTokenReused — a security signal worth routing to alerting.
func (s *Server) recordRefreshTokenReuse(ctx HandlerContext, clientID, familyID string, killed int) {
	audit.RecordRefreshTokenReuse(s.auditor, ctx, clientID, familyID, killed)
}

// recordRefreshRotationVelocity emits a refresh_rotation_velocity_exceeded
// event after the per-family rotation-velocity cap trips and the family is
// killed. The wire response stays the generic invalid_grant — this audit
// event (plus sso_refresh_rotation_velocity_exceeded_total) is the only
// place the velocity detail surfaces.
func (s *Server) recordRefreshRotationVelocity(ctx HandlerContext, clientID, familyID string, count, killed int) {
	audit.RecordRefreshRotationVelocityExceeded(s.auditor, ctx, clientID, familyID, count, killed)
}

// recordCallbackFailure emits a callback_failure event.
func (s *Server) recordCallbackFailure(ctx HandlerContext, provider, reason string) {
	audit.RecordCallbackFailure(s.auditor, ctx, provider, reason)
}

// PathOIDCDiscovery is the OpenID Connect Discovery 1.0 metadata
// endpoint (also the de-facto location for RFC 8414 OAuth 2.0
// Authorization Server Metadata since most ecosystems collapsed them).
