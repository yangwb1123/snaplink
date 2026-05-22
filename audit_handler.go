package sso

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
)

// Query parameter names for /audit/events.
const (
	QueryAuditType      = "type"
	QueryAuditActorID   = "actor_id"
	QueryAuditClientID  = "client_id"
	QueryAuditProvider  = "provider"
	QueryAuditOutcome   = "outcome"
	QueryAuditRequestID = "request_id"
	QueryAuditTraceID   = "trace_id"
	QueryAuditSince     = "since"
	QueryAuditUntil     = "until"
	QueryAuditLimit     = "limit"
	QueryAuditOffset    = "offset"
)

// Response keys for /audit/events.
const (
	KeyAuditEvents = "events"
	KeyAuditCount  = "count"
)

// Error codes for /audit/events.
const (
	ErrAuditNotEnabled    = "audit_not_enabled"
	ErrAuditEventNotFound = "audit_event_not_found"
)

func (s *Server) handleAuditEvents(ctx HandlerContext) {
	if s.auditor == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrAuditNotEnabled))
		return
	}

	q, err := parseAuditQuery(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(ErrInvalidRequest, err.Error()))
		return
	}

	events, err := s.auditor.Sink().Query(ctx.Request().Context(), q)
	if err != nil {
		s.logger.Error("audit query failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, map[string]any{
		KeyAuditEvents: events,
		KeyAuditCount:  len(events),
	})
}

func (s *Server) handleAuditEventByID(ctx HandlerContext) {
	if s.auditor == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrAuditNotEnabled))
		return
	}

	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}

	event, err := s.auditor.Sink().Get(ctx.Request().Context(), id)
	if err != nil {
		if errors.Is(err, audit.ErrEventNotFound) {
			ctx.JSON(http.StatusNotFound, errorBody(ErrAuditEventNotFound))
			return
		}
		s.logger.Error("audit get failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	ctx.JSON(http.StatusOK, event)
}

func parseAuditQuery(ctx HandlerContext) (audit.Query, error) {
	q := audit.Query{
		Type:      audit.EventType(ctx.Query(QueryAuditType)),
		ActorID:   ctx.Query(QueryAuditActorID),
		ClientID:  ctx.Query(QueryAuditClientID),
		Provider:  ctx.Query(QueryAuditProvider),
		Outcome:   audit.Outcome(ctx.Query(QueryAuditOutcome)),
		RequestID: ctx.Query(QueryAuditRequestID),
		TraceID:   ctx.Query(QueryAuditTraceID),
	}
	if v := ctx.Query(QueryAuditSince); v != "" {
		t, err := parseAuditTime(v)
		if err != nil {
			return q, err
		}
		q.Since = t
	}
	if v := ctx.Query(QueryAuditUntil); v != "" {
		t, err := parseAuditTime(v)
		if err != nil {
			return q, err
		}
		q.Until = t
	}
	if v := ctx.Query(QueryAuditLimit); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return q, err
		}
		q.Limit = n
	}
	if v := ctx.Query(QueryAuditOffset); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return q, err
		}
		q.Offset = n
	}
	return q, nil
}

// parseAuditTime accepts RFC3339 ("2006-01-02T15:04:05Z") and also Unix
// seconds for convenience from CLI testing.
func parseAuditTime(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Time{}, errors.New("expected RFC3339 timestamp or unix seconds")
}

// auditEventFromRequest pre-fills an Event with caller-side
// metadata (IP, user-agent, request ID, trace context, plus geo
// when the geo middleware is wired). Handlers fill the rest.
// TracingMiddleware populates the headers this function reads;
// without that middleware installed, RequestID/TraceID/SpanID
// stay empty. GeoMiddleware similarly populates the geo metadata
// keys; without it, no geo.* metadata appears.
func auditEventFromRequest(ctx HandlerContext) *audit.Event {
	r := ctx.Request()
	e := &audit.Event{
		RequestID:    r.Header.Get(HeaderRequestID),
		ParentSpanID: r.Header.Get(HeaderParentSpanID),
		ActorIP:      clientIP(r),
		UserAgent:    r.Header.Get("User-Agent"),
	}
	if tp := r.Header.Get(HeaderTraceparent); tp != "" {
		if tc, err := tracer.ParseTraceparent(tp); err == nil {
			e.TraceID = tc.TraceID
			e.SpanID = tc.SpanID
		}
	}
	enrichEventTenant(ctx, e)
	enrichEventGeo(ctx, e)
	return e
}

// enrichEventTenant lifts tenant routing results onto
// Event.Metadata under the tenant.* prefix. No-op when the
// tenant middleware didn't run (no store wired, unknown host,
// suspended tenant). Tenant goes onto every audit event so
// SIEM filters like "show me failed logins for tenant X" become
// a single Metadata key check.
func enrichEventTenant(ctx HandlerContext, e *audit.Event) {
	r, ok := TenantFromHandlerContext(ctx)
	if !ok || r.Tenant == nil {
		return
	}
	setMeta(e, "tenant.id", r.Tenant.ID)
	setMeta(e, "tenant.slug", r.Tenant.Slug)
	if r.Domain != nil {
		setMeta(e, "tenant.domain", r.Domain.Hostname)
	}
}

// enrichEventGeo lifts geo lookup results from HandlerContext onto
// Event.Metadata under the geo.* prefix. No-op when the geo
// middleware didn't run (no Lookup, ErrNotFound, nil Provider).
// Only non-empty fields are projected so audit consumers can do a
// presence check rather than a value check.
func enrichEventGeo(ctx HandlerContext, e *audit.Event) {
	info, ok := GeoFromHandlerContext(ctx)
	if !ok {
		return
	}
	setMeta(e, "geo.country_code", info.CountryCode)
	setMeta(e, "geo.region", info.Region)
	setMeta(e, "geo.city", info.City)
	setMeta(e, "geo.recommended_language", info.RecommendedLanguage)
}

// setMeta writes key=val into e.Metadata, lazily allocating the map
// and skipping empty values. Use this instead of `e.Metadata = map[...]{...}`
// — direct assignment would clobber whatever auditEventFromRequest
// already populated (geo enrichment, future fields).
func setMeta(e *audit.Event, key, val string) {
	if val == "" {
		return
	}
	if e.Metadata == nil {
		e.Metadata = make(map[string]string, 4)
	}
	e.Metadata[key] = val
}

// ctxKeyLoginStart is the HandlerContext.Set/Get key holding the
// time.Time stamped at /auth/login entry. Used by recordLogin* to
// observe the per-provider login duration histogram.
const ctxKeyLoginStart = "_sso_login_start"

// observeLoginDuration computes elapsed since the stamp + observes
// the histogram. Safe no-op when metrics aren't wired or the stamp
// is absent (defensive — tests may bypass handleLogin).
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
	s.observeLoginDuration(ctx, provider, "failure")
	s.dispatchLoginAnomaly(ctx, "", clientID, provider, "failure", reason)
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventLoginFailure
	e.Outcome = audit.OutcomeFailure
	e.ClientID = clientID
	e.Provider = provider
	e.Reason = reason
	s.auditor.Record(ctx.Request().Context(), e)
}

// dispatchLoginAnomaly hands a LoginEvent to the AnomalyRunner.
// Nil-safe — no runner = no-op zero overhead. SubjectID is
// optional on failure paths (the credential validator may not
// have resolved a user); detectors needing it skip the subject-
// scoped checks.
func (s *Server) dispatchLoginAnomaly(ctx HandlerContext, subjectID, clientID, provider, outcome, failureReason string) {
	if s.anomalyRunner == nil {
		return
	}
	r := ctx.Request()
	event := &LoginEvent{
		SubjectID:     subjectID,
		ClientID:      clientID,
		Provider:      provider,
		Outcome:       outcome,
		FailureReason: failureReason,
		RemoteIP:      clientIP(r),
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
	s.observeLoginDuration(ctx, provider, "success")
	s.dispatchLoginAnomaly(ctx, userID, clientID, provider, "success", "")
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventLogin
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	e.Provider = provider
	e.TokenStrategy = strategy
	e.ActorID = userID
	e.SessionID = sessionID
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordLogout emits a logout event with what was actually revoked.
func (s *Server) recordLogout(ctx HandlerContext, sessionID string, revoked []string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventLogout
	e.Outcome = audit.OutcomeSuccess
	e.SessionID = sessionID
	if len(revoked) > 0 {
		setMeta(e, "revoked", strings.Join(revoked, ","))
	}
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordLogoutNotifySuccess emits a `logout_notified` audit
// event for a successful back-channel logout fanout. ClientID is
// the RP that was notified; ActorID is the user whose logout
// triggered the notification.
func (s *Server) recordLogoutNotifySuccess(ctx HandlerContext, clientID, subject, uri string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventLogoutNotified
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subject
	setMeta(e, "uri", uri)
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordLogoutNotifyFailure emits a `logout_notified` audit
// event with Outcome=failure when the back-channel POST failed
// or the RP returned a non-2xx status. The error string lands
// in Reason so SIEMs can alert on patterns ("rp-X always 503").
func (s *Server) recordLogoutNotifyFailure(ctx HandlerContext, clientID, subject, reason string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventLogoutNotified
	e.Outcome = audit.OutcomeFailure
	e.ClientID = clientID
	e.ActorID = subject
	e.Reason = reason
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordAccountLocked emits an account_locked audit event. Fires
// both when a NEW lockout engages (after the failure crossed the
// threshold) and when a subsequent attempt arrives while the
// lock is still active — operators want both signals to
// distinguish "lock just engaged" from "attacker keeps trying
// against a locked account". The lockoutKey lands in ActorID so
// SIEMs can pivot on it.
func (s *Server) recordAccountLocked(ctx HandlerContext, clientID, provider, lockKey string, until time.Time) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventAccountLocked
	e.Outcome = audit.OutcomeFailure
	e.ClientID = clientID
	e.Provider = provider
	e.ActorID = lockKey
	if !until.IsZero() {
		setMeta(e, "until", until.UTC().Format(time.RFC3339))
	}
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordCodeSent emits a code_sent event for two-step flows (phone/email).
// target is intentionally not stored in full to limit PII spread; only its
// type lives in Provider, the value goes into a short metadata key.
func (s *Server) recordCodeSent(ctx HandlerContext, provider, target string, ok bool) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventCodeSent
	e.Provider = provider
	if ok {
		e.Outcome = audit.OutcomeSuccess
	} else {
		e.Outcome = audit.OutcomeFailure
	}
	if target != "" {
		setMeta(e, "target", maskTarget(target))
	}
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordTokenIssued emits a token_issued event (used for grant flows).
func (s *Server) recordTokenIssued(ctx HandlerContext, clientID, strategy, subjectID string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventTokenIssued
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	e.TokenStrategy = strategy
	e.ActorID = subjectID
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordRefreshTokenIssued emits a refresh_token_issued event. Set
// rotation=true on the rotation path so SIEMs can separate first-
// issue (login / authz_code) from rotation (refresh_token grant).
func (s *Server) recordRefreshTokenIssued(ctx HandlerContext, clientID, subjectID string, rotation bool) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventRefreshTokenIssued
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subjectID
	if rotation {
		setMeta(e, "rotation", "true")
	}
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordIDTokenIssued emits an id_token_issued event whenever an
// OIDC id_token is appended to the response.
func (s *Server) recordIDTokenIssued(ctx HandlerContext, clientID, subjectID string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventIDTokenIssued
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	e.ActorID = subjectID
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordDeviceCodeIssued emits a device_code_issued event at the
// start of an RFC 8628 device authorization grant.
func (s *Server) recordDeviceCodeIssued(ctx HandlerContext, clientID string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventDeviceCodeIssued
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordDeviceCodeApproved / Denied emit at the consent step.
// userID is the user who hit /device/verify; deviceClientID is the
// client_id that originally requested the device authorization.
func (s *Server) recordDeviceCodeDecision(ctx HandlerContext, userID, deviceClientID string, approved bool) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	if approved {
		e.Type = audit.EventDeviceCodeApproved
		e.Outcome = audit.OutcomeSuccess
	} else {
		e.Type = audit.EventDeviceCodeDenied
		e.Outcome = audit.OutcomeFailure
	}
	e.ActorID = userID
	setMeta(e, "device_client_id", deviceClientID)
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordRefreshTokenReuse emits a refresh_token_reuse_detected event.
// Fired from the rotation grant when the store signals
// ErrRefreshTokenReused — a security signal worth routing to alerting.
func (s *Server) recordRefreshTokenReuse(ctx HandlerContext, clientID, familyID string, killed int) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventRefreshTokenReuse
	e.Outcome = audit.OutcomeFailure
	e.ClientID = clientID
	e.Reason = "family=" + familyID
	if killed > 0 {
		setMeta(e, "killed", itoa(killed))
	}
	s.auditor.Record(ctx.Request().Context(), e)
}

// itoa is a tiny strconv-free int formatter — keeps audit_handler.go
// free of a strconv import for one call site.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// recordCallbackFailure emits a callback_failure event.
func (s *Server) recordCallbackFailure(ctx HandlerContext, provider, reason string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventCallbackFailure
	e.Outcome = audit.OutcomeFailure
	e.Provider = provider
	e.Reason = reason
	s.auditor.Record(ctx.Request().Context(), e)
}

// maskTarget redacts the bulk of a phone number or email so the event remains
// auditable without storing the raw identifier.
func maskTarget(t string) string {
	if at := strings.IndexByte(t, '@'); at > 0 {
		// email: keep first char + domain
		if at == 1 {
			return t[:1] + "***" + t[at:]
		}
		return t[:1] + "***" + t[at-1:]
	}
	if len(t) > 4 {
		return t[:2] + strings.Repeat("*", len(t)-4) + t[len(t)-2:]
	}
	return "***"
}

func clientIP(r *http.Request) string {
	if h := r.Header.Get("X-Forwarded-For"); h != "" {
		if i := strings.IndexByte(h, ','); i > 0 {
			return strings.TrimSpace(h[:i])
		}
		return strings.TrimSpace(h)
	}
	if h := r.Header.Get("X-Real-IP"); h != "" {
		return h
	}
	if i := strings.LastIndexByte(r.RemoteAddr, ':'); i > 0 {
		return r.RemoteAddr[:i]
	}
	return r.RemoteAddr
}
