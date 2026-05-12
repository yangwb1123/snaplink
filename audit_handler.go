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
	ErrAuditNotEnabled = "audit_not_enabled"
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

// auditEventFromRequest pre-fills an Event with caller-side metadata
// (IP, user-agent, request ID, trace context). Handlers fill the rest.
// TracingMiddleware populates the headers this function reads; without that
// middleware installed, RequestID/TraceID/SpanID stay empty.
func auditEventFromRequest(r *http.Request) *audit.Event {
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
	return e
}

// recordLoginFailure emits a login-failure audit event. Reason is one of the
// Err* constants describing why authentication was refused.
func (s *Server) recordLoginFailure(ctx HandlerContext, clientID, provider, reason string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx.Request())
	e.Type = audit.EventLoginFailure
	e.Outcome = audit.OutcomeFailure
	e.ClientID = clientID
	e.Provider = provider
	e.Reason = reason
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordLoginSuccess emits a login event after a fully successful login flow.
func (s *Server) recordLoginSuccess(ctx HandlerContext, clientID, provider, strategy, userID, sessionID string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx.Request())
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
	e := auditEventFromRequest(ctx.Request())
	e.Type = audit.EventLogout
	e.Outcome = audit.OutcomeSuccess
	e.SessionID = sessionID
	if len(revoked) > 0 {
		e.Metadata = map[string]string{"revoked": strings.Join(revoked, ",")}
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
	e := auditEventFromRequest(ctx.Request())
	e.Type = audit.EventCodeSent
	e.Provider = provider
	if ok {
		e.Outcome = audit.OutcomeSuccess
	} else {
		e.Outcome = audit.OutcomeFailure
	}
	if target != "" {
		e.Metadata = map[string]string{"target": maskTarget(target)}
	}
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordTokenIssued emits a token_issued event (used for grant flows).
func (s *Server) recordTokenIssued(ctx HandlerContext, clientID, strategy, subjectID string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx.Request())
	e.Type = audit.EventTokenIssued
	e.Outcome = audit.OutcomeSuccess
	e.ClientID = clientID
	e.TokenStrategy = strategy
	e.ActorID = subjectID
	s.auditor.Record(ctx.Request().Context(), e)
}

// recordCallbackFailure emits a callback_failure event.
func (s *Server) recordCallbackFailure(ctx HandlerContext, provider, reason string) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx.Request())
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
