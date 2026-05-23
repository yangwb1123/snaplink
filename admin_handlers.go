package sso

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/permissions"
)

// Query parameter accepted by the /permissions/me, /menus/me, /roles/me
// endpoints to scope the lookup to a particular APP.
const QueryClientID = "client_id"

// Response keys for the permission endpoints.
const (
	KeyPermissions = "permissions"
	KeyRoles       = "roles"
	KeyMenus       = "menus"
	KeyClient      = "client_id"
)

// Error codes for the permission endpoints.
const (
	ErrPermissionProviderNotConfigured = "permission_provider_not_configured"
	ErrPermissionLookupFailed          = "permission_lookup_failed"
)

// authenticatedSubject resolves the bearer token to a user ID + client ID.
// client_id resolution: explicit query param > token audience > "".
func (s *Server) authenticatedSubject(ctx HandlerContext) (userID, clientID string, ok bool) {
	tokenString := bearerToken(ctx.Request())
	if tokenString == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return "", "", false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return "", "", false
	}
	clientID = ctx.Query(QueryClientID)
	if clientID == "" && len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}
	return claims.Subject, clientID, true
}

func (s *Server) handleMyPermissions(ctx HandlerContext) {
	userID, clientID, ok := s.authenticatedSubject(ctx)
	if !ok {
		return
	}
	if s.permissions == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrPermissionProviderNotConfigured))
		return
	}
	perms, err := s.permissions.Permissions(ctx.Request().Context(), userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("permissions lookup failed", "user", userID, "client", clientID, "error", err)
		s.recordPermissionQuery(ctx, userID, clientID, KeyPermissions, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrPermissionLookupFailed))
		return
	}
	if perms == nil {
		perms = []permissions.Permission{}
	}
	s.recordPermissionQuery(ctx, userID, clientID, KeyPermissions, true)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyClient:      clientID,
		KeyPermissions: perms,
	})
}

func (s *Server) handleMyRoles(ctx HandlerContext) {
	userID, clientID, ok := s.authenticatedSubject(ctx)
	if !ok {
		return
	}
	if s.permissions == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrPermissionProviderNotConfigured))
		return
	}
	roles, err := s.permissions.Roles(ctx.Request().Context(), userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("roles lookup failed", "user", userID, "client", clientID, "error", err)
		s.recordPermissionQuery(ctx, userID, clientID, KeyRoles, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrPermissionLookupFailed))
		return
	}
	if roles == nil {
		roles = []permissions.Role{}
	}
	s.recordPermissionQuery(ctx, userID, clientID, KeyRoles, true)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyClient: clientID,
		KeyRoles:  roles,
	})
}

func (s *Server) handleMyMenus(ctx HandlerContext) {
	userID, clientID, ok := s.authenticatedSubject(ctx)
	if !ok {
		return
	}
	if s.permissions == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrPermissionProviderNotConfigured))
		return
	}
	menus, err := s.permissions.Menus(ctx.Request().Context(), userID, clientID)
	if err != nil {
		s.logger.Error("menus lookup failed", "user", userID, "client", clientID, "error", err)
		s.recordPermissionQuery(ctx, userID, clientID, KeyMenus, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrPermissionLookupFailed))
		return
	}
	if menus == nil {
		menus = permissions.MenuTree{}
	}
	s.recordPermissionQuery(ctx, userID, clientID, KeyMenus, true)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyClient: clientID,
		KeyMenus:  menus,
	})
}

// resolvePermissionsForLogin pulls the bundle that gets embedded in a login
// response. Errors are swallowed and turned into empty slices so login never
// fails due to a permission lookup hiccup.
func (s *Server) resolvePermissionsForLogin(ctx context.Context, userID, clientID string) (
	[]permissions.Role, []permissions.Permission, permissions.MenuTree,
) {
	if s.permissions == nil {
		return nil, nil, nil
	}
	roles, err := s.permissions.Roles(ctx, userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("login embed: roles", "error", err)
	}
	perms, err := s.permissions.Permissions(ctx, userID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		s.logger.Error("login embed: permissions", "error", err)
	}
	menus, err := s.permissions.Menus(ctx, userID, clientID)
	if err != nil {
		s.logger.Error("login embed: menus", "error", err)
	}
	return roles, perms, menus
}

func (s *Server) recordPermissionQuery(ctx HandlerContext, userID, clientID, kind string, ok bool) {
	if s.auditor == nil {
		return
	}
	e := auditEventFromRequest(ctx)
	e.Type = audit.EventPermissionQuery
	e.ActorID = userID
	e.ClientID = clientID
	if ok {
		e.Outcome = audit.OutcomeSuccess
	} else {
		e.Outcome = audit.OutcomeFailure
	}
	setMeta(e, "kind", kind)
	s.auditor.Record(ctx.Request().Context(), e)
}

// Response keys for netpolicy endpoints.
const (
	KeyNetPolicies = "policies"
	KeyNetClass    = "class"
	KeyNetPolicy   = "policy"
)

// JSON payload for POST /api/v1/netpolicy/policies. Mirrors the netpolicy.Policy
// fields callers are allowed to set — Version and UpdatedAt are server-stamped.
type netPolicyPayload struct {
	Name                string            `json:"name"`
	CIDRs               []string          `json:"cidrs,omitempty"`
	Hostnames           []string          `json:"hostnames,omitempty"`
	Priority            int32             `json:"priority,omitempty"`
	AdvertisedBaseURL   string            `json:"advertised_base_url,omitempty"`
	AdvertisedJWKSURL   string            `json:"advertised_jwks_url,omitempty"`
	AdvertisedLogoutURL string            `json:"advertised_logout_url,omitempty"`
	Metadata            map[string]string `json:"metadata,omitempty"`
}

func (p *netPolicyPayload) toPolicy() *netpolicy.Policy {
	return &netpolicy.Policy{
		Name:                p.Name,
		CIDRs:               p.CIDRs,
		Hostnames:           p.Hostnames,
		Priority:            p.Priority,
		AdvertisedBaseURL:   p.AdvertisedBaseURL,
		AdvertisedJWKSURL:   p.AdvertisedJWKSURL,
		AdvertisedLogoutURL: p.AdvertisedLogoutURL,
		Metadata:            p.Metadata,
	}
}

func (s *Server) handleListNetPolicies(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	policies, err := s.netStore.List(ctx.Request().Context())
	if err != nil {
		s.logger.Error("netpolicy list", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetPolicies: policies})
}

func (s *Server) handleGetNetPolicy(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	name := ctx.Param("name")
	if name == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	p, err := s.netStore.Get(ctx.Request().Context(), name)
	if errors.Is(err, netpolicy.ErrNotFound) {
		ctx.JSON(http.StatusNotFound, errorBody(ErrNetPolicyNotFound))
		return
	}
	if err != nil {
		s.logger.Error("netpolicy get", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetPolicy: p})
}

func (s *Server) handleApplyNetPolicy(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	var payload netPolicyPayload
	if err := ctx.Bind(&payload); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBodyWithDescription(ErrInvalidRequest, err.Error()))
		return
	}
	if payload.Name == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	stored, err := s.netStore.Apply(ctx.Request().Context(), payload.toPolicy())
	if err != nil {
		s.logger.Error("netpolicy apply", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordNetPolicyMutation(ctx, audit.EventNetPolicyApply, stored.Name)
	ctx.JSON(http.StatusOK, map[string]any{KeyNetPolicy: stored})
}

func (s *Server) handleDeleteNetPolicy(ctx HandlerContext) {
	if s.netStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	name := ctx.Param("name")
	if name == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if err := s.netStore.Delete(ctx.Request().Context(), name); err != nil {
		s.logger.Error("netpolicy delete", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordNetPolicyMutation(ctx, audit.EventNetPolicyDelete, name)
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusOK})
}

func (s *Server) handleClassifyNetPolicy(ctx HandlerContext) {
	if s.netClassifier == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	remoteAddr := ctx.Query("remote_addr")
	host := ctx.Query("host")
	p := s.netClassifier.Classify(remoteAddr, host)
	if p == nil {
		ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: ""})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: p.Name, KeyNetPolicy: p})
}

// handleResolveMeNetPolicy classifies the CURRENT request and returns the
// matched policy. Convenience endpoint for clients that want to discover
// "which JWKS URL / callback URL should I use" without re-implementing the
// classification.
func (s *Server) handleResolveMeNetPolicy(ctx HandlerContext) {
	if s.netClassifier == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrNetPolicyNotConfigured))
		return
	}
	r := ctx.Request()
	remoteAddr := r.RemoteAddr
	host := r.Host
	p := s.netClassifier.Classify(remoteAddr, host)
	if p == nil {
		ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: ""})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyNetClass: p.Name, KeyNetPolicy: p})
}

// ClassifyRequest is exposed for embedders that want to classify a request
// in their own middleware. Returns nil when no classifier is wired or no
// policy matches.
func (s *Server) ClassifyRequest(r *http.Request) *netpolicy.Policy {
	if s.netClassifier == nil || r == nil {
		return nil
	}
	return s.netClassifier.Classify(r.RemoteAddr, r.Host)
}

func (s *Server) recordNetPolicyMutation(ctx HandlerContext, t audit.EventType, name string) {
	if s.auditor == nil {
		return
	}
	r := ctx.Request()
	s.auditor.Record(reqContext(r), &audit.Event{
		Type:      t,
		Outcome:   audit.OutcomeSuccess,
		Timestamp: time.Now().UTC(),
		ActorIP:   r.RemoteAddr,
		UserAgent: r.UserAgent(),
		Reason:    "name=" + name,
	})
}

// reqContext returns r.Context() but never nil — defensive against rare
// stdlib edge cases (custom transports etc.).
func reqContext(r *http.Request) context.Context {
	if r == nil {
		return context.Background()
	}
	if ctx := r.Context(); ctx != nil {
		return ctx
	}
	return context.Background()
}

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
// oauth.ErrRefreshTokenReused — a security signal worth routing to alerting.
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
