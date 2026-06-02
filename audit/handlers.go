package audit

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/spi"
)

// Query parameter names for /api/v1/audit/events.
const (
	QueryType      = "type"
	QueryActorID   = "actor_id"
	QueryClientID  = "client_id"
	QueryProvider  = "provider"
	QueryOutcome   = "outcome"
	QueryRequestID = "request_id"
	QueryTraceID   = "trace_id"
	QuerySince     = "since"
	QueryUntil     = "until"
	QueryLimit     = "limit"
	QueryOffset    = "offset"
)

// Response keys for /api/v1/audit/events.
const (
	KeyEvents = "events"
	KeyCount  = "count"
)

// Response key for /api/v1/audit/facets.
const KeyFacets = "facets"

// Error codes for /api/v1/audit/events.
const (
	ErrNotEnabled        = "audit_not_enabled"
	ErrEventNotFoundCode = "audit_event_not_found"
)

// HandlerDeps is what the audit HTTP handlers need. *sso.Server
// satisfies via its accessor methods.
type HandlerDeps interface {
	Auditor() *Recorder
	SrvLogger() spi.Logger
}

// HandleEvents implements GET /api/v1/audit/events with optional
// query-string filters (type, actor_id, client_id, outcome, since,
// until, limit, offset). Requires admin scope.
func HandleEvents(d HandlerDeps, ctx core.HandlerContext) {
	rec := d.Auditor()
	if rec == nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: ErrNotEnabled})
		return
	}
	q, err := parseQuery(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: err.Error()})
		return
	}
	events, err := rec.Sink().Query(ctx.Request().Context(), q)
	if err != nil {
		d.SrvLogger().Error("audit query failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyEvents: events,
		KeyCount:  len(events),
	})
}

// HandleFacets implements GET /api/v1/audit/facets. It accepts the same
// filter query-string as HandleEvents (limit/offset are ignored — facets
// summarize the whole filtered window) and returns per-dimension candidate
// values + counts so a filter UI can render its options without an N+1
// round trip. Admin-gated like the rest of /api/v1/audit/*.
//
// The Sink must implement the optional FacetQuerier extension. A sink
// that doesn't (e.g. a write-only WebhookSink) yields HTTP 501 with the
// existing audit_not_enabled code so the UI falls back to plain queries
// rather than surfacing a hard error.
func HandleFacets(d HandlerDeps, ctx core.HandlerContext) {
	rec := d.Auditor()
	if rec == nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: ErrNotEnabled})
		return
	}
	fq, ok := rec.Sink().(FacetQuerier)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: ErrNotEnabled})
		return
	}
	q, err := parseQuery(ctx)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest, core.KeyErrorDescription: err.Error()})
		return
	}
	facets, err := fq.Facets(ctx.Request().Context(), q)
	if err != nil {
		// A wrapped sink that delegates may still report the capability
		// missing at call time (AsyncSink/MultiSink over a write-only leaf).
		if errors.Is(err, ErrFacetsUnsupported) {
			ctx.JSON(http.StatusNotImplemented, map[string]string{core.KeyError: ErrNotEnabled})
			return
		}
		d.SrvLogger().Error("audit facets failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyFacets: facets,
	})
}

// HandleEventByID implements GET /api/v1/audit/events/:id.
func HandleEventByID(d HandlerDeps, ctx core.HandlerContext) {
	rec := d.Auditor()
	if rec == nil {
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: ErrNotEnabled})
		return
	}
	id := ctx.Param("id")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, map[string]string{core.KeyError: core.ErrInvalidRequest})
		return
	}
	event, err := rec.Sink().Get(ctx.Request().Context(), id)
	if err != nil {
		if errors.Is(err, ErrEventNotFound) {
			ctx.JSON(http.StatusNotFound, map[string]string{core.KeyError: ErrEventNotFoundCode})
			return
		}
		d.SrvLogger().Error("audit get failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	ctx.JSON(http.StatusOK, event)
}

func parseQuery(ctx core.HandlerContext) (Query, error) {
	q := Query{
		Type:      EventType(ctx.Query(QueryType)),
		ActorID:   ctx.Query(QueryActorID),
		ClientID:  ctx.Query(QueryClientID),
		Provider:  ctx.Query(QueryProvider),
		Outcome:   Outcome(ctx.Query(QueryOutcome)),
		RequestID: ctx.Query(QueryRequestID),
		TraceID:   ctx.Query(QueryTraceID),
	}
	if v := ctx.Query(QuerySince); v != "" {
		t, err := parseTime(v)
		if err != nil {
			return q, err
		}
		q.Since = t
	}
	if v := ctx.Query(QueryUntil); v != "" {
		t, err := parseTime(v)
		if err != nil {
			return q, err
		}
		q.Until = t
	}
	if v := ctx.Query(QueryLimit); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return q, err
		}
		q.Limit = n
	}
	if v := ctx.Query(QueryOffset); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			return q, err
		}
		q.Offset = n
	}
	return q, nil
}

// parseTime accepts RFC3339 ("2006-01-02T15:04:05Z") and also Unix
// seconds for convenience from CLI testing.
func parseTime(v string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, nil
	}
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		return time.Unix(n, 0), nil
	}
	return time.Time{}, errors.New("expected RFC3339 timestamp or unix seconds")
}
