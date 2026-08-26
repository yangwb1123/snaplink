package audit

import (
	"context"
	"net/http"
	"time"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/platform/tracing"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// tracer is the package-level helper for parsing W3C traceparent headers
// into TraceID/SpanID for stamping on Event records. Stateless — safe
// at package scope.
var tracer = NewTracer()

// metaKeyRegionServing is the Event.Metadata key for the serving region —
// WHICH regional deployment handled the request. Deliberately a DIFFERENT
// namespace from geo.region (the geo.* keys above describe WHERE THE CLIENT
// IS, an ISO 3166-2 subdivision derived from the client IP); conflating them
// would let a client-IP geo hint masquerade as a serving-region governance
// signal. Lives here beside the geo.* metadata-key literals it parallels.
const metaKeyRegionServing = "region.serving"

// EventFromRequest builds an audit.Event pre-populated with HTTP +
// transport metadata pulled from ctx: RequestID, TraceID/SpanID/
// ParentSpanID (span-first, Decision 8 of
// docs/design/middleware-observability-unified.md), ActorIP, UserAgent,
// tenant.* metadata (when tenant middleware ran), and geo.* metadata
// (when the geo middleware is wired). Handlers fill the rest.
//
// The OTel span is the single source of truth for trace correlation: a
// live request span (real provider) wins over headers, even hostile ones.
// Header parsing remains only as a fallback for callers outside the
// middleware chain (embedded SDK users who propagate manually). Without
// the Correlation middleware installed, RequestID stays empty; without a
// real provider, TraceID/SpanID/ParentSpanID stay empty. GeoMiddleware
// similarly populates the geo metadata keys; without it, no geo.*
// metadata appears.
func EventFromRequest(ctx core.HandlerContext) *Event {
	e := eventFromHTTPRequest(ctx.Request())
	EnrichTenant(ctx, e)
	EnrichGeo(ctx, e)
	EnrichRegion(ctx, e)
	return e
}

// EventFromGRPCContext builds an audit event from transport-safe gRPC
// correlation data. It never mints IDs and never treats metadata as a peer IP.
func EventFromGRPCContext(ctx context.Context, typ EventType, outcome Outcome, reason string) *Event {
	e := &Event{Type: typ, Outcome: outcome, Reason: reason, Timestamp: time.Now()}
	if p, ok := peer.FromContext(ctx); ok && p != nil && p.Addr != nil {
		e.ActorIP = p.Addr.String()
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if values := md.Get(core.HeaderRequestID); len(values) > 0 {
			e.RequestID = values[0]
		}
		if values := md.Get(core.HeaderTraceparent); len(values) > 0 {
			if tc, err := NewTracer().ParseTraceparent(values[0]); err == nil {
				e.TraceID = tc.TraceID
				e.SpanID = tc.SpanID
			}
		}
	}
	return e
}

func eventFromHTTPRequest(r *http.Request) *Event {
	e := &Event{
		RequestID: r.Header.Get(core.HeaderRequestID),
		ActorIP:   ClientIP(r),
		UserAgent: r.Header.Get("User-Agent"),
	}
	// Span first: ParentSpanID comes from the span's ACTUAL parent (the
	// real span tree), not the legacy X-Parent-Span-Id header the deleted
	// Tracing middleware reconstructed. tracing.ParentSpanID is the seam
	// because otel's public Span interface exposes no Parent() (drift
	// ruling vs the design's sample code, which called span.Parent()).
	if sc := trace.SpanFromContext(r.Context()).SpanContext(); sc.IsValid() && sc.HasTraceID() {
		e.TraceID = sc.TraceID().String()
		e.SpanID = sc.SpanID().String()
		e.ParentSpanID = tracing.ParentSpanID(r.Context())
	} else if tp := r.Header.Get(core.HeaderTraceparent); tp != "" {
		if tc, err := tracer.ParseTraceparent(tp); err == nil {
			e.TraceID = tc.TraceID
			e.SpanID = tc.SpanID
		}
	}
	return e
}

// EnrichTenant lifts tenant routing results onto Event.TenantID (first-
// class, indexed) and Event.Metadata under the tenant.* prefix. No-op
// when the tenant middleware didn't run (no store wired, unknown host,
// suspended tenant). TenantID is the efficient per-tenant query field;
// the metadata keys carry the slug + domain for human-readable context.
func EnrichTenant(ctx core.HandlerContext, e *Event) {
	r, ok := tenant.FromHandlerContext(ctx)
	if !ok || r.Tenant == nil {
		return
	}
	e.TenantID = r.Tenant.ID
	SetMeta(e, "tenant.id", r.Tenant.ID)
	SetMeta(e, "tenant.slug", r.Tenant.Slug)
	if r.Domain != nil {
		SetMeta(e, "tenant.domain", r.Domain.Hostname)
	}
}

// EnrichGeo lifts geo lookup results from HandlerContext onto
// Event.Metadata under the geo.* prefix. No-op when the geo
// middleware didn't run (no Lookup, ErrNotFound, nil Provider).
// Only non-empty fields are projected so audit consumers can do a
// presence check rather than a value check.
func EnrichGeo(ctx core.HandlerContext, e *Event) {
	info, ok := geo.FromHandlerContext(ctx)
	if !ok {
		return
	}
	SetMeta(e, "geo.country_code", info.CountryCode)
	SetMeta(e, "geo.region", info.Region)
	SetMeta(e, "geo.city", info.City)
	SetMeta(e, "geo.recommended_language", info.RecommendedLanguage)
}

// EnrichRegion lifts the resolved serving-region ID from HandlerContext onto
// Event.Metadata under the region.serving key (NEVER geo.region — they are
// distinct namespaces, see metaKeyRegionServing). No-op when the region
// middleware didn't run or resolved no region (empty ID). SetMeta skips the
// empty value, so an unconstrained request adds no key — audit consumers do a
// presence check. SetMeta also guarantees this never clobbers the tenant.* /
// geo.* keys already stamped by EnrichTenant / EnrichGeo.
func EnrichRegion(ctx core.HandlerContext, e *Event) {
	id, ok := region.FromHandlerContext(ctx)
	if !ok {
		return
	}
	SetMeta(e, metaKeyRegionServing, string(id))
}

// SetMeta writes key=val into e.Metadata, lazily allocating the map
// and skipping empty values. Use this instead of `e.Metadata = map[...]{...}`
// — direct assignment would clobber whatever EventFromRequest already
// populated (geo enrichment, future fields).
func SetMeta(e *Event, key, val string) {
	if val == "" {
		return
	}
	if e.Metadata == nil {
		e.Metadata = make(map[string]string, 4)
	}
	e.Metadata[key] = val
}

// ClientIP extracts the apparent client IP using the standard
// precedence: X-Forwarded-For (first hop) → X-Real-IP → RemoteAddr
// (port stripped). Only trust forwarded headers behind a known edge.
// Delegates to the shared-kernel implementation (peertrust.ClientIP) so
// the audit event path and the access log share one byte-identical rule.
func ClientIP(r *http.Request) string { return peertrust.ClientIP(r) }
