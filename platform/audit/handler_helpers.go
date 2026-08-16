package audit

import (
	"net/http"

	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/peertrust"
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
// ParentSpanID (when TracingMiddleware ran), ActorIP, UserAgent,
// tenant.* metadata (when tenant middleware ran), and geo.* metadata
// (when the geo middleware is wired). Handlers fill the rest.
//
// TracingMiddleware populates the headers this function reads;
// without that middleware installed, RequestID/TraceID/SpanID stay
// empty. GeoMiddleware similarly populates the geo metadata keys;
// without it, no geo.* metadata appears.
func EventFromRequest(ctx core.HandlerContext) *Event {
	r := ctx.Request()
	e := &Event{
		RequestID:    r.Header.Get(core.HeaderRequestID),
		ParentSpanID: r.Header.Get(core.HeaderParentSpanID),
		ActorIP:      ClientIP(r),
		UserAgent:    r.Header.Get("User-Agent"),
	}
	if tp := r.Header.Get(core.HeaderTraceparent); tp != "" {
		if tc, err := tracer.ParseTraceparent(tp); err == nil {
			e.TraceID = tc.TraceID
			e.SpanID = tc.SpanID
		}
	}
	EnrichTenant(ctx, e)
	EnrichGeo(ctx, e)
	EnrichRegion(ctx, e)
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
