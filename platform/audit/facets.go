package audit

import "context"

// Facets holds per-dimension value counts for the events matching a
// [Query] (its Since/Until window plus every non-dimension filter). It
// is the key-path backend for an audit-explorer filter UI: instead of an
// N+1 round trip per candidate value, the UI renders "Outcome: success
// (1.2k) / failure (40)", "Client: web (900) / mobile (300)", etc. from
// one response.
//
// Dimensions are deliberately limited to the stable, bounded-ish facets a
// filter UI offers — Outcome (2 values), Type (a fixed event vocabulary),
// Client, and Provider (operator-configured, small sets). High-cardinality
// per-user / per-request fields (ActorID, TraceID, RequestID) are NOT
// faceted: their value space grows with traffic and would blow up the
// response, exactly the bounded-cardinality discipline the metrics layer
// follows. Filter on those via [Query] directly instead.
type Facets struct {
	// Total is the number of events that matched the query (the sum of
	// each dimension's counts, modulo events that leave a dimension
	// empty — empty values are not counted in that dimension's map).
	Total int `json:"total"`

	// Outcomes counts matching events by Outcome (success / failure).
	Outcomes map[Outcome]int `json:"outcomes"`

	// Types counts matching events by EventType.
	Types map[EventType]int `json:"types"`

	// Clients counts matching events by ClientID. Empty ClientID is
	// skipped (not a meaningful filter value).
	Clients map[string]int `json:"clients"`

	// Providers counts matching events by Provider. Empty Provider is
	// skipped.
	Providers map[string]int `json:"providers"`
}

// FacetQuerier is an OPTIONAL [Sink] extension: a Sink that can aggregate
// candidate filter values + counts implements it. Read paths type-assert
// the Sink to this interface (mirroring the cluster-shared Ping / Stats
// optional-interface pattern), so the write-only / fan-out Sinks
// (WebhookSink, WriterSink, MultiSink, RetryingSink) are NOT forced to
// implement it.
//
// Facets respects the Query's time range (Since/Until) and its
// non-dimension filters (Type/ActorID/ClientID/Provider/Outcome/...): the
// simplest correct v1 applies the full [Query.Match] predicate, then
// groups the survivors by each dimension. Limit/Offset are ignored —
// facets describe the whole filtered window, not a page of it.
type FacetQuerier interface {
	Facets(ctx context.Context, q Query) (*Facets, error)
}

// Sinks that expose facet aggregation. MemorySink computes it directly;
// AsyncSink + MultiSink delegate to a wrapped FacetQuerier (or report
// ErrFacetsUnsupported), keeping the capability optional and composable.
var (
	_ FacetQuerier = (*MemorySink)(nil)
	_ FacetQuerier = (*AsyncSink)(nil)
	_ FacetQuerier = (*MultiSink)(nil)
)

// newFacets returns a Facets with all dimension maps initialized so a
// zero-match query still serializes empty objects (not null) for the UI.
func newFacets() *Facets {
	return &Facets{
		Outcomes:  map[Outcome]int{},
		Types:     map[EventType]int{},
		Clients:   map[string]int{},
		Providers: map[string]int{},
	}
}

// add increments every dimension for a single matching event. Empty
// ClientID / Provider are skipped (not a filter value the UI offers).
func (f *Facets) add(e *Event) {
	f.Total++
	f.Outcomes[e.Outcome]++
	f.Types[e.Type]++
	if e.ClientID != "" {
		f.Clients[e.ClientID]++
	}
	if e.Provider != "" {
		f.Providers[e.Provider]++
	}
}
