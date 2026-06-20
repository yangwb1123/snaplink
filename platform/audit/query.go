package audit

import "time"

// DefaultQueryLimit is applied when Query.Limit is zero or negative.
const DefaultQueryLimit = 100

// MaxQueryLimit caps Query.Limit to bound memory pressure on the API.
const MaxQueryLimit = 1000

// Query filters audit events. Empty fields are wildcards. Time bounds are
// inclusive for Since and exclusive for Until (matching standard half-open
// range semantics).
type Query struct {
	Type      EventType
	ActorID   string
	ClientID  string
	TenantID  string
	Provider  string
	Outcome   Outcome
	RequestID string
	TraceID   string
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

// Match reports whether e satisfies q. Sinks that store events in-memory may
// reuse this; backends with their own query language should translate Query
// directly.
func (q Query) Match(e *Event) bool {
	return q.matchEnums(e) && q.matchIdentifiers(e) && q.matchTimeRange(e)
}

// matchEnums checks the typed enum filters (Type and Outcome). Empty fields are
// wildcards.
func (q Query) matchEnums(e *Event) bool {
	if q.Type != "" && e.Type != q.Type {
		return false
	}
	if q.Outcome != "" && e.Outcome != q.Outcome {
		return false
	}
	return true
}

// matchIdentifiers checks the string identity filters. Empty fields are
// wildcards.
func (q Query) matchIdentifiers(e *Event) bool {
	if q.ActorID != "" && e.ActorID != q.ActorID {
		return false
	}
	if q.ClientID != "" && e.ClientID != q.ClientID {
		return false
	}
	if q.TenantID != "" && e.TenantID != q.TenantID {
		return false
	}
	if q.Provider != "" && e.Provider != q.Provider {
		return false
	}
	if q.RequestID != "" && e.RequestID != q.RequestID {
		return false
	}
	if q.TraceID != "" && e.TraceID != q.TraceID {
		return false
	}
	return true
}

// matchTimeRange checks the half-open time bounds: Since inclusive, Until
// exclusive. Zero bounds are wildcards.
func (q Query) matchTimeRange(e *Event) bool {
	if !q.Since.IsZero() && e.Timestamp.Before(q.Since) {
		return false
	}
	if !q.Until.IsZero() && !e.Timestamp.Before(q.Until) {
		return false
	}
	return true
}

// NormalizedLimit returns Limit clamped to (0, MaxQueryLimit], defaulting to
// DefaultQueryLimit when unset.
func (q Query) NormalizedLimit() int {
	if q.Limit <= 0 {
		return DefaultQueryLimit
	}
	if q.Limit > MaxQueryLimit {
		return MaxQueryLimit
	}
	return q.Limit
}
