// Package audit provides tamper-evident audit logging with hash-chain
// verification. Events are recorded via a Recorder which feeds one or
// more Sinks (memory ring buffer, SQLite, webhook).
package auditspi

import "time"

// Outcome distinguishes successful events from attempted/failed ones.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
)

// Event is a single immutable audit record. ID is assigned by the Sink on
// Record; callers leave it empty.
//
// Sensitive fields (raw token bodies, password material) MUST NOT be put on
// an Event. Use TokenID for a hash/prefix that's safe to store.
type Event struct {
	ID           string    `json:"id"`
	Type         EventType `json:"type"`
	Outcome      Outcome   `json:"outcome"`
	Timestamp    time.Time `json:"timestamp"`
	RequestID    string    `json:"request_id,omitempty"`
	TraceID      string    `json:"trace_id,omitempty"`
	SpanID       string    `json:"span_id,omitempty"`
	ParentSpanID string    `json:"parent_span_id,omitempty"`
	ActorID      string    `json:"actor_id,omitempty"`
	ActorIP      string    `json:"actor_ip,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	ClientID     string    `json:"client_id,omitempty"`
	// TenantID is a first-class indexed field for per-tenant metering and
	// querying. Populated by EnrichTenant when the tenant middleware ran;
	// empty for requests outside a tenant context. Mirrors the "tenant.id"
	// Metadata key but promotes it out of the JSON blob so the SQLite sink
	// can index and aggregate efficiently without per-event JSON scanning.
	TenantID      string            `json:"tenant_id,omitempty"`
	Provider      string            `json:"provider,omitempty"`
	TokenStrategy string            `json:"token_strategy,omitempty"`
	SessionID     string            `json:"session_id,omitempty"`
	TokenID       string            `json:"token_id,omitempty"`
	Reason        string            `json:"reason,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`

	// PrevHash + Hash form a tamper-evident chain when a Recorder
	// is constructed with [WithHashChain]. PrevHash is the previous
	// event's Hash; Hash is sha256(canonical-JSON of this event with
	// Hash cleared). VerifyChain walks a sequence and reports any
	// break. Empty for both = chain disabled.
	PrevHash string `json:"prev_hash,omitempty"`
	Hash     string `json:"hash,omitempty"`

	// ServerVersion is the deploying software version, resolved at
	// Recorder construction via the [WithServerVersion] option.
	// Stamped onto every event so operators correlating audit trails
	// across a rolling deployment can tell which binary version
	// produced each record. Empty when the option is not wired.
	ServerVersion string `json:"server_version,omitempty"`
}
