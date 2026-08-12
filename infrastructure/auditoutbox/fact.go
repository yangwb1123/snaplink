// Package auditoutbox is the IdP-side B4-5 governance connector: it
// turns a narrow, permitted class of audit events into durable outbox
// facts that the existing auditgovernance relay machinery drains.
//
// The gate is FAIL-CLOSED at the source: only login_failure events that
// are tenant-scoped may enter the governance outbox (the "login-failure
// post-commit is the only permitted class" contract). Every other class
// is rejected outright, so a future caller cannot silently widen the
// governance surface. The fact payload is a bounded, REDACTED projection
// — the Err* reason code plus the audit_hash that links the fact to its
// single chain event — never credentials, PII, or request input such as
// the raw provider string (bounded-cardinality discipline, see
// interfaces/sso boundLoginProvider).
//
// Two durable-store shapes are provided, mirroring the commerce outbox
// pattern: [SQLiteOutboxStore] (self-owned audit_outbox DDL in the SAME
// sqlite file as the audit chain, written in the audit row's own
// transaction via platform/audit/sqlite.WithTxAppender) and
// [MemoryOutboxStore] plus a fail-open [MemorySink] wrapper for the
// in-process path. Both implement domains/tenant/commerce.OutboxStore,
// so infrastructure/auditgovernance.NewRelay drains them unchanged.
package auditoutbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/audit/auditspi"
)

// Fact event type, following the dotted naming convention of the
// commerce event vocabulary (snaplink.<domain>.<class>).
const (
	FactEventType commerce.EventType = "snaplink.audit.login_failure"

	// factAggregateType is the outbox aggregate namespace for audit facts.
	factAggregateType = "audit"
	// factAggregateVersion is the immutable projection version of every
	// audit fact (a fact is a point-in-time projection, never re-versioned).
	factAggregateVersion = uint64(1)
)

// Payload keys of the redacted fact projection. audit_hash is the
// linkage: it equals the Hash of the single audit chain event the fact
// was derived from, so a recipient can verify the fact against the
// exported chain. reason is the closed Err* vocabulary recorded on the
// event (never free-form request input).
const (
	PayloadKeyAuditHash = "audit_hash"
	PayloadKeyReason    = "reason"
)

var (
	// ErrClassNotPermitted rejects any audit event that is not a
	// login_failure — the fail-closed single-permitted-class gate.
	ErrClassNotPermitted = errors.New("auditoutbox: event class not permitted (login_failure is the only governance fact class)")
	// ErrFactNotTenantScoped rejects a login_failure without a tenant:
	// governance facts must be attributable to exactly one tenant.
	ErrFactNotTenantScoped = errors.New("auditoutbox: login-failure fact requires a tenant-scoped audit event")
)

// FactFromAudit projects a permitted audit event into a governance
// outbox fact. It is the single conversion gate: nil, non-login-failure,
// or tenant-less events are rejected with the errors above, so the
// outbox can never be widened by accident. The fact's ID and
// idempotency key are the audit event's own ID, making re-append
// idempotent and giving the relay a stable dedupe identity. The payload
// carries the chain hash for linkage and the bounded reason code only.
func FactFromAudit(e *audit.Event) (*commerce.OutboxEvent, error) {
	if e == nil || e.Type != auditspi.EventLoginFailure {
		return nil, ErrClassNotPermitted
	}
	if e.TenantID == "" {
		return nil, ErrFactNotTenantScoped
	}
	payload := map[string]string{
		PayloadKeyAuditHash: e.Hash,
		PayloadKeyReason:    e.Reason,
	}
	return &commerce.OutboxEvent{
		ID:               e.ID,
		TenantID:         e.TenantID,
		Type:             FactEventType,
		AggregateType:    factAggregateType,
		AggregateID:      e.ID,
		AggregateVersion: factAggregateVersion,
		IdempotencyKey:   e.ID,
		OccurredAt:       e.Timestamp,
		Payload:          payload,
		PayloadDigest:    digestPayload(payload),
		Status:           commerce.OutboxPending,
		CreatedAt:        e.Timestamp,
	}, nil
}

// digestPayload mirrors commerce's own digest (json.Marshal sorts map
// keys, so the digest is canonical for identical payloads).
func digestPayload(payload map[string]string) string {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
