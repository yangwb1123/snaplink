package auditoutbox

import (
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tenant/commerce"
	"github.com/yangwb1123/snaplink/platform/audit"
)

// loginFailure returns a valid, chain-stamped login-failure event (the
// fields FactFromAudit projects).
func loginFailure(id, tenantID string) *audit.Event {
	return &audit.Event{
		ID: id, Type: audit.EventLoginFailure, Outcome: audit.OutcomeFailure,
		Timestamp: time.Now().UTC(), TenantID: tenantID, ClientID: "client-1",
		Provider: "password", Reason: "invalid_credentials", Hash: "hash-" + id,
	}
}

// TestFactFromAudit_RejectsNonLoginFailure pins the single-permitted-
// class gate: no event class other than login_failure may enter the
// governance outbox.
func TestFactFromAudit_RejectsNonLoginFailure(t *testing.T) {
	cases := []struct {
		name string
		ev   *audit.Event
	}{
		{"nil", nil},
		{"login", &audit.Event{ID: "e", Type: audit.EventLogin, TenantID: "t"}},
		{"token_issued", &audit.Event{ID: "e", Type: audit.EventTokenIssued, TenantID: "t"}},
		{"token_revoked", &audit.Event{ID: "e", Type: audit.EventTokenRevoked, TenantID: "t"}},
		{"custom", &audit.Event{ID: "e", Type: "my.custom.event", TenantID: "t"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fact, err := FactFromAudit(tc.ev)
			if !errors.Is(err, ErrClassNotPermitted) {
				t.Fatalf("err = %v, want ErrClassNotPermitted", err)
			}
			if fact != nil {
				t.Fatalf("fact = %+v, want nil", fact)
			}
		})
	}
}

// TestFactFromAudit_RejectsTenantLess pins the tenant-scoped gate: a
// login failure that cannot be attributed to a tenant never becomes a
// governance fact.
func TestFactFromAudit_RejectsTenantLess(t *testing.T) {
	ev := loginFailure("e1", "")
	ev.Type = audit.EventLoginFailure
	fact, err := FactFromAudit(ev)
	if !errors.Is(err, ErrFactNotTenantScoped) {
		t.Fatalf("err = %v, want ErrFactNotTenantScoped", err)
	}
	if fact != nil {
		t.Fatalf("fact = %+v, want nil", fact)
	}
}

// TestFactFromAudit_ProjectsLinkedFact verifies the projection: the fact
// is tenant-scoped, redacted (reason + audit_hash ONLY — no provider,
// no IP, no request input), and its audit_hash equals the chain event's
// Hash — the linkage the relayed fact shares with the exported chain.
func TestFactFromAudit_ProjectsLinkedFact(t *testing.T) {
	ev := loginFailure("evt-42", "tenant-7")
	ev.Reason = "invalid_grant"
	fact, err := FactFromAudit(ev)
	if err != nil {
		t.Fatalf("FactFromAudit: %v", err)
	}
	if fact.ID != ev.ID || fact.TenantID != "tenant-7" {
		t.Errorf("identity: got id=%q tenant=%q", fact.ID, fact.TenantID)
	}
	if fact.Type != FactEventType {
		t.Errorf("type: got %q want %q", fact.Type, FactEventType)
	}
	if fact.IdempotencyKey != ev.ID {
		t.Errorf("idempotency key must be the audit event ID, got %q", fact.IdempotencyKey)
	}
	if fact.AggregateType != "audit" || fact.AggregateID != ev.ID {
		t.Errorf("aggregate: got (%q, %q)", fact.AggregateType, fact.AggregateID)
	}
	if fact.Payload[PayloadKeyAuditHash] != "hash-evt-42" {
		t.Errorf("audit_hash linkage: got %q", fact.Payload[PayloadKeyAuditHash])
	}
	if fact.Payload[PayloadKeyReason] != "invalid_grant" {
		t.Errorf("reason: got %q", fact.Payload[PayloadKeyReason])
	}
	if len(fact.Payload) != 2 {
		t.Errorf("payload not redacted to audit_hash+reason: %v", fact.Payload)
	}
	if fact.PayloadDigest == "" {
		t.Error("payload digest missing")
	}
	if fact.Status != commerce.OutboxPending {
		t.Errorf("status: got %q want pending", fact.Status)
	}
	if err := fact.Validate(); err != nil {
		t.Errorf("fact fails commerce validation: %v", err)
	}
}
