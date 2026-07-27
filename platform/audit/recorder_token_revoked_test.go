package audit_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
)

// TestRecordTokenRevoked_EmitsWithClaimsAndIssuers proves RecordTokenRevoked
// (the missing emission — see its doc comment for why EventTokenRevoked was
// previously a dead audit event that platform/lifecycle/webhook.Engine could
// never observe) stamps Type=token_revoked, Outcome=success, the caller-
// supplied ClientID/ActorID, and a comma-joined "issuers" metadata entry.
func TestRecordTokenRevoked_EmitsWithClaimsAndIssuers(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)

	audit.RecordTokenRevoked(rec, context.Background(), "client-1", "user-1", []string{"jwt", "session"})

	events, err := sink.Query(context.Background(), audit.Query{Limit: 16})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	e := events[0]
	if e.Type != audit.EventTokenRevoked {
		t.Errorf("Type = %q, want %q", e.Type, audit.EventTokenRevoked)
	}
	if e.Outcome != audit.OutcomeSuccess {
		t.Errorf("Outcome = %q, want %q", e.Outcome, audit.OutcomeSuccess)
	}
	if e.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want %q", e.ClientID, "client-1")
	}
	if e.ActorID != "user-1" {
		t.Errorf("ActorID = %q, want %q", e.ActorID, "user-1")
	}
	if got := e.Metadata["issuers"]; got != "jwt,session" {
		t.Errorf("Metadata[issuers] = %q, want %q", got, "jwt,session")
	}
}

// TestRecordTokenRevoked_EmptyIssuersOmitsMetadata proves an empty issuers
// slice (defensive: RecordTokenRevoked's only real caller only invokes it
// when len(revoked) > 0) never stamps an empty "issuers" key.
func TestRecordTokenRevoked_EmptyIssuersOmitsMetadata(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)

	audit.RecordTokenRevoked(rec, context.Background(), "client-1", "user-1", nil)

	events, err := sink.Query(context.Background(), audit.Query{Limit: 16})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("got %d events, want 1", len(events))
	}
	if _, ok := events[0].Metadata["issuers"]; ok {
		t.Errorf("Metadata[issuers] present with empty issuers: %+v", events[0].Metadata)
	}
}

// TestRecordTokenRevoked_NilRecorderIsSafeNoOp mirrors every other Record*
// helper's nil-safety contract so a caller never needs a conditional guard.
func TestRecordTokenRevoked_NilRecorderIsSafeNoOp(t *testing.T) {
	t.Parallel()
	var rec *audit.Recorder
	audit.RecordTokenRevoked(rec, context.Background(), "client-1", "user-1", []string{"jwt"})
}
