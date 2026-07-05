package agentidentity

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
)

func newTestSession(t *testing.T, store AgentSessionStore, id, human string) {
	t.Helper()
	sess := &AgentSession{ID: id, HumanSubject: human, AgentID: "agent-1", ExpiresAt: time.Now().Add(time.Hour)}
	if err := store.Create(context.Background(), sess); err != nil {
		t.Fatalf("Create(%s): %v", id, err)
	}
}

func TestRevokeSession_AuditsAndRevokes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryAgentSessionStore()
	newTestSession(t, store, "sess-1", "alice")

	sink := audit.NewMemorySink(8)
	rec := audit.New(sink)

	if err := RevokeSession(ctx, store, rec, "sess-1"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	sess, err := store.Get(ctx, "sess-1")
	if err != nil || !sess.Revoked {
		t.Fatalf("session not revoked: %+v, %v", sess, err)
	}

	events, _ := sink.Query(ctx, audit.Query{})
	if len(events) != 1 {
		t.Fatalf("got %d audited events, want 1", len(events))
	}
	if events[0].Type != audit.EventAgentSessionRevoked {
		t.Fatalf("event type = %v, want EventAgentSessionRevoked", events[0].Type)
	}
	if events[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("outcome = %v, want success", events[0].Outcome)
	}
	if events[0].Metadata[MetaAgentSessionID] != "sess-1" {
		t.Fatalf("meta[agent_session_id] = %v, want sess-1", events[0].Metadata[MetaAgentSessionID])
	}
}

func TestRevokeSession_NilAuditorIsANoOp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryAgentSessionStore()
	newTestSession(t, store, "sess-1", "alice")

	if err := RevokeSession(ctx, store, nil, "sess-1"); err != nil {
		t.Fatalf("RevokeSession with nil auditor should still revoke: %v", err)
	}
	sess, _ := store.Get(ctx, "sess-1")
	if !sess.Revoked {
		t.Fatal("session must still be revoked even without an auditor wired")
	}
}

func TestRevokeAllForHuman_AuditsCohortCount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryAgentSessionStore()
	newTestSession(t, store, "s1", "alice")
	newTestSession(t, store, "s2", "alice")
	newTestSession(t, store, "s3", "bob")

	sink := audit.NewMemorySink(8)
	rec := audit.New(sink)

	n, err := RevokeAllForHuman(ctx, store, rec, "alice")
	if err != nil || n != 2 {
		t.Fatalf("RevokeAllForHuman = %d, %v; want 2, nil", n, err)
	}

	events, _ := sink.Query(ctx, audit.Query{})
	if len(events) != 1 {
		t.Fatalf("got %d audited events, want 1 (one cohort event, not per-session)", len(events))
	}
	if events[0].Metadata[MetaRevokedCount] != "2" {
		t.Fatalf("meta[revoked_count] = %v, want 2", events[0].Metadata[MetaRevokedCount])
	}

	if s3, _ := store.Get(ctx, "s3"); s3.Revoked {
		t.Fatal("bob's session must not be revoked by alice's cohort revoke")
	}
}
