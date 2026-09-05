package agentidentity

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"
)

func TestAgentSession_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		sess    AgentSession
		wantErr bool
	}{
		{"valid", AgentSession{ID: "sess-1", HumanSubject: "alice", AgentID: "agent-1"}, false},
		{"missing id", AgentSession{HumanSubject: "alice", AgentID: "agent-1"}, true},
		{"missing human subject", AgentSession{ID: "sess-1", AgentID: "agent-1"}, true},
		{"missing agent id", AgentSession{ID: "sess-1", HumanSubject: "alice"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.sess.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidSession) {
				t.Fatalf("expected wrapped ErrInvalidSession, got %v", err)
			}
		})
	}
}

func TestMemoryAgentSessionStore_CreateGetRevoke(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryAgentSessionStore()

	if _, err := m.Get(ctx, "unknown"); !errors.Is(err, ErrNoSuchSession) {
		t.Fatalf("Get(unknown) = %v, want ErrNoSuchSession", err)
	}

	sess := &AgentSession{
		ID:            "sess-1",
		HumanSubject:  "alice",
		AgentID:       "agent-1",
		GrantedScopes: []string{"tickets:read"},
		ExpiresAt:     time.Now().Add(time.Hour),
	}
	if err := m.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := m.Create(ctx, &AgentSession{HumanSubject: "alice", AgentID: "agent-1"}); err == nil {
		t.Fatal("Create with invalid session should fail")
	}

	got, err := m.Get(ctx, "sess-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Revoked {
		t.Fatal("freshly created session must not be revoked")
	}

	if err := m.Revoke(ctx, "sess-1"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	got, _ = m.Get(ctx, "sess-1")
	if !got.Revoked || got.RevokedAt.IsZero() {
		t.Fatalf("Revoke did not mark the session revoked: %+v", got)
	}

	// Idempotent: revoking again, or an unknown id, is a no-op success.
	if err := m.Revoke(ctx, "sess-1"); err != nil {
		t.Fatalf("re-Revoke should be idempotent, got %v", err)
	}
	if err := m.Revoke(ctx, "never-existed"); err != nil {
		t.Fatalf("Revoke of unknown id should be idempotent no-op, got %v", err)
	}
}

func TestMemoryAgentSessionStore_ClonesGrantedScopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryAgentSessionStore()
	scopes := []string{"tickets:read", "tickets:write"}
	sess := &AgentSession{
		ID: "sess-copy", HumanSubject: "alice", AgentID: "agent-1",
		GrantedScopes: scopes,
	}
	if err := store.Create(ctx, sess); err != nil {
		t.Fatalf("Create: %v", err)
	}

	scopes[0] = "admin:write"
	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get after input mutation: %v", err)
	}
	if got.GrantedScopes[0] != "tickets:read" {
		t.Fatalf("stored scopes changed through Create input: %v", got.GrantedScopes)
	}

	got.GrantedScopes[1] = "admin:write"
	again, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if want := []string{"tickets:read", "tickets:write"}; !slices.Equal(again.GrantedScopes, want) {
		t.Fatalf("stored scopes changed through Get result: %v, want %v", again.GrantedScopes, want)
	}
}

func TestMemoryAgentSessionStore_RevokeAllForHuman(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryAgentSessionStore()

	sessions := []*AgentSession{
		{ID: "s1", HumanSubject: "alice", AgentID: "agent-1"},
		{ID: "s2", HumanSubject: "alice", AgentID: "agent-2"},
		{ID: "s3", HumanSubject: "bob", AgentID: "agent-1"},
	}
	for _, s := range sessions {
		if err := m.Create(ctx, s); err != nil {
			t.Fatalf("Create(%s): %v", s.ID, err)
		}
	}

	n, err := m.RevokeAllForHuman(ctx, "alice")
	if err != nil {
		t.Fatalf("RevokeAllForHuman: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeAllForHuman(alice) count = %d, want 2", n)
	}

	if s1, _ := m.Get(ctx, "s1"); !s1.Revoked {
		t.Fatal("s1 should be revoked")
	}
	if s3, _ := m.Get(ctx, "s3"); s3.Revoked {
		t.Fatal("s3 (bob's session) must NOT be revoked by alice's cohort revoke")
	}

	// Re-running is idempotent and counts zero the second time.
	n, err = m.RevokeAllForHuman(ctx, "alice")
	if err != nil || n != 0 {
		t.Fatalf("second RevokeAllForHuman(alice) = %d, %v; want 0, nil", n, err)
	}
}
