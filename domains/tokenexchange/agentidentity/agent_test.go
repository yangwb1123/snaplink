package agentidentity

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryAgentProvider_ClonesAllowedScopes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := NewMemoryAgentProvider()
	scopes := []string{"tickets:read", "tickets:write"}
	agent := &Agent{ID: "agent-copy", DisplayName: "Copy Bot", AllowedScopes: scopes}
	if err := store.Register(ctx, agent); err != nil {
		t.Fatalf("Register: %v", err)
	}

	scopes[0] = "admin:write"
	got, err := store.Get(ctx, agent.ID)
	if err != nil {
		t.Fatalf("Get after input mutation: %v", err)
	}
	if got.AllowedScopes[0] != "tickets:read" {
		t.Fatalf("stored ceiling changed through Register input: %v", got.AllowedScopes)
	}

	got.AllowedScopes[1] = "admin:write"
	list, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List after Get mutation: %v", err)
	}
	if len(list) != 1 || list[0].AllowedScopes[1] != "tickets:write" {
		t.Fatalf("stored ceiling changed through Get result: %+v", list)
	}

	list[0].AllowedScopes[0] = "admin:write"
	again, err := store.Get(ctx, agent.ID)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	if again.AllowedScopes[0] != "tickets:read" {
		t.Fatalf("stored ceiling changed through List result: %v", again.AllowedScopes)
	}
}

func TestAgent_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		agent   Agent
		wantErr bool
	}{
		{"valid", Agent{ID: "agent-1", DisplayName: "Support Bot"}, false},
		{"missing id", Agent{DisplayName: "Support Bot"}, true},
		{"missing display name", Agent{ID: "agent-1"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.agent.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidAgent) {
				t.Fatalf("expected wrapped ErrInvalidAgent, got %v", err)
			}
		})
	}
}

func TestMemoryAgentProvider_RegisterGetList(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	m := NewMemoryAgentProvider()

	if _, err := m.Get(ctx, "unknown"); !errors.Is(err, ErrNoSuchAgent) {
		t.Fatalf("Get(unknown) = %v, want ErrNoSuchAgent", err)
	}

	agent := &Agent{ID: "agent-1", DisplayName: "Support Bot", AllowedScopes: []string{"tickets:read", "tickets:write"}}
	if err := m.Register(ctx, agent); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, err := m.Get(ctx, "agent-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DisplayName != "Support Bot" || len(got.AllowedScopes) != 2 {
		t.Fatalf("Get returned unexpected agent: %+v", got)
	}
	// Mutating the returned copy must not affect the store.
	got.DisplayName = "tampered"
	if again, _ := m.Get(ctx, "agent-1"); again.DisplayName != "Support Bot" {
		t.Fatalf("Get must return a defensive copy, store was mutated: %+v", again)
	}

	// Register again (upsert) replaces fields in place.
	if err := m.Register(ctx, &Agent{ID: "agent-1", DisplayName: "Renamed Bot"}); err != nil {
		t.Fatalf("re-Register: %v", err)
	}
	got, _ = m.Get(ctx, "agent-1")
	if got.DisplayName != "Renamed Bot" {
		t.Fatalf("upsert did not replace DisplayName: %+v", got)
	}

	if err := m.Register(ctx, &Agent{DisplayName: "no id"}); err == nil {
		t.Fatal("Register with invalid agent should fail")
	}

	list, err := m.List(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("List() = %v, %v; want 1 agent", list, err)
	}
}
