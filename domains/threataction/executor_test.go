package threataction

import (
	"context"
	"errors"
	"testing"
)

func TestExecuteFuncAdapter(t *testing.T) {
	expectedErr := errors.New("threat handled")
	var executed bool

	fn := ExecuteFunc(func(ctx context.Context, threat Threat, policy ThreatPolicy) (ActionResult, error) {
		executed = true
		if threat.Type != "test-threat" {
			t.Errorf("expected threat type 'test-threat', got %q", threat.Type)
		}
		if policy.Action != "warn" {
			t.Errorf("expected policy action 'warn', got %q", policy.Action)
		}
		return ActionResult{}, expectedErr
	})

	if fn.Name() != "func" {
		t.Errorf("expected Name()='func', got %q", fn.Name())
	}

	result, err := fn.Execute(context.Background(), Threat{Type: "test-threat"}, ThreatPolicy{Action: "warn"})
	if !executed {
		t.Error("ExecuteFunc was not called")
	}
	if err != expectedErr {
		t.Errorf("expected error %v, got %v", expectedErr, err)
	}
	_ = result
}



func TestThreatExecutorInterface(t *testing.T) {
	// Compile-time check
	var _ ThreatExecutor = (*mockExecutor)(nil)
}

type mockExecutor struct{}

func (m *mockExecutor) Name() string { return "mock" }
func (m *mockExecutor) Execute(ctx context.Context, threat Threat, policy ThreatPolicy) (ActionResult, error) {
	return ActionResult{}, nil
}


