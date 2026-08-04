package core

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestAuthHookRegistryOrdersAndMergesSupportedMutations(t *testing.T) {
	registry := NewAuthHookRegistry(nil)
	var order []string
	registerTestHook(t, registry, AuthHookFunc{
		At: PhasePostAuthenticate, Config: AuthHookConfig{Name: "later", Priority: 20, FailClosed: true},
		Run: func(_ context.Context, _ *HookInput) (*HookOutput, error) {
			order = append(order, "later")
			return &HookOutput{Attributes: map[string]string{"role": "admin"}}, nil
		},
	})
	registerTestHook(t, registry, AuthHookFunc{
		At: PhasePostAuthenticate, Config: AuthHookConfig{Name: "first", Priority: 10, FailClosed: true},
		Run: func(_ context.Context, _ *HookInput) (*HookOutput, error) {
			order = append(order, "first")
			return &HookOutput{SkipMFA: true}, nil
		},
	})

	output, err := registry.Execute(context.Background(), &HookInput{Phase: PhasePostAuthenticate})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"first", "later"}) {
		t.Fatalf("execution order = %v", order)
	}
	if !output.SkipMFA || output.Attributes["role"] != "admin" {
		t.Fatalf("merged output = %#v", output)
	}
}

func TestAuthHookRegistryFailureModesAndObserver(t *testing.T) {
	var executions []AuthHookExecution
	registry := NewAuthHookRegistry(func(_ context.Context, execution AuthHookExecution) {
		executions = append(executions, execution)
	})
	failure := errors.New("secret provider detail")
	registerTestHook(t, registry, AuthHookFunc{
		At: PhasePreAuthenticate, Config: AuthHookConfig{Name: "open", Priority: 1},
		Run: func(context.Context, *HookInput) (*HookOutput, error) { return nil, failure },
	})
	registerTestHook(t, registry, AuthHookFunc{
		At: PhasePreAuthenticate, Config: AuthHookConfig{Name: "closed", Priority: 2, FailClosed: true},
		Run: func(context.Context, *HookInput) (*HookOutput, error) { return nil, failure },
	})

	_, err := registry.Execute(context.Background(), &HookInput{Phase: PhasePreAuthenticate})
	status, code, ok := AuthHookHTTPError(err)
	if !ok || status != http.StatusForbidden || code != ErrAuthHookRejected {
		t.Fatalf("wire error = (%d, %q, %v), err=%v", status, code, ok, err)
	}
	if len(executions) != 2 || !executions[0].Continued || executions[1].Continued {
		t.Fatalf("executions = %#v", executions)
	}
}

func TestAuthHookRegistryTimeoutAndNotificationAlwaysFailOpen(t *testing.T) {
	registry := NewAuthHookRegistry(nil)
	blocking := func(ctx context.Context, _ *HookInput) (*HookOutput, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	registerTestHook(t, registry, AuthHookFunc{
		At:     PhasePreTokenIssuance,
		Config: AuthHookConfig{Name: "timeout", FailClosed: true, Timeout: time.Millisecond}, Run: blocking,
	})
	_, err := registry.Execute(context.Background(), &HookInput{Phase: PhasePreTokenIssuance})
	status, code, ok := AuthHookHTTPError(err)
	if !ok || status != http.StatusServiceUnavailable || code != ErrAuthHookTimeout {
		t.Fatalf("timeout = (%d, %q, %v), err=%v", status, code, ok, err)
	}

	notifications := NewAuthHookRegistry(nil)
	registerTestHook(t, notifications, AuthHookFunc{
		At:     PhaseOnLoginFailed,
		Config: AuthHookConfig{Name: "notification", FailClosed: true},
		Run:    func(context.Context, *HookInput) (*HookOutput, error) { return nil, failureSentinel{} },
	})
	if _, err := notifications.Execute(context.Background(), &HookInput{Phase: PhaseOnLoginFailed}); err != nil {
		t.Fatalf("notification phase failed closed: %v", err)
	}
}

func TestAuthHookRegistryDeepCopiesInputsAndRejectsWrongMutation(t *testing.T) {
	registry := NewAuthHookRegistry(nil)
	registerTestHook(t, registry, AuthHookFunc{
		At: PhasePreTokenIssuance, Config: AuthHookConfig{Name: "mutator", FailClosed: true},
		Run: func(_ context.Context, input *HookInput) (*HookOutput, error) {
			input.Claims["unsafe"] = "mutation"
			input.Scopes[0] = "changed"
			return &HookOutput{Claims: map[string]string{"safe": "output"}}, nil
		},
	})
	input := &HookInput{Phase: PhasePreTokenIssuance, Claims: map[string]string{"base": "value"}, Scopes: []string{"read"}}
	output, err := registry.Execute(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if input.Claims["unsafe"] != "" || input.Scopes[0] != "read" || output.Claims["safe"] != "output" {
		t.Fatalf("input=%#v output=%#v", input, output)
	}

	invalid := NewAuthHookRegistry(nil)
	registerTestHook(t, invalid, AuthHookFunc{
		At: PhasePreAuthenticate, Config: AuthHookConfig{Name: "wrong", FailClosed: true},
		Run: func(context.Context, *HookInput) (*HookOutput, error) {
			return &HookOutput{Claims: map[string]string{"x": "y"}}, nil
		},
	})
	if _, err := invalid.Execute(context.Background(), &HookInput{Phase: PhasePreAuthenticate}); err == nil {
		t.Fatal("expected incompatible mutation to fail closed")
	}
}

func TestAuthHookRegistryRejectsDuplicateAndInvalidPhase(t *testing.T) {
	registry := NewAuthHookRegistry(nil)
	hook := AuthHookFunc{At: PhasePreAuthenticate, Config: AuthHookConfig{Name: "same"}, Run: noOpHook}
	registerTestHook(t, registry, hook)
	if err := registry.Register(hook); err == nil {
		t.Fatal("expected duplicate registration error")
	}
	if err := registry.Register(AuthHookFunc{At: "unknown", Run: noOpHook}); err == nil {
		t.Fatal("expected invalid phase error")
	}
}

type failureSentinel struct{}

func (failureSentinel) Error() string { return "failed" }

func noOpHook(context.Context, *HookInput) (*HookOutput, error) { return nil, nil }

func registerTestHook(t *testing.T, registry *AuthHookRegistry, hook AuthHook) {
	t.Helper()
	if err := registry.Register(hook); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkAuthPipelineZeroHooks(b *testing.B) {
	var registry *AuthHookRegistry
	b.ReportAllocs()
	for b.Loop() {
		if registry != nil && registry.Has(PhasePreAuthenticate) {
			b.Fatal("nil registry reported a hook")
		}
	}
}
