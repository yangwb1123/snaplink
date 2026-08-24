package webhook

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
)

func TestManagedRuntimeActivatesAndReplacesGenerations(t *testing.T) {
	subs := NewMemorySubscriptionStore()
	dlq := NewMemoryDeadLetterStore(8)
	prepares := 0
	runtime, err := NewManagedRuntime(func(context.Context, []byte, uint64) (*Engine, error) {
		prepares++
		return NewEngine(subs, dlq), nil
	}, []byte(`{"revision":1}`), modules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagedRuntime(t, runtime)
	if prepares != 1 {
		t.Fatalf("initial prepares = %d, want 1", prepares)
	}
	assertManagedGeneration(t, runtime, 1)

	created, err := runtime.Subscriptions().Create(context.Background(), EventSubscription{
		URL: "https://collector.example/events", EventTypes: []audit.EventType{audit.EventLogin}, Secret: "secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Activate(context.Background(), []byte(`{"revision":2}`)); err != nil {
		t.Fatal(err)
	}
	assertManagedGeneration(t, runtime, 2)
	if _, err := runtime.Subscriptions().Get(context.Background(), created.ID); err != nil {
		t.Fatalf("subscription lost across replacement: %v", err)
	}
	if prepares != 2 {
		t.Fatalf("replacement prepares = %d, want 2", prepares)
	}
}

func TestManagedRuntimeFailedReplacementKeepsActiveGeneration(t *testing.T) {
	var fail bool
	runtime, err := NewManagedRuntime(func(context.Context, []byte, uint64) (*Engine, error) {
		if fail {
			return nil, errors.New("candidate rejected")
		}
		return NewEngine(NewMemorySubscriptionStore(), NewMemoryDeadLetterStore(1)), nil
	}, nil, modules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeManagedRuntime(t, runtime)
	fail = true
	if err := runtime.Activate(context.Background(), []byte(`{"revision":2}`)); err == nil {
		t.Fatal("failed replacement returned nil")
	}
	assertManagedGeneration(t, runtime, 1)
	if err := runtime.Ready(context.Background()); err != nil {
		t.Fatalf("runtime lost readiness after failed replacement: %v", err)
	}
}

func TestManagedRuntimeDisableLeavesNoActiveGeneration(t *testing.T) {
	runtime, err := NewManagedRuntime(func(context.Context, []byte, uint64) (*Engine, error) {
		return NewEngine(NewMemorySubscriptionStore(), NewMemoryDeadLetterStore(1)), nil
	}, nil, modules.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := runtime.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if runtime.CurrentEngine() != nil {
		t.Fatal("disabled runtime still exposes a current engine")
	}
	if err := runtime.Ready(context.Background()); !errors.Is(err, modules.ErrModuleInactive) {
		t.Fatalf("disabled readiness error = %v", err)
	}
	closeManagedRuntime(t, runtime)
}

func assertManagedGeneration(t *testing.T, runtime *ManagedRuntime, want uint64) {
	t.Helper()
	statuses := runtime.Status()
	if len(statuses) != 1 || statuses[0].Generation != want || statuses[0].State != modules.StateActive {
		t.Fatalf("runtime status = %+v, want active generation %d", statuses, want)
	}
}

func closeManagedRuntime(t *testing.T, runtime *ManagedRuntime) {
	t.Helper()
	if err := runtime.Close(context.Background()); err != nil {
		t.Fatalf("runtime close: %v", err)
	}
}
