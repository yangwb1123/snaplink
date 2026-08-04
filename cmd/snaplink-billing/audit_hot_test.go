package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/lifecycle/modules"
)

func TestAuditModuleHotDesiredStateIsMonotonic(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-runtime.json")
	writeAuditDesiredFile(t, path, `{"revision":1,"enabled":true}`)
	factory := &countingLifecycleFactory{}
	module, err := newAuditModule(factory, path, modules.Options{
		DrainTimeout: time.Second, LifecycleTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer module.Close()
	if err := module.applyInitial(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertAuditModuleState(t, module, modules.StateActive, 1)

	writeAuditDesiredFile(t, path, "{\n  \"enabled\": true, \"revision\": 1\n}")
	module.reload(context.Background())
	assertAuditModuleState(t, module, modules.StateActive, 1)
	if factory.count() != 1 {
		t.Fatalf("same desired state prepared %d generations", factory.count())
	}

	writeAuditDesiredFile(t, path, `{"revision":1,"enabled":false}`)
	module.reload(context.Background())
	if err := module.Ready(context.Background()); !errors.Is(err, errAuditDesiredInvalid) {
		t.Fatalf("equivocation readiness error = %v", err)
	}
	assertAuditModuleState(t, module, modules.StateActive, 1)

	writeAuditDesiredFile(t, path, `{"revision":2,"enabled":false}`)
	module.reload(context.Background())
	if err := module.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertAuditModuleState(t, module, modules.StateInactive, 0)

	writeAuditDesiredFile(t, path, `{"revision":1,"enabled":true}`)
	module.reload(context.Background())
	if err := module.Ready(context.Background()); !errors.Is(err, errAuditDesiredInvalid) {
		t.Fatalf("rollback readiness error = %v", err)
	}
	writeAuditDesiredFile(t, path, `{"revision":3,"enabled":true}`)
	module.reload(context.Background())
	if err := module.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertAuditModuleState(t, module, modules.StateActive, 2)
}

func TestLoadAuditDesiredRejectsUnsafeOrAmbiguousFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit-runtime.json")
	writeAuditDesiredFile(t, path, `{"revision":1,"enabled":true,"secret":"no"}`)
	if _, _, err := loadAuditDesired(path); !errors.Is(err, errAuditDesiredInvalid) {
		t.Fatalf("unknown field error = %v", err)
	}
	writeAuditDesiredFile(t, path, `{"revision":1}`)
	if _, _, err := loadAuditDesired(path); !errors.Is(err, errAuditDesiredInvalid) {
		t.Fatalf("missing enabled error = %v", err)
	}
	writeAuditDesiredFile(t, path, `{"revision":1,"enabled":true}`)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadAuditDesired(path); !errors.Is(err, errAuditDesiredInvalid) {
		t.Fatalf("writable desired-state error = %v", err)
	}
}

func writeAuditDesiredFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertAuditModuleState(
	t *testing.T, module *auditModule, state modules.State, generation uint64,
) {
	t.Helper()
	statuses := module.manager.Status()
	if len(statuses) != 1 || statuses[0].State != state || statuses[0].Generation != generation {
		t.Fatalf("module status = %+v, want state=%s generation=%d", statuses, state, generation)
	}
}

type countingLifecycleFactory struct {
	mu       sync.Mutex
	prepares int
}

func (f *countingLifecycleFactory) Prepare(
	context.Context, modules.PrepareRequest,
) (modules.Instance, error) {
	f.mu.Lock()
	f.prepares++
	f.mu.Unlock()
	return noopLifecycleInstance{}, nil
}

func (f *countingLifecycleFactory) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.prepares
}

type noopLifecycleInstance struct{}

func (noopLifecycleInstance) Start(context.Context) error   { return nil }
func (noopLifecycleInstance) Ready(context.Context) error   { return nil }
func (noopLifecycleInstance) Quiesce(context.Context) error { return nil }
func (noopLifecycleInstance) Stop(context.Context) error    { return nil }
