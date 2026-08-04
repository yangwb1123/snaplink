package modules

import (
	"context"
	"errors"
	"testing"
)

func TestManagerPinsDependencyGeneration(t *testing.T) {
	baseFactory := newFakeFactory()
	childFactory := newFakeFactory()
	manager := dependencyManager(t, baseFactory, childFactory)
	base := activateForTest(t, manager, "base", nil)
	child := activateForTest(t, manager, "child", nil)
	request := childFactory.requests[0]
	if request.Dependencies["base"] != baseFactory.instance(base.Generation) {
		t.Fatal("child did not receive the pinned base instance")
	}
	if _, err := manager.Disable("base"); !errors.Is(err, ErrDependentsActive) {
		t.Fatalf("Disable(base) error = %v", err)
	}
	if _, err := manager.Activate(context.Background(), "base", nil); !errors.Is(err, ErrDependentsActive) {
		t.Fatalf("Activate(base replacement) error = %v", err)
	}
	disableAndWait(t, manager, "child")
	if child.Generation == 0 {
		t.Fatal("child generation was not published")
	}
	disableAndWait(t, manager, "base")
}

func dependencyManager(t *testing.T, base, child Factory) *Manager {
	t.Helper()
	manager, err := New([]Definition{
		{ID: "base", Factory: base},
		{ID: "child", Dependencies: []string{"base"}, Factory: child},
	}, Options{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return manager
}

func disableAndWait(t *testing.T, manager *Manager, id string) {
	t.Helper()
	retirement, err := manager.Disable(id)
	if err != nil {
		t.Fatalf("Disable(%s) error = %v", id, err)
	}
	if err := retirement.Wait(context.Background()); err != nil {
		t.Fatalf("retire(%s) error = %v", id, err)
	}
}

func TestManagerRejectsInvalidCatalog(t *testing.T) {
	factory := newFakeFactory()
	cases := []struct {
		name        string
		definitions []Definition
		want        error
	}{
		{"invalid id", []Definition{{ID: "Bad_ID", Factory: factory}}, ErrDefinitionInvalid},
		{"duplicate", []Definition{{ID: "same", Factory: factory}, {ID: "same", Factory: factory}}, ErrDefinitionDuplicate},
		{"missing", []Definition{{ID: "child", Dependencies: []string{"missing"}, Factory: factory}}, ErrDependencyMissing},
		{"cycle", []Definition{{ID: "one", Dependencies: []string{"two"}, Factory: factory}, {ID: "two", Dependencies: []string{"one"}, Factory: factory}}, ErrDependencyCycle},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(test.definitions, Options{})
			if !errors.Is(err, test.want) {
				t.Fatalf("New() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestManagerCloseStopsDependentsBeforeDependencies(t *testing.T) {
	baseFactory := newFakeFactory()
	childFactory := newFakeFactory()
	manager := dependencyManager(t, baseFactory, childFactory)
	base := activateForTest(t, manager, "base", nil)
	child := activateForTest(t, manager, "child", nil)
	if err := manager.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !childFactory.instance(child.Generation).stopped.Load() || !baseFactory.instance(base.Generation).stopped.Load() {
		t.Fatal("Close() left a generation running")
	}
	if _, err := manager.Acquire("base", LeaseRequest); !errors.Is(err, ErrManagerClosed) {
		t.Fatalf("Acquire() after close error = %v", err)
	}
}
