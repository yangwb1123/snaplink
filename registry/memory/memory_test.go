package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/registry"
	"github.com/snaplink/sso/registry/memory"
)

func newSvc(id, name string) *registry.Service {
	return &registry.Service{ID: id, Name: name, Address: "127.0.0.1", Port: 8000}
}

func TestRegister_RequiresIDAndName(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	if err := r.Register(context.Background(), &registry.Service{Name: "x"}); err == nil {
		t.Error("expected error for missing ID")
	}
	if err := r.Register(context.Background(), &registry.Service{ID: "x"}); err == nil {
		t.Error("expected error for missing Name")
	}
	if err := r.Register(context.Background(), nil); err == nil {
		t.Error("expected error for nil service")
	}
}

func TestRegisterAndDiscover(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx := context.Background()
	if err := r.Register(ctx, newSvc("sso-1", "sso")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := r.Discover(ctx, "sso")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 1 || got[0].ID != "sso-1" {
		t.Fatalf("Discover = %+v", got)
	}
}

func TestDiscover_UnknownReturnsErrNotFound(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	_, err := r.Discover(context.Background(), "nope")
	if !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestDiscover_MultipleInstances(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx := context.Background()
	_ = r.Register(ctx, newSvc("sso-1", "sso"))
	_ = r.Register(ctx, newSvc("sso-2", "sso"))
	_ = r.Register(ctx, newSvc("other-1", "other"))
	got, _ := r.Discover(ctx, "sso")
	if len(got) != 2 {
		t.Fatalf("expected 2 sso instances, got %d", len(got))
	}
}

func TestDeregister(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx := context.Background()
	_ = r.Register(ctx, newSvc("sso-1", "sso"))
	if err := r.Deregister(ctx, "sso-1"); err != nil {
		t.Fatalf("Deregister: %v", err)
	}
	if _, err := r.Discover(ctx, "sso"); !errors.Is(err, registry.ErrNotFound) {
		t.Errorf("after deregister, Discover should be ErrNotFound; got %v", err)
	}
}

func TestDeregister_UnknownIsNoop(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	if err := r.Deregister(context.Background(), "ghost"); err != nil {
		t.Fatalf("Deregister unknown should not error; got %v", err)
	}
}

func TestRegister_UpdatesEmitUpdatedEvent(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx := context.Background()

	watch, _ := r.Watch(ctx, "sso")

	_ = r.Register(ctx, newSvc("sso-1", "sso")) // → Added
	_ = r.Register(ctx, newSvc("sso-1", "sso")) // → Updated (same ID)

	gotAdded := waitEvent(t, watch)
	gotUpdated := waitEvent(t, watch)
	if gotAdded.Type != registry.EventAdded {
		t.Errorf("first event = %s, want Added", gotAdded.Type)
	}
	if gotUpdated.Type != registry.EventUpdated {
		t.Errorf("second event = %s, want Updated", gotUpdated.Type)
	}
}

func TestWatch_DeliversAddedAndRemoved(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx := context.Background()
	watch, err := r.Watch(ctx, "sso")
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	_ = r.Register(ctx, newSvc("sso-1", "sso"))
	added := waitEvent(t, watch)
	if added.Type != registry.EventAdded || added.Service.ID != "sso-1" {
		t.Fatalf("added event mismatch: %+v", added)
	}

	_ = r.Deregister(ctx, "sso-1")
	removed := waitEvent(t, watch)
	if removed.Type != registry.EventRemoved || removed.Service.ID != "sso-1" {
		t.Fatalf("removed event mismatch: %+v", removed)
	}
}

func TestWatch_ClosedOnContextCancel(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := r.Watch(ctx, "sso")

	cancel()

	// Give the watcher goroutine a moment to close.
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel closed after context cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("watch channel did not close after context cancel")
	}
}

func TestClose_ClosesAllWatchers(t *testing.T) {
	r := memory.New()
	ch, _ := r.Watch(context.Background(), "sso")
	_ = r.Close()

	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("channel should be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("watch channel not closed after registry Close")
	}
}

func TestOperationsAfterClose(t *testing.T) {
	r := memory.New()
	_ = r.Close()

	if err := r.Register(context.Background(), newSvc("x", "y")); !errors.Is(err, memory.ErrClosed) {
		t.Errorf("Register: expected ErrClosed, got %v", err)
	}
	if err := r.Deregister(context.Background(), "x"); !errors.Is(err, memory.ErrClosed) {
		t.Errorf("Deregister: expected ErrClosed, got %v", err)
	}
	if _, err := r.Discover(context.Background(), "y"); !errors.Is(err, memory.ErrClosed) {
		t.Errorf("Discover: expected ErrClosed, got %v", err)
	}
	if _, err := r.Watch(context.Background(), "y"); !errors.Is(err, memory.ErrClosed) {
		t.Errorf("Watch: expected ErrClosed, got %v", err)
	}
}

func TestTTLExpiry(t *testing.T) {
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx := context.Background()

	svc := newSvc("sso-1", "sso")
	svc.TTL = 50 * time.Millisecond
	_ = r.Register(ctx, svc)

	// Immediately discoverable.
	if _, err := r.Discover(ctx, "sso"); err != nil {
		t.Fatalf("immediate Discover: %v", err)
	}

	// After enough time for the janitor (1s tick) to run, the entry is gone.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, err := r.Discover(ctx, "sso")
		if errors.Is(err, registry.ErrNotFound) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("TTL'd entry never expired")
}

func TestRegisterDeepCopiesInputs(t *testing.T) {
	// Mutating the supplied Service's Tags / Metadata after Register must
	// not bleed into the registry's snapshot.
	r := memory.New()
	defer func() { _ = r.Close() }()
	ctx := context.Background()

	svc := &registry.Service{
		ID: "x", Name: "y",
		Tags:     []string{"a"},
		Metadata: map[string]string{"k": "v"},
	}
	_ = r.Register(ctx, svc)
	svc.Tags[0] = "MUTATED"
	svc.Metadata["k"] = "MUTATED"

	got, _ := r.Discover(ctx, "y")
	if got[0].Tags[0] != "a" {
		t.Errorf("Tags should be insulated; got %v", got[0].Tags)
	}
	if got[0].Metadata["k"] != "v" {
		t.Errorf("Metadata should be insulated; got %v", got[0].Metadata)
	}
}

func TestServiceEndpoint(t *testing.T) {
	if (&registry.Service{Address: "1.2.3.4", Port: 80}).Endpoint() != "1.2.3.4:80" {
		t.Fail()
	}
	if (&registry.Service{Address: "host"}).Endpoint() != "host" {
		t.Fail()
	}
}

// waitEvent receives one event from ch with a short timeout to keep failures
// crisp instead of hanging the suite.
func waitEvent(t *testing.T, ch <-chan registry.Event) registry.Event {
	t.Helper()
	select {
	case e := <-ch:
		return e
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for registry event")
		return registry.Event{}
	}
}
