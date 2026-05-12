package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/netpolicy/memory"
)

func TestStore_ApplyGetList(t *testing.T) {
	s := memory.New()
	defer s.Close()

	p := &netpolicy.Policy{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}}
	got, err := s.Apply(context.Background(), p)
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if got.Version == 0 || got.UpdatedAt.IsZero() {
		t.Errorf("Version/UpdatedAt not stamped: %+v", got)
	}
	if got.Name != "intranet" {
		t.Errorf("Name = %q", got.Name)
	}

	loaded, err := s.Get(context.Background(), "intranet")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if loaded.Version != got.Version {
		t.Errorf("loaded.Version=%d, got.Version=%d", loaded.Version, got.Version)
	}

	all, _ := s.List(context.Background())
	if len(all) != 1 {
		t.Fatalf("List len=%d", len(all))
	}
}

func TestStore_ApplyTwiceIncrementsVersion(t *testing.T) {
	s := memory.New()
	defer s.Close()
	p := &netpolicy.Policy{Name: "x"}
	v1, _ := s.Apply(context.Background(), p)
	v2, _ := s.Apply(context.Background(), p)
	if v2.Version <= v1.Version {
		t.Errorf("expected version bump: v1=%d v2=%d", v1.Version, v2.Version)
	}
}

func TestStore_ApplyMissingNameErrors(t *testing.T) {
	s := memory.New()
	defer s.Close()
	if _, err := s.Apply(context.Background(), &netpolicy.Policy{}); err == nil {
		t.Fatal("expected error for missing Name")
	}
}

func TestStore_GetUnknownReturnsErrNotFound(t *testing.T) {
	s := memory.New()
	defer s.Close()
	if _, err := s.Get(context.Background(), "nope"); !errors.Is(err, netpolicy.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestStore_DeleteIdempotent(t *testing.T) {
	s := memory.New()
	defer s.Close()
	if err := s.Delete(context.Background(), "ghost"); err != nil {
		t.Fatalf("Delete of missing should be nil, got %v", err)
	}
	_, _ = s.Apply(context.Background(), &netpolicy.Policy{Name: "x"})
	if err := s.Delete(context.Background(), "x"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Get(context.Background(), "x"); !errors.Is(err, netpolicy.ErrNotFound) {
		t.Fatalf("after Delete, Get should be ErrNotFound, got %v", err)
	}
}

func TestStore_WatchDeliversAddUpdateRemove(t *testing.T) {
	s := memory.New()
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ch, err := s.Watch(ctx)
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}

	_, _ = s.Apply(context.Background(), &netpolicy.Policy{Name: "p"})
	_, _ = s.Apply(context.Background(), &netpolicy.Policy{Name: "p", CIDRs: []string{"10.0.0.0/8"}})
	_ = s.Delete(context.Background(), "p")

	want := []netpolicy.EventType{netpolicy.EventAdded, netpolicy.EventUpdated, netpolicy.EventRemoved}
	for i, expect := range want {
		select {
		case evt, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed before event %d", i)
			}
			if evt.Type != expect {
				t.Errorf("event %d: got %s, want %s", i, evt.Type, expect)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for event %d (%s)", i, expect)
		}
	}
}

func TestStore_WatchClosesOnContextCancel(t *testing.T) {
	s := memory.New()
	defer s.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := s.Watch(ctx)
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected channel closed after ctx cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: channel didn't close")
	}
}

func TestStore_CloseClosesWatchers(t *testing.T) {
	s := memory.New()
	ch, _ := s.Watch(context.Background())
	_ = s.Close()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("timeout: Close did not close watcher")
	}
}

func TestStore_ApplyAfterCloseFails(t *testing.T) {
	s := memory.New()
	_ = s.Close()
	if _, err := s.Apply(context.Background(), &netpolicy.Policy{Name: "x"}); !errors.Is(err, memory.ErrClosed) {
		t.Fatalf("expected ErrClosed, got %v", err)
	}
}
