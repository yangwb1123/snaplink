package sse

import (
	"sync"
	"testing"
	"time"
)

// waitForSubscribers polls (bounded, no fixed sleep-and-hope) until the
// broker reports at least n live subscribers, or fails the test. Used by
// handler tests that need a publish to happen only AFTER HandleStream's
// Subscribe has registered — reading b.subs directly (white-box, same
// package) instead of racing on a side channel.
func waitForSubscribers(t *testing.T, b *Broker, n int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		b.mu.Lock()
		count := len(b.subs)
		b.mu.Unlock()
		if count >= n {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d subscriber(s)", n)
}

func drain(t *testing.T, s *Subscriber, timeout time.Duration) (Event, bool) {
	t.Helper()
	select {
	case ev, ok := <-s.C():
		return ev, ok
	case <-time.After(timeout):
		t.Fatal("timed out waiting for event")
		return Event{}, false
	}
}

func TestBroker_PublishFanoutMonotonicIDs(t *testing.T) {
	b := NewBroker(Options{})
	s1, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe s1: %v", err)
	}
	s2, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe s2: %v", err)
	}
	defer s1.Close()
	defer s2.Close()

	id1 := b.Publish(Event{Type: "a", Data: []byte(`{"n":1}`)})
	id2 := b.Publish(Event{Type: "b", Data: []byte(`{"n":2}`)})
	if id1 != 1 || id2 != 2 {
		t.Fatalf("expected monotonic ids 1,2; got %d,%d", id1, id2)
	}

	for _, sub := range []*Subscriber{s1, s2} {
		ev, ok := drain(t, sub, time.Second)
		if !ok || ev.ID != 1 || ev.Type != "a" {
			t.Fatalf("subscriber missed first event: ok=%v ev=%+v", ok, ev)
		}
		ev, ok = drain(t, sub, time.Second)
		if !ok || ev.ID != 2 || ev.Type != "b" {
			t.Fatalf("subscriber missed second event: ok=%v ev=%+v", ok, ev)
		}
	}
}

func TestBroker_FilterByTypeAndTenant(t *testing.T) {
	b := NewBroker(Options{})
	typed, err := b.Subscribe(Filter{Types: []string{"login"}})
	if err != nil {
		t.Fatalf("subscribe typed: %v", err)
	}
	defer typed.Close()
	tenanted, err := b.Subscribe(Filter{TenantID: "acme"})
	if err != nil {
		t.Fatalf("subscribe tenanted: %v", err)
	}
	defer tenanted.Close()

	b.Publish(Event{Type: "logout", TenantID: "other", Data: []byte("{}")})
	b.Publish(Event{Type: "login", TenantID: "other", Data: []byte(`{"n":2}`)})
	b.Publish(Event{Type: "logout", TenantID: "acme", Data: []byte(`{"n":3}`)})

	ev, ok := drain(t, typed, time.Second)
	if !ok || ev.ID != 2 {
		t.Fatalf("type filter let through wrong event: ok=%v ev=%+v", ok, ev)
	}
	select {
	case extra, ok := <-typed.C():
		t.Fatalf("type filter delivered an unexpected extra event: ok=%v ev=%+v", ok, extra)
	case <-time.After(20 * time.Millisecond):
	}

	ev, ok = drain(t, tenanted, time.Second)
	if !ok || ev.ID != 3 {
		t.Fatalf("tenant filter let through wrong event: ok=%v ev=%+v", ok, ev)
	}
}

func TestBroker_SlowConsumerEvictedNeverBlocksPublisher(t *testing.T) {
	b := NewBroker(Options{SubscriberBuffer: 1})
	slow, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer slow.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Never drain slow.C(): the first Publish fills its 1-slot buffer,
		// every subsequent Publish must evict rather than block.
		for i := 0; i < 50; i++ {
			b.Publish(Event{Type: "x", Data: []byte("{}")})
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a slow consumer instead of evicting it")
	}

	// The evicted subscriber's channel must be closed (handler-visible
	// signal to end the SSE response so the client reconnects).
	select {
	case _, ok := <-slow.C():
		if ok {
			// One buffered event may still be pending; drain until closed.
			for ok {
				_, ok = <-slow.C()
			}
		}
	case <-time.After(time.Second):
		t.Fatal("evicted subscriber channel was never closed")
	}
}

func TestBroker_MaxSubscribersRejectsPastCap(t *testing.T) {
	b := NewBroker(Options{MaxSubscribers: 2})
	s1, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe 1: %v", err)
	}
	defer s1.Close()
	s2, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe 2: %v", err)
	}
	defer s2.Close()

	if _, err := b.Subscribe(Filter{}); err != ErrMaxSubscribers {
		t.Fatalf("expected ErrMaxSubscribers, got %v", err)
	}

	// Freeing a slot (explicit Close) must let a new Subscribe through.
	s1.Close()
	s3, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe after free: %v", err)
	}
	defer s3.Close()
}

func TestBroker_ReplayWindowAndFilter(t *testing.T) {
	b := NewBroker(Options{ReplayBuffer: 3})
	for i := 1; i <= 5; i++ {
		b.Publish(Event{Type: "t", TenantID: "acme", Data: []byte("{}")})
	}
	// Only the last ReplayBuffer(3) events (ids 3,4,5) survive the ring.
	all := b.Replay(0, Filter{})
	if len(all) != 3 || all[0].ID != 3 || all[2].ID != 5 {
		t.Fatalf("expected ring window [3,4,5], got %+v", all)
	}

	after4 := b.Replay(4, Filter{})
	if len(after4) != 1 || after4[0].ID != 5 {
		t.Fatalf("expected only id 5 after afterID=4, got %+v", after4)
	}

	filtered := b.Replay(0, Filter{TenantID: "other"})
	if len(filtered) != 0 {
		t.Fatalf("expected no events for a non-matching tenant filter, got %+v", filtered)
	}
}

func TestBroker_CloseEvictsSubscribersAndRejectsNew(t *testing.T) {
	b := NewBroker(Options{})
	s, err := b.Subscribe(Filter{})
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	b.Close()

	select {
	case _, ok := <-s.C():
		if ok {
			t.Fatal("subscriber channel produced a value instead of closing on Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not close the subscriber channel")
	}

	if _, err := b.Subscribe(Filter{}); err != ErrBrokerClosed {
		t.Fatalf("expected ErrBrokerClosed after Close, got %v", err)
	}
	// Publish after Close is a documented no-op, not a panic.
	if id := b.Publish(Event{Type: "x"}); id != 0 {
		t.Fatalf("expected Publish after Close to no-op with id 0, got %d", id)
	}
}

// TestBroker_ConcurrentFanoutRace drives concurrent Subscribe/Publish/Close
// from many goroutines so `go test -race` catches any lock-ordering or
// map-mutation bug in the fan-out path. Regression coverage for the
// "publisher iterates b.subs while a slow consumer is evicted" pattern.
func TestBroker_ConcurrentFanoutRace(t *testing.T) {
	b := NewBroker(Options{SubscriberBuffer: 2, MaxSubscribers: 8})
	var wg sync.WaitGroup

	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				b.Publish(Event{Type: "race", Data: []byte("{}")})
			}
		}()
	}
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				sub, err := b.Subscribe(Filter{})
				if err != nil {
					continue
				}
				// Read a couple of events (or let eviction/close race in)
				// then detach — exercising both the drain path and the
				// concurrent-Close idempotency guard.
				select {
				case <-sub.C():
				case <-time.After(5 * time.Millisecond):
				}
				sub.Close()
			}
		}()
	}
	wg.Wait()
}

func TestBroker_SubjectFilterNeverCrossesUsers(t *testing.T) {
	b := NewBroker(Options{})
	alice, err := b.Subscribe(Filter{SubjectID: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	defer alice.Close()
	bob, err := b.Subscribe(Filter{SubjectID: "bob"})
	if err != nil {
		t.Fatal(err)
	}
	defer bob.Close()
	b.Publish(Event{Type: "notification", SubjectID: "alice", Data: []byte("{}")})
	if event, ok := drain(t, alice, time.Second); !ok || event.SubjectID != "alice" {
		t.Fatalf("alice event=%#v ok=%v", event, ok)
	}
	select {
	case event := <-bob.C():
		t.Fatalf("bob received alice event: %#v", event)
	case <-time.After(20 * time.Millisecond):
	}
	if replay := b.Replay(0, Filter{SubjectID: "bob"}); len(replay) != 0 {
		t.Fatalf("bob replay leaked %d event(s)", len(replay))
	}
}
