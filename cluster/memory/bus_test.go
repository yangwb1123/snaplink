package memory_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/cluster/memory"
)

func recv(t *testing.T, ch <-chan cluster.Event) cluster.Event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("channel closed, expected event")
		}
		return e
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
		return cluster.Event{}
	}
}

func TestPublish_DeliversToSubscriber(t *testing.T) {
	b := memory.New()
	defer b.Close()
	ch, err := b.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	want := cluster.Event{Kind: cluster.KindTenantSuspension, Key: "tenant-1"}
	if err := b.Publish(context.Background(), want); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := recv(t, ch); got.Kind != want.Kind || got.Key != want.Key {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestPublish_FansOutToAllSubscribers(t *testing.T) {
	b := memory.New()
	defer b.Close()
	ch1, _ := b.Subscribe(context.Background())
	ch2, _ := b.Subscribe(context.Background())
	evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: "t"}
	if err := b.Publish(context.Background(), evt); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := recv(t, ch1); got.Key != evt.Key {
		t.Fatalf("sub1 got %+v", got)
	}
	if got := recv(t, ch2); got.Key != evt.Key {
		t.Fatalf("sub2 got %+v", got)
	}
}

func TestSubscribe_ClosedOnContextCancel(t *testing.T) {
	b := memory.New()
	defer b.Close()
	ctx, cancel := context.WithCancel(context.Background())
	ch, _ := b.Subscribe(ctx)
	cancel()
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel after cancel")
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed after context cancel")
	}
}

func TestClose_ClosesSubscribersAndRejects(t *testing.T) {
	b := memory.New()
	ch, _ := b.Subscribe(context.Background())
	if err := b.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case _, ok := <-ch:
		if ok {
			t.Fatal("expected closed channel after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("subscriber channel not closed by Close")
	}
	if err := b.Publish(context.Background(), cluster.Event{}); !errors.Is(err, memory.ErrClosed) {
		t.Fatalf("Publish after Close: got %v, want ErrClosed", err)
	}
	if _, err := b.Subscribe(context.Background()); !errors.Is(err, memory.ErrClosed) {
		t.Fatalf("Subscribe after Close: got %v, want ErrClosed", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	b := memory.New()
	if err := b.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

// A full subscriber buffer must not block the publisher; the event is
// dropped (best-effort contract) and Publish still returns promptly.
func TestPublish_SlowConsumerDoesNotBlock(t *testing.T) {
	b := memory.New()
	defer b.Close()
	if _, err := b.Subscribe(context.Background()); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	done := make(chan struct{})
	go func() {
		for range 1000 {
			_ = b.Publish(context.Background(), cluster.Event{Key: "k"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked on a full subscriber buffer")
	}
}
