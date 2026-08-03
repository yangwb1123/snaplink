package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/platform/cluster"
)

// recvBusEvent waits up to timeout for one event on ch. Fatal on close or
// timeout, so tests read with a bounded wait instead of blocking forever.
func recvBusEvent(t *testing.T, ch <-chan cluster.Event, timeout time.Duration) cluster.Event {
	t.Helper()
	select {
	case evt, ok := <-ch:
		if !ok {
			t.Fatal("bus stream closed while expecting an event")
		}
		return evt
	case <-time.After(timeout):
		t.Fatalf("no bus event within %v", timeout)
		return cluster.Event{}
	}
}

// publishRaw sends an arbitrary payload on the bus channel, bypassing the
// envelope marshalling — what a peer with a different wire format (or a
// garbage producer) would put on the channel.
func publishRaw(t *testing.T, rdb goredis.Cmdable, channel, payload string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rdb.Publish(ctx, channel, payload).Err(); err != nil {
		t.Fatalf("raw publish: %v", err)
	}
}

// envelopeBody marshals a wire envelope exactly as the bus would (used to
// inject near-miss self-skip ids and absent-instance messages).
func envelopeBody(t *testing.T, evt cluster.Event, instance string) string {
	t.Helper()
	body, err := json.Marshal(busEnvelope{Event: evt, Instance: instance})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	return string(body)
}

// TestBus_PublishSubscribeRoundTrip proves the round-trip decode fidelity:
// the received Event carries an identical Kind/Key/Payload to the published
// one (spec I1a).
func TestBus_PublishSubscribeRoundTrip(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	evt := cluster.Event{
		Kind: cluster.KindTokenRevoked,
		Payload: map[string]string{
			cluster.MetaRevokedToken: "access-token-abc",
			cluster.MetaRevokedExp:   "1750000000",
		},
	}
	if err := bus.Publish(ctx, evt); err != nil {
		t.Fatalf("publish: %v", err)
	}
	got := recvBusEvent(t, events, 2*time.Second)
	if got.Kind != evt.Kind || got.Key != evt.Key {
		t.Fatalf("got kind=%q key=%q; want kind=%q key=%q", got.Kind, got.Key, evt.Kind, evt.Key)
	}
	if len(got.Payload) != len(evt.Payload) || got.Payload[cluster.MetaRevokedToken] != evt.Payload[cluster.MetaRevokedToken] {
		t.Fatalf("payload mismatch: %v vs %v", got.Payload, evt.Payload)
	}
}

// TestBus_TwoInstancesOneRedis proves two separate Bus instances (simulated
// replicas) over one Redis deliver to each other, while each instance's own
// events are filtered by its self-skip id (spec I1b + I1e).
func TestBus_TwoInstancesOneRedis(t *testing.T) {
	_, rdb := newTestClient(t)
	busA := NewBus(rdb, WithInstanceID("replica-a"))
	busB := NewBus(rdb, WithInstanceID("replica-b"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsA, err := busA.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe A: %v", err)
	}
	eventsB, err := busB.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe B: %v", err)
	}

	evtA := cluster.Event{Kind: cluster.KindTenantSuspension, Key: "t-1"}
	if err := busA.Publish(ctx, evtA); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	// B receives A's event; A must NOT receive its own (self-skip).
	got := recvBusEvent(t, eventsB, 2*time.Second)
	if !reflect.DeepEqual(got, evtA) {
		t.Fatalf("B got %+v; want %+v", got, evtA)
	}
	select {
	case evt := <-eventsA:
		t.Fatalf("A received its own event %+v; self-skip must filter it", evt)
	case <-time.After(300 * time.Millisecond):
	}

	evtB := cluster.Event{Kind: cluster.KindDiscoveryReload}
	if err := busB.Publish(ctx, evtB); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	// The reverse direction: A receives B's event.
	got = recvBusEvent(t, eventsA, 2*time.Second)
	if !reflect.DeepEqual(got, evtB) {
		t.Fatalf("A got %+v; want %+v", got, evtB)
	}
}

// TestBus_CloseThenPublishErrClosed proves the ErrClosed contract (spec I1c):
// after Close, Publish and Subscribe return ErrClosed and Close is idempotent.
func TestBus_CloseThenPublishErrClosed(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := bus.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := bus.Close(); err != nil {
		t.Fatalf("second Close must be idempotent: %v", err)
	}
	if err := bus.Publish(ctx, cluster.Event{Kind: cluster.KindTenantSuspension, Key: "t"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Publish after Close = %v; want ErrClosed", err)
	}
	if _, err := bus.Subscribe(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("Subscribe after Close = %v; want ErrClosed", err)
	}
}

// TestBus_CtxCancelClosesStreamExactlyOnce proves ctx cancellation closes the
// subscription channel exactly once — a second receive on the closed channel
// yields ok=false without a double-close panic (spec I1d).
func TestBus_CtxCancelClosesStreamExactlyOnce(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb)
	ctx, cancel := context.WithCancel(context.Background())

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	cancel()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("stream delivered an event after ctx cancel")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not close on ctx cancel")
	}
	if _, ok := <-events; ok {
		t.Fatal("stream reopened after close")
	}
}

// TestBus_CloseWithActiveSubscription proves Close terminates an in-flight
// Subscribe stream (the path wireCluster's shutdown relies on): the stream
// closes exactly once, and subsequent calls return ErrClosed (QA M2).
func TestBus_CloseWithActiveSubscription(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := bus.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("stream delivered after Close")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not close on Bus Close")
	}
	if err := bus.Publish(ctx, cluster.Event{Kind: cluster.KindTenantSuspension, Key: "t"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("Publish after Close = %v; want ErrClosed", err)
	}
	if _, err := bus.Subscribe(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("Subscribe after Close = %v; want ErrClosed", err)
	}
}

// TestBus_SelfSkipFiltersOnlyOwnEvents proves the self-skip filter is a
// strict exact match on the instance id (QA M1): the own id is suppressed,
// while a peer id, an ABSENT instance (an older peer, mixed-version
// direction), and near-miss ids ("a ", "A", "a\n" — no normalization) are all
// delivered.
func TestBus_SelfSkipFiltersOnlyOwnEvents(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb, WithInstanceID("a"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: "t-1"}
	// Own event: filtered.
	if err := bus.Publish(ctx, evt); err != nil {
		t.Fatalf("publish own: %v", err)
	}
	// Peer event: delivered.
	if err := NewBus(rdb, WithInstanceID("b")).Publish(ctx, evt); err != nil {
		t.Fatalf("publish peer: %v", err)
	}
	// Absent instance (older peer): delivered.
	publishRaw(t, rdb, bus.Channel(), envelopeBody(t, evt, ""))
	// Near-miss ids: delivered (exact match only, no trimming/casing).
	for _, near := range []string{"a ", "A", "a\n"} {
		publishRaw(t, rdb, bus.Channel(), envelopeBody(t, evt, near))
	}

	for i := 0; i < 5; i++ {
		if got := recvBusEvent(t, events, 2*time.Second); !reflect.DeepEqual(got, evt) {
			t.Fatalf("event %d: got %+v; want %+v", i, got, evt)
		}
	}
	select {
	case evt := <-events:
		t.Fatalf("unexpected extra event %+v (own event must be filtered)", evt)
	case <-time.After(300 * time.Millisecond):
	}
}

// TestBus_GarbagePayloadDropped proves an undecodable message is dropped
// without closing the stream or crashing the consumer loop, and a valid event
// still arrives afterwards.
func TestBus_GarbagePayloadDropped(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	publishRaw(t, rdb, bus.Channel(), "not-json{{{")
	publishRaw(t, rdb, bus.Channel(), `{"kind":`)

	evt := cluster.Event{Kind: cluster.KindDiscoveryReload}
	if err := bus.Publish(ctx, evt); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := recvBusEvent(t, events, 2*time.Second); !reflect.DeepEqual(got, evt) {
		t.Fatalf("got %+v; want %+v after garbage", got, evt)
	}
}

// TestBus_SlowConsumerDropsNotBlocks proves the out-channel has a bounded
// queue: the publisher never blocks behind it and the stream stays alive after
// excess events are dropped. The cumulative number read is not buffer-bounded
// once this test starts consuming concurrently with the subscriber goroutine.
func TestBus_SlowConsumerDropsNotBlocks(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	const total = 30 // > subscribeChannelBuffer, no draining in between
	evt := cluster.Event{Kind: cluster.KindClientChange, Key: "c"}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < total; i++ {
			if err := bus.Publish(ctx, evt); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("publisher errored: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("publisher blocked behind the slow consumer; drop-not-block violated")
	}
	if got := cap(events); got != subscribeChannelBuffer {
		t.Fatalf("event channel capacity = %d, want %d", got, subscribeChannelBuffer)
	}

	var got int
	for {
		select {
		case <-events:
			got++
		case <-time.After(500 * time.Millisecond):
			// Quiet: the receive goroutine has drained everything it will get.
			if got == 0 {
				t.Fatal("no events received at all")
			}
			// The stream must still be alive and delivering.
			if err := bus.Publish(ctx, evt); err != nil {
				t.Fatalf("publish after drop: %v", err)
			}
			if got2 := recvBusEvent(t, events, 2*time.Second); !reflect.DeepEqual(got2, evt) {
				t.Fatalf("got %+v; want %+v", got2, evt)
			}
			return
		}
	}
}

// TestBus_ForcedServerLossClosesStreamAndPublishFails is the loss-detection
// unit test (spec I3, G-2/G-4): killing the Redis server with a live
// subscription must close the stream (a lost subscription looks exactly like
// a closed channel) and a subsequent Publish must return a transport error.
func TestBus_ForcedServerLossClosesStreamAndPublishFails(t *testing.T) {
	mr, rdb := newTestClient(t)
	bus := NewBus(rdb, WithInstanceID("a"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	// Prime the stream so a delivery works before the loss. Published via a
	// peer bus (no self-skip id) so this bus's own self-skip filter can't
	// swallow it.
	peer := NewBus(rdb)
	evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: "t-1"}
	if err := peer.Publish(ctx, evt); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if got := recvBusEvent(t, events, 2*time.Second); !reflect.DeepEqual(got, evt) {
		t.Fatalf("got %+v; want %+v", got, evt)
	}

	// Kill the server: miniredis closes every peer connection, so the
	// dedicated pub/sub connection dies and the stream must close.
	mr.Close()
	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("stream delivered after server loss")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("stream did not close on server loss")
	}
	// Publish must now fail (transport unreachable), not silently succeed.
	if err := bus.Publish(ctx, evt); err == nil {
		t.Fatal("Publish after server loss returned nil; want transport error")
	}
}

// TestBus_SubscribeFailsWhenRedisUnreachable proves the initial-subscribe
// boot contract (spec I3 loss-taxonomy row 1, QA H2): a Redis that cannot be
// reached at subscribe time surfaces as a synchronous Subscribe error, not as
// an async channel close that would look like a mid-life degradation.
func TestBus_SubscribeFailsWhenRedisUnreachable(t *testing.T) {
	// A listener we immediately close: a guaranteed-closed local port.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	rdb := goredis.NewClient(&goredis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	bus := NewBus(rdb)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := bus.Subscribe(ctx); err == nil {
		t.Fatal("Subscribe to unreachable Redis returned nil; want synchronous error")
	}
}

// TestBus_NilRdbErrorsAtFirstUse proves a hand-constructed nil-rdb Bus errors
// descriptively on first use instead of panicking (QA H2, F-11's runtime
// counterpart).
func TestBus_NilRdbErrorsAtFirstUse(t *testing.T) {
	bus := NewBus(nil)
	ctx := context.Background()
	if err := bus.Publish(ctx, cluster.Event{Kind: cluster.KindTenantSuspension, Key: "t"}); err == nil {
		t.Fatal("Publish on nil-rdb bus returned nil; want descriptive error")
	} else if errors.Is(err, ErrClosed) {
		t.Fatalf("Publish on nil-rdb bus = ErrClosed; want descriptive client error, got %v", err)
	}
	if _, err := bus.Subscribe(ctx); err == nil {
		t.Fatal("Subscribe on nil-rdb bus returned nil; want descriptive error")
	} else if errors.Is(err, ErrClosed) {
		t.Fatalf("Subscribe on nil-rdb bus = ErrClosed; want descriptive client error, got %v", err)
	}
}

// TestBus_ConcurrentPublishRace proves Publish is safe for concurrent use
// (spec I1 "safe for concurrent use", QA M3): many goroutines publishing
// distinct events while one subscriber drains — no panic, no deadlock, and
// every received event decodes to one of the published set. Run with
// -race -count=10+ per AGENTS.md §5.
func TestBus_ConcurrentPublishRace(t *testing.T) {
	_, rdb := newTestClient(t)
	bus := NewBus(rdb, WithInstanceID("a"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	events, err := bus.Subscribe(ctx)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	const goroutines = 8
	const perGoroutine = 25
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: fmt.Sprintf("g%d-%d", g, i)}
				if err := bus.Publish(ctx, evt); err != nil {
					t.Errorf("publish: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	published := make(map[string]bool, goroutines*perGoroutine)
	for g := 0; g < goroutines; g++ {
		for i := 0; i < perGoroutine; i++ {
			published[fmt.Sprintf("g%d-%d", g, i)] = true
		}
	}
	// Drain until quiet; every received event must be one of the published set
	// (the 16-slot buffer may drop the rest — that is the contract).
	for {
		select {
		case evt := <-events:
			if !published[evt.Key] {
				t.Fatalf("received event key %q that was never published (corruption?)", evt.Key)
			}
		case <-time.After(500 * time.Millisecond):
			return
		}
	}
}
