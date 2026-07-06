package mqttbus

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/cluster"
)

// TestBus_SubscribeChannelClosesWhenBrokerDies is the differentiating test
// this backend needs beyond what infrastructure/kafka's producer-only
// module required: proof that Subscribe's contract matches etcd.go's
// exactly (channel closes on transport loss while ctx is still live), so
// the generic self-heal wrapper (interfaces/sso's runInvalidationBus)
// notices and retries instead of the subscriber going silently deaf. See
// doc.go's "Reconnection" section for why this matters more here than for
// etcd (paho's own auto-reconnect, if used naively, could otherwise leave
// a connection "transport-healthy but broker-deaf").
func TestBus_SubscribeChannelClosesWhenBrokerDies(t *testing.T) {
	t.Parallel()
	broker, addr := newTestBroker(t)
	sub := newTestBus(t, addr, "subscriber-selfheal")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := sub.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}

	// Kill the broker out from under the live subscription.
	if err := broker.Close(); err != nil {
		t.Fatalf("broker Close: %v", err)
	}

	select {
	case _, ok := <-events:
		if ok {
			t.Error("expected the channel to close (no event) after the broker died")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out: Subscribe's channel did not close after the broker died — " +
			"a real deployment would sit silently deaf, never tripping the degraded/self-heal path")
	}
}

// TestBus_SubscribeRecoversAfterBrokerRestart proves the OTHER half: once
// the transport is back and the caller (mimicking runInvalidationBus)
// calls Subscribe again, delivery resumes normally — this Bus does not
// need its own internal retry loop for the generic wrapper to work.
func TestBus_SubscribeRecoversAfterBrokerRestart(t *testing.T) {
	t.Parallel()
	broker, addr := newTestBroker(t)
	sub := newTestBus(t, addr, "subscriber-recover")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := sub.Subscribe(ctx)
	if err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}
	if err := broker.Close(); err != nil {
		t.Fatalf("broker Close: %v", err)
	}
	select {
	case <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the channel to close after broker death")
	}

	// Bring a NEW broker up on the SAME address the Bus is configured
	// for, simulating the broker coming back.
	newBroker, newAddr := newTestBroker(t)
	sub.cfg.BrokerAddr = newAddr
	_ = newBroker

	events2, err := sub.Subscribe(ctx)
	if err != nil {
		t.Fatalf("second Subscribe (after recovery): %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	pub := newTestBus(t, newAddr, "publisher-recover")
	if err := pub.Publish(context.Background(), cluster.Event{Kind: cluster.KindTenantSuspension, Key: "tenant-1"}); err != nil {
		t.Fatalf("Publish after recovery: %v", err)
	}

	select {
	case got := <-events2:
		if got.Key != "tenant-1" {
			t.Errorf("got Key=%q, want tenant-1", got.Key)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the event after broker recovery")
	}
}
