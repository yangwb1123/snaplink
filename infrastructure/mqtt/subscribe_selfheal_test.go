package mqttbus

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/cluster"
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

// TestBus_SessionResumptionRedeliversEventsPublishedDuringGap is the direct
// regression test for doc.go's advertised advantage over the etcd peer: "a
// brief disconnect shorter than SessionExpiryInterval lets the broker queue
// QoS-1 messages published during the gap and deliver them on reconnect".
// Unlike TestBus_SubscribeRecoversAfterBrokerRestart (which spins up a BRAND
// NEW broker and so never exercises session resumption at all), this test
// keeps the SAME broker alive, gracefully disconnects the subscriber (ctx
// cancel — a real MQTT DISCONNECT, not a transport kill), publishes into the
// gap while the subscriber is offline, then reconnects with the SAME
// ClientID + cleanStart=false and expects the broker to flush the queued
// message immediately.
//
// This also pins the ordering fix in client.go/subscribe.go: the inbound-
// publish handler is now wired via paho.ClientConfig.OnPublishReceived at
// client CONSTRUCTION (before Connect starts the incoming/routePublishPackets
// goroutines), not via a post-Connect AddOnPublishReceived call. A session
// resumption can flush its queued backlog the instant CONNACK completes, and
// paho auto-acks every message regardless of how many handlers are bound —
// registering the handler even one step too late risks the queued message
// being silently, permanently dropped (acked with zero handlers), which a
// fresh-broker test can never catch.
func TestBus_SessionResumptionRedeliversEventsPublishedDuringGap(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	sub := newTestBus(t, addr, "subscriber-resume")

	ctx1, cancel1 := context.WithCancel(context.Background())
	events1, err := sub.Subscribe(ctx1)
	if err != nil {
		t.Fatalf("first Subscribe: %v", err)
	}
	// Let the SUBSCRIBE land at the broker before disconnecting.
	time.Sleep(50 * time.Millisecond)

	// Graceful disconnect (ctx cancel -> Subscribe's goroutine sends a clean
	// DISCONNECT) — the SAME broker stays up, so its persistent session for
	// this ClientID survives per Config.SessionExpiryInterval.
	cancel1()
	select {
	case <-events1:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the channel to close after ctx cancel")
	}

	// Publish while the subscriber is offline: the broker queues this QoS-1
	// message against the still-live (not yet expired) session.
	pub := newTestBus(t, addr, "publisher-resume")
	want := cluster.Event{Kind: cluster.KindTenantSuspension, Key: "tenant-gap"}
	if err := pub.Publish(context.Background(), want); err != nil {
		t.Fatalf("Publish during gap: %v", err)
	}

	// Reconnect with the SAME ClientID (cleanStart=false) — session
	// resumption should immediately redeliver the queued message.
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	events2, err := sub.Subscribe(ctx2)
	if err != nil {
		t.Fatalf("second Subscribe (resume): %v", err)
	}

	select {
	case got := <-events2:
		if got.Key != want.Key {
			t.Errorf("got Key=%q, want %q", got.Key, want.Key)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the gap-published event to be redelivered on session " +
			"resumption — the persistent-session replay this backend advertises over etcd's " +
			"watch-gap behavior is not actually working")
	}
}
