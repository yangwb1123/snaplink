package mqttbus

import (
	"context"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
	"github.com/yangwb1123/snaplink/platform/cluster"
)

func newTestBus(t *testing.T, addr, clientID string) *Bus {
	t.Helper()
	b, err := New(Config{
		BrokerAddr:     addr,
		ClientID:       clientID,
		ConnectTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return b
}

func TestNew_RequiresBrokerAddrAndClientID(t *testing.T) {
	t.Parallel()
	if _, err := New(Config{ClientID: "c"}); err == nil {
		t.Error("expected error for empty BrokerAddr")
	}
	if _, err := New(Config{BrokerAddr: "localhost:1883"}); err == nil {
		t.Error("expected error for empty ClientID")
	}
}

func TestBus_PublishThenSubscribeReceives(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	pub := newTestBus(t, addr, "publisher-1")
	sub := newTestBus(t, addr, "subscriber-1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := sub.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	// Give the SUBSCRIBE a moment to land at the broker before publishing
	// — MQTT does not guarantee a publish racing a fresh subscribe is seen.
	time.Sleep(50 * time.Millisecond)

	want := cluster.Event{Kind: cluster.KindTokenRevoked, Payload: map[string]string{cluster.MetaRevokedToken: "tok-1"}}
	if err := pub.Publish(context.Background(), want); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-events:
		if got.Kind != want.Kind || got.Payload[cluster.MetaRevokedToken] != "tok-1" {
			t.Errorf("got = %+v, want %+v", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the published event")
	}
}

func TestBus_FanOutToMultipleSubscribers(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	pub := newTestBus(t, addr, "publisher-fanout")
	subA := newTestBus(t, addr, "subscriber-fanout-a")
	subB := newTestBus(t, addr, "subscriber-fanout-b")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	eventsA, err := subA.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe A: %v", err)
	}
	eventsB, err := subB.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe B: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if err := pub.Publish(context.Background(), cluster.Event{Kind: cluster.KindClientChange, Key: "client-1"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	for name, ch := range map[string]<-chan cluster.Event{"A": eventsA, "B": eventsB} {
		select {
		case got := <-ch:
			if got.Key != "client-1" {
				t.Errorf("subscriber %s got Key=%q, want client-1", name, got.Key)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("subscriber %s: timed out waiting for the published event", name)
		}
	}
}

func TestBus_SubscribeChannelClosesOnContextCancel(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	sub := newTestBus(t, addr, "subscriber-cancel")

	ctx, cancel := context.WithCancel(context.Background())
	events, err := sub.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	cancel()

	select {
	case _, ok := <-events:
		if ok {
			t.Error("expected the channel to be closed (no event), got one instead")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the channel to close after ctx cancel")
	}
}

func TestBus_PublishAndSubscribeAfterCloseReturnErrClosed(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	b := newTestBus(t, addr, "closed-bus")
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := b.Publish(context.Background(), cluster.Event{Kind: cluster.KindClientChange}); err != ErrClosed {
		t.Errorf("Publish after Close = %v, want ErrClosed", err)
	}
	if _, err := b.Subscribe(context.Background()); err != ErrClosed {
		t.Errorf("Subscribe after Close = %v, want ErrClosed", err)
	}
}

func TestBus_CloseIsIdempotent(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	b := newTestBus(t, addr, "idempotent-close")
	if err := b.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestBus_PublishGarbageTopicPayloadIsSkippedNotCrashed(t *testing.T) {
	t.Parallel()
	// A non-JSON payload on the shared topic (e.g. from an unrelated
	// publisher) must be silently skipped, never crash the subscriber.
	_, addr := newTestBroker(t)
	sub := newTestBus(t, addr, "subscriber-garbage")
	rawPub := newTestBus(t, addr, "publisher-garbage")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, err := sub.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	// Publish garbage directly via a raw connection to the same topic.
	client, _, connErr := dialConnect(context.Background(), rawPub.cfg, rawPub.cfg.ClientID+"-pub-raw", true, nil)
	if connErr != nil {
		t.Fatalf("dialConnect: %v", connErr)
	}
	if _, err := client.Publish(context.Background(), &paho.Publish{
		Topic:   rawPub.cfg.Prefix,
		QoS:     1,
		Payload: []byte("not json"),
	}); err != nil {
		t.Fatalf("publish garbage: %v", err)
	}

	// Then a real, valid event — the subscriber must still be alive and
	// deliver it (proving the garbage payload was skipped, not fatal).
	if err := rawPub.Publish(context.Background(), cluster.Event{Kind: cluster.KindDiscoveryReload}); err != nil {
		t.Fatalf("Publish valid event: %v", err)
	}

	select {
	case got := <-events:
		if got.Kind != cluster.KindDiscoveryReload {
			t.Errorf("got = %+v, want KindDiscoveryReload", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the valid event after garbage")
	}
}
