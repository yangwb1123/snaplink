package mqttbus

import (
	"context"
	"testing"
	"time"

	"github.com/eclipse/paho.golang/paho"
)

func newTestTopicPublisher(t *testing.T, addr, clientID string) *TopicPublisher {
	t.Helper()
	p, err := NewTopicPublisher(Config{
		BrokerAddr:     addr,
		ClientID:       clientID,
		ConnectTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewTopicPublisher: %v", err)
	}
	return p
}

func TestNewTopicPublisher_RequiresBrokerAddrAndClientID(t *testing.T) {
	t.Parallel()
	if _, err := NewTopicPublisher(Config{ClientID: "c"}); err == nil {
		t.Error("expected error for empty BrokerAddr")
	}
	if _, err := NewTopicPublisher(Config{BrokerAddr: "localhost:1883"}); err == nil {
		t.Error("expected error for empty ClientID")
	}
}

func TestTopicPublisher_PublishToArbitraryTopic(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	pub := newTestTopicPublisher(t, addr, "topic-publisher-1")

	sub := newTestBus(t, addr, "topic-publisher-subscriber")
	// Subscribe directly to the arbitrary per-receiver topic via a raw
	// connection (Bus.Subscribe only listens on Config.Prefix).
	client, err := dialConnect(context.Background(), sub.cfg, sub.cfg.ClientID, false)
	if err != nil {
		t.Fatalf("dialConnect: %v", err)
	}
	defer func() { _ = client.Disconnect(&paho.Disconnect{ReasonCode: 0}) }()

	const topic = "caep/receivers/client-123/events"
	received := make(chan []byte, 1)
	client.AddOnPublishReceived(func(pr paho.PublishReceived) (bool, error) {
		received <- pr.Packet.Payload
		return true, nil
	})
	if _, err := client.Subscribe(context.Background(), &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{Topic: topic, QoS: 1}},
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	want := []byte("eyJhbGciOiJFUzI1NiJ9.example-set.signature")
	if err := pub.Publish(context.Background(), topic, want); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-received:
		if string(got) != string(want) {
			t.Errorf("payload = %q, want %q", got, want)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the published payload")
	}
}

func TestTopicPublisher_DifferentTopicsDoNotCrossDeliver(t *testing.T) {
	t.Parallel()
	_, addr := newTestBroker(t)
	pub := newTestTopicPublisher(t, addr, "topic-publisher-2")
	sub := newTestBus(t, addr, "topic-publisher-subscriber-2")

	client, err := dialConnect(context.Background(), sub.cfg, sub.cfg.ClientID, false)
	if err != nil {
		t.Fatalf("dialConnect: %v", err)
	}
	defer func() { _ = client.Disconnect(&paho.Disconnect{ReasonCode: 0}) }()

	received := make(chan []byte, 1)
	client.AddOnPublishReceived(func(pr paho.PublishReceived) (bool, error) {
		received <- pr.Packet.Payload
		return true, nil
	})
	if _, err := client.Subscribe(context.Background(), &paho.Subscribe{
		Subscriptions: []paho.SubscribeOptions{{Topic: "caep/receivers/client-A/events", QoS: 1}},
	}); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	if err := pub.Publish(context.Background(), "caep/receivers/client-B/events", []byte("not-for-A")); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	select {
	case got := <-received:
		t.Fatalf("received a message meant for a different topic: %q", got)
	case <-time.After(300 * time.Millisecond):
		// Expected: no cross-delivery.
	}
}
