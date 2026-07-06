package mqttbus

import (
	"context"
	"fmt"

	"github.com/eclipse/paho.golang/paho"
)

// TopicPublisher publishes arbitrary payloads to an ARBITRARY MQTT
// topic — a more general primitive than [Bus] (which always publishes a
// cluster.Event to the one fixed Config.Prefix topic). Useful wherever a
// caller needs a per-call topic rather than one shared coordination
// topic — e.g. protocols/caep's MQTTPublisher seam, which pushes a
// signed SET to a PER-RECEIVER topic instead of the cluster-wide
// invalidation topic.
//
// Deliberately a SEPARATE type from Bus, not an added method on it: Bus's
// whole contract (Publish/Subscribe/Close, one fixed topic) matches
// cluster.Bus's interface exactly, and mixing in an arbitrary-topic
// method would blur that. Construct a TopicPublisher alongside (or
// instead of) a Bus as needed — they share no state.
type TopicPublisher struct {
	cfg Config
}

// NewTopicPublisher validates cfg and returns a TopicPublisher. Like
// [New], this does not dial — a connection is established lazily on
// every Publish call (see Publish's doc for why one-shot).
func NewTopicPublisher(cfg Config) (*TopicPublisher, error) {
	if cfg.BrokerAddr == "" {
		return nil, fmt.Errorf("mqttbus: BrokerAddr required")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("mqttbus: ClientID required")
	}
	return &TopicPublisher{cfg: cfg.withDefaults()}, nil
}

// Publish opens a one-shot connection (a derived, per-call-unique
// ClientID — see client.go's dialConnect doc for why Publish never
// reuses a shared session identity), publishes payload to topic at
// Config.QoS with retain=false, and disconnects. Matches [Bus.Publish]'s
// shape exactly, just parameterized by topic instead of Config.Prefix
// and by a raw payload instead of a marshaled cluster.Event.
func (p *TopicPublisher) Publish(ctx context.Context, topic string, payload []byte) error {
	clientID := p.cfg.ClientID + "-pub-" + randomSuffix()
	client, err := dialConnect(ctx, p.cfg, clientID, true)
	if err != nil {
		return err
	}
	defer func() { _ = client.Disconnect(&paho.Disconnect{ReasonCode: 0}) }()

	if _, err := client.Publish(ctx, &paho.Publish{
		Topic:   topic,
		QoS:     *p.cfg.QoS,
		Retain:  false,
		Payload: payload,
	}); err != nil {
		return fmt.Errorf("mqttbus: publish: %w", err)
	}
	return nil
}
