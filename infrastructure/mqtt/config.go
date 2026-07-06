package mqttbus

import (
	"crypto/tls"
	"time"
)

// Defaults applied when a corresponding Config field is zero.
const (
	// DefaultPrefix is the flat topic every Kind publishes to and
	// Subscribe listens on. See doc.go's "Wire format" section for why
	// this is a single topic, not a per-Kind tree.
	DefaultPrefix = "snaplink/cluster/bus/events"

	// DefaultConnectTimeout bounds the TCP dial + MQTT CONNECT handshake.
	DefaultConnectTimeout = 10 * time.Second

	// DefaultKeepAlive is the MQTT keep-alive interval (seconds), matching
	// paho's recommended default — frequent enough that a dead peer is
	// detected well within any reasonable readiness-check interval.
	DefaultKeepAlive = 30

	// DefaultQoS is the delivery guarantee for both Publish and Subscribe.
	// See doc.go's "Delivery semantics" section for why QoS 1, not 0 or 2.
	DefaultQoS = byte(1)

	// DefaultSessionExpiryInterval bounds how long the broker remembers
	// this Bus's persistent session (and queues QoS-1 messages published
	// during a disconnect) before treating it as abandoned. See doc.go's
	// "Delivery semantics" section.
	DefaultSessionExpiryInterval = 5 * time.Minute
)

// Config configures the MQTT Bus.
type Config struct {
	// BrokerAddr is a "host:port" TCP address (e.g. "mqtt.internal:1883").
	// Required. Unlike Kafka's bootstrap-then-metadata-refresh or etcd's
	// multi-endpoint client-side failover, MQTT has no equivalent client
	// cluster discovery — point BrokerAddr at a load-balanced VIP/DNS name
	// in front of a real broker cluster (EMQX/HiveMQ/mosquitto-HA) for HA;
	// this Bus does not attempt to reimplement that.
	BrokerAddr string

	// TLSConfig, when non-nil, dials BrokerAddr over TLS instead of plain
	// TCP. nil means an unencrypted connection — appropriate only on a
	// trusted mesh-internal network (the same trust model as every other
	// cluster.Bus peer; see platform/cluster/bus.go's doc).
	TLSConfig *tls.Config

	// ClientID identifies this replica's persistent MQTT session. Required
	// and MUST be stable across this replica's reconnects (a changing
	// ClientID starts a fresh, empty session each time and defeats
	// SessionExpiryInterval's queued-message replay) — but MUST be unique
	// across replicas (two Bus instances sharing a ClientID cause the
	// broker to disconnect one of them, per the MQTT spec).
	ClientID string

	// Username / Password are optional MQTT-level credentials.
	Username string
	Password string

	// Prefix is the topic every Event publishes to and Subscribe listens
	// on. Defaults to DefaultPrefix.
	Prefix string

	// QoS is the delivery guarantee (0, 1, or 2) for both Publish and
	// Subscribe. Defaults to DefaultQoS (1). Callers wanting QoS 0/2
	// instead of the default must set this explicitly — see doc.go for
	// why 1 is recommended.
	QoS *byte

	// ConnectTimeout bounds the TCP dial + MQTT CONNECT handshake.
	// Defaults to DefaultConnectTimeout.
	ConnectTimeout time.Duration

	// SessionExpiryInterval bounds how long the broker retains this Bus's
	// persistent session across a disconnect. Defaults to
	// DefaultSessionExpiryInterval.
	SessionExpiryInterval time.Duration
}

// withDefaults returns a copy of cfg with every zero field set to its
// documented default.
func (cfg Config) withDefaults() Config {
	if cfg.Prefix == "" {
		cfg.Prefix = DefaultPrefix
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = DefaultConnectTimeout
	}
	if cfg.SessionExpiryInterval <= 0 {
		cfg.SessionExpiryInterval = DefaultSessionExpiryInterval
	}
	if cfg.QoS == nil {
		q := DefaultQoS
		cfg.QoS = &q
	}
	return cfg
}
