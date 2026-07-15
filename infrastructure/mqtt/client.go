package mqttbus

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/eclipse/paho.golang/paho"
)

// dialConnect opens a TCP (or TLS) connection to cfg.BrokerAddr and
// performs the MQTT CONNECT handshake, returning a ready-to-use client.
// clientID and cleanStart are parameters (not read from cfg) because
// Publish and Subscribe need DIFFERENT identities: two connections
// sharing one ClientID would have the broker disconnect the older one
// per the MQTT spec, so a persistent Subscribe session (cfg.ClientID,
// cleanStart=false) must never collide with a one-shot Publish
// connection (a derived, per-call-unique ID, cleanStart=true).
//
// onPublishReceived, when non-nil, is registered via paho.ClientConfig
// AT CONSTRUCTION — i.e. before Connect() starts the incoming/
// routePublishPackets goroutines — rather than via the client's
// AddOnPublishReceived method after Connect returns. This ordering
// matters for a resumed persistent session (cleanStart=false): the
// broker may flush QoS-1 messages queued during the disconnect gap the
// instant CONNACK completes, and paho's routePublishPackets auto-acks
// every message REGARDLESS of how many handlers are currently bound —
// zero handlers means the message is silently dropped AND acknowledged
// as delivered, so it is never redelivered. Passing the handler through
// ClientConfig closes that registration-order race entirely. nil is
// used for the one-shot Publish path, which has nothing to receive.
//
// The returned client has NO auto-reconnect and no OnClientError/
// OnServerDisconnect retry logic of its own — connection loss is
// reported solely via the returned Client's Done() channel, per
// doc.go's "Reconnection" section. Callers own calling Disconnect.
//
// The returned bool is the CONNACK's Session Present flag (MQTT v5
// §3.2.2.1.1): true means the broker already had a live, non-expired
// session for clientID (a resumed persistent session, cleanStart=false
// only) — its subscriptions, if any, are ALREADY known to the broker.
// Subscribe.go uses this to skip a redundant re-SUBSCRIBE on a resumed
// session: besides being unnecessary, re-subscribing right as the broker
// is flushing that session's queued QoS-1 backlog has been observed to
// collide with at least one real broker's (mochi-mqtt) own PacketID
// bookkeeping for the in-flight redelivery, spuriously failing the whole
// reconnect and discarding an already-in-flight message.
func dialConnect(ctx context.Context, cfg Config, clientID string, cleanStart bool, onPublishReceived func(paho.PublishReceived) (bool, error)) (*paho.Client, bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, cfg.ConnectTimeout)
	defer cancel()

	conn, err := dialConn(dialCtx, cfg)
	if err != nil {
		return nil, false, fmt.Errorf("mqttbus: dial %s: %w", cfg.BrokerAddr, err)
	}

	clientCfg := paho.ClientConfig{
		ClientID: clientID,
		Conn:     conn,
	}
	if onPublishReceived != nil {
		clientCfg.OnPublishReceived = []func(paho.PublishReceived) (bool, error){onPublishReceived}
	}
	client := paho.NewClient(clientCfg)

	connectPacket := &paho.Connect{
		ClientID:   clientID,
		CleanStart: cleanStart,
		KeepAlive:  DefaultKeepAlive,
	}
	if cfg.Username != "" {
		connectPacket.UsernameFlag = true
		connectPacket.Username = cfg.Username
	}
	if cfg.Password != "" {
		connectPacket.PasswordFlag = true
		connectPacket.Password = []byte(cfg.Password)
	}
	if !cleanStart {
		sec := uint32(cfg.SessionExpiryInterval.Seconds())
		connectPacket.Properties = &paho.ConnectProperties{SessionExpiryInterval: &sec}
	}

	ca, err := client.Connect(dialCtx, connectPacket)
	if err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("mqttbus: connect: %w", err)
	}
	if ca.ReasonCode != 0 {
		_ = conn.Close()
		return nil, false, fmt.Errorf("mqttbus: connect refused: reason code %d", ca.ReasonCode)
	}
	return client, ca.SessionPresent, nil
}

// dialConn opens the raw transport (TLS when cfg.TLSConfig is set, plain
// TCP otherwise). Split out of dialConnect for the function-length budget.
func dialConn(ctx context.Context, cfg Config) (net.Conn, error) {
	if cfg.TLSConfig != nil {
		d := tls.Dialer{Config: cfg.TLSConfig}
		return d.DialContext(ctx, "tcp", cfg.BrokerAddr)
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", cfg.BrokerAddr)
}

// randomSuffix returns a short hex string for building a per-call-unique
// publisher ClientID (see dialConnect's doc for why Publish never reuses
// cfg.ClientID).
func randomSuffix() string {
	var buf [8]byte
	_, _ = rand.Read(buf[:])
	return hex.EncodeToString(buf[:])
}
